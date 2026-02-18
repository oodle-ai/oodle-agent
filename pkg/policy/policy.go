package policy

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Policy defines agent-side access restrictions.
// When EnableAccessRestrictions is true, every outbound
// connection is checked against the AllowedEndpoints
// whitelist before execution.
type Policy struct {
	// EnableAccessRestrictions toggles whitelist
	// enforcement. When false, all requests are
	// allowed.
	EnableAccessRestrictions bool `yaml:"enable_access_restrictions"`
	// AllowedEndpoints is a list of endpoint patterns.
	// Supported formats:
	//   "host:port"          exact match
	//   "host"               any port
	//   "*.example.com:443"  wildcard subdomain
	//   "*:5432"             any host, specific port
	AllowedEndpoints []string `yaml:"allowed_endpoints"`
	// Kubernetes restricts K8s metadata access.
	Kubernetes *KubernetesPolicy `yaml:"kubernetes,omitempty"`

	compiled []endpointMatcher
}

// KubernetesPolicy restricts K8s resource and namespace
// access.
type KubernetesPolicy struct {
	AllowedNamespaces []string `yaml:"allowed_namespaces"`
	AllowedResources  []string `yaml:"allowed_resources"`
	// DenyResources takes precedence over
	// AllowedResources.
	DenyResources []string `yaml:"deny_resources"`
}

type endpointMatcher struct {
	host    string // lowercase; "*" = any host
	port    string // "" = any port; "*" = any port
	isGlob  bool   // host starts with "*."
	globSfx string // e.g. ".example.com"
}

// LoadFromFile reads a YAML policy file and returns
// a compiled Policy.
func LoadFromFile(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf(
			"read policy file %s: %w",
			path,
			err,
		)
	}
	return LoadFromBytes(data)
}

// LoadFromBytes parses YAML bytes into a Policy.
func LoadFromBytes(data []byte) (*Policy, error) {
	var p Policy
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf(
			"unmarshal policy: %w",
			err,
		)
	}
	if err := p.compile(); err != nil {
		return nil, err
	}
	return &p, nil
}

// Default returns a permissive policy with restrictions
// disabled.
func Default() *Policy {
	return &Policy{
		EnableAccessRestrictions: false,
	}
}

// blockedCIDRs contains IP ranges that must never be
// accessed regardless of policy configuration. This
// prevents SSRF to cloud metadata endpoints, loopback,
// and internal networks.
var blockedCIDRs = func() []*net.IPNet {
	cidrs := []string{
		"127.0.0.0/8",    // IPv4 loopback
		"169.254.0.0/16", // IPv4 link-local / metadata
		"0.0.0.0/8",      // "this" network
		"::1/128",        // IPv6 loopback
		"fe80::/10",      // IPv6 link-local
	}
	nets := make([]*net.IPNet, 0, len(cidrs))
	for _, cidr := range cidrs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			panic(
				"bad built-in CIDR: " + cidr,
			)
		}
		nets = append(nets, ipNet)
	}
	return nets
}()

// isBlockedIP resolves a host to IPs and returns an
// error if any resolved IP falls within a blocked CIDR.
// This is enforced regardless of policy configuration
// to prevent SSRF to cloud metadata and loopback.
func isBlockedIP(host string) error {
	// Check if host is already an IP literal.
	if ip := net.ParseIP(host); ip != nil {
		for _, cidr := range blockedCIDRs {
			if cidr.Contains(ip) {
				return fmt.Errorf(
					"policy violation: "+
						"address %s is in "+
						"blocked range %s",
					host,
					cidr.String(),
				)
			}
		}
		return nil
	}

	// Resolve hostname and check all IPs.
	ips, err := net.LookupIP(host)
	if err != nil {
		// Resolution failure is not a policy
		// violation; the connection will fail later.
		return nil
	}
	for _, ip := range ips {
		for _, cidr := range blockedCIDRs {
			if cidr.Contains(ip) {
				return fmt.Errorf(
					"policy violation: "+
						"host %s resolves to "+
						"blocked address %s "+
						"(range %s)",
					host,
					ip.String(),
					cidr.String(),
				)
			}
		}
	}
	return nil
}

// CheckAddress validates a host:port address against the
// whitelist. Used for TCP, UDP, Postgres, and
// stream_open.
func (p *Policy) CheckAddress(address string) error {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		// Might be host-only without port.
		return p.CheckHost(address)
	}
	if err := isBlockedIP(host); err != nil {
		return err
	}
	if p == nil || !p.EnableAccessRestrictions {
		return nil
	}
	return p.matchEndpoint(host, port)
}

// CheckHost validates a host (no port) against the
// whitelist. Used for Ping and Traceroute.
func (p *Policy) CheckHost(host string) error {
	if err := isBlockedIP(host); err != nil {
		return err
	}
	if p == nil || !p.EnableAccessRestrictions {
		return nil
	}
	return p.matchEndpoint(host, "")
}

// CheckHTTPURL parses a URL and checks the host:port
// against the whitelist, using scheme-based defaults
// (80 for http, 443 for https).
func (p *Policy) CheckHTTPURL(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf(
			"policy violation: invalid URL %q",
			rawURL,
		)
	}
	host := u.Hostname()
	if err := isBlockedIP(host); err != nil {
		return err
	}
	if p == nil || !p.EnableAccessRestrictions {
		return nil
	}
	port := u.Port()
	if port == "" {
		switch u.Scheme {
		case "https":
			port = "443"
		default:
			port = "80"
		}
	}
	return p.matchEndpoint(host, port)
}

// CheckK8sAccess validates a K8s resource and namespace
// access against the kubernetes policy section.
// Secrets are always denied regardless of policy
// configuration (defense-in-depth).
func (p *Policy) CheckK8sAccess(
	resource string,
	namespace string,
) error {
	res := strings.ToLower(resource)

	// Secrets are always denied regardless of
	// whether access restrictions are enabled.
	if matchResource(res, "secrets") {
		return fmt.Errorf(
			"policy violation: resource %q denied",
			resource,
		)
	}

	if p == nil || !p.EnableAccessRestrictions {
		return nil
	}
	if p.Kubernetes == nil {
		return nil
	}

	// deny_resources takes precedence.
	for _, denied := range p.Kubernetes.DenyResources {
		if matchResource(res, strings.ToLower(denied)) {
			return fmt.Errorf(
				"policy violation: resource %q denied",
				resource,
			)
		}
	}

	// Check allowed_resources if non-empty.
	if len(p.Kubernetes.AllowedResources) > 0 {
		found := false
		for _, allowed := range p.Kubernetes.AllowedResources {
			if matchResource(
				res,
				strings.ToLower(allowed),
			) {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf(
				"policy violation: resource %q "+
					"not in allowed list",
				resource,
			)
		}
	}

	// Check allowed_namespaces if non-empty.
	ns := strings.ToLower(namespace)
	if len(p.Kubernetes.AllowedNamespaces) > 0 &&
		ns != "" {
		found := false
		for _, allowed := range p.Kubernetes.AllowedNamespaces {
			if strings.ToLower(allowed) == ns {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf(
				"policy violation: namespace %q "+
					"not in allowed list",
				namespace,
			)
		}
	}

	return nil
}

func (p *Policy) compile() error {
	p.compiled = make(
		[]endpointMatcher,
		0,
		len(p.AllowedEndpoints),
	)
	for _, ep := range p.AllowedEndpoints {
		m, err := parseEndpoint(ep)
		if err != nil {
			return fmt.Errorf(
				"invalid endpoint %q: %w",
				ep,
				err,
			)
		}
		p.compiled = append(p.compiled, m)
	}
	return nil
}

func parseEndpoint(ep string) (endpointMatcher, error) {
	ep = strings.TrimSpace(ep)
	if ep == "" {
		return endpointMatcher{}, fmt.Errorf(
			"empty endpoint",
		)
	}

	var m endpointMatcher

	// Try host:port split.
	host, port, err := net.SplitHostPort(ep)
	if err != nil {
		// No port -- treat as host-only.
		m.host = strings.ToLower(ep)
		m.port = ""
	} else {
		m.host = strings.ToLower(host)
		m.port = port
	}

	// Detect wildcard glob pattern.
	if strings.HasPrefix(m.host, "*.") {
		m.isGlob = true
		m.globSfx = m.host[1:] // e.g. ".example.com"
	}

	return m, nil
}

func (p *Policy) matchEndpoint(
	host string,
	port string,
) error {
	h := strings.ToLower(host)
	for _, m := range p.compiled {
		if matchHost(m, h) && matchPort(m, port) {
			return nil
		}
	}
	target := host
	if port != "" {
		target = net.JoinHostPort(host, port)
	}
	return fmt.Errorf(
		"policy violation: %s not in allowed endpoints",
		target,
	)
}

func matchHost(m endpointMatcher, host string) bool {
	if m.host == "*" {
		return true
	}
	if m.isGlob {
		// *.example.com matches a.example.com,
		// x.y.example.com
		return strings.HasSuffix(host, m.globSfx)
	}
	return m.host == host
}

func matchPort(m endpointMatcher, port string) bool {
	// Matcher has no port constraint -- matches any.
	if m.port == "" {
		return true
	}
	// Host-only check (ping/traceroute) -- port is
	// irrelevant.
	if port == "" {
		return true
	}
	return m.port == port
}

// matchResource checks if a resource string matches an
// allowed/denied entry. Handles singular/plural.
func matchResource(res, pattern string) bool {
	if res == pattern {
		return true
	}
	// Handle singular vs plural (e.g. "pod" vs "pods").
	if res+"s" == pattern || res == pattern+"s" {
		return true
	}
	return false
}
