package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	gotraceroute "github.com/aeden/traceroute"
	probing "github.com/prometheus-community/pro-bing"

	"github.com/oodle-ai/oodle-agent/pkg/agent"
	"github.com/oodle-ai/oodle-agent/pkg/k8s"
	"github.com/oodle-ai/oodle-agent/pkg/policy"
)

const (
	ProtoHTTP       = "http"
	ProtoTCP        = "tcp"
	ProtoUDP        = "udp"
	ProtoPostgres   = "postgres"
	ProtoK8sMeta    = "k8s-metadata"
	ProtoPing       = "ping"
	ProtoDNS        = "dns"
	ProtoSSL        = "ssl"
	ProtoTraceroute = "traceroute"
)

// Timeouts configures timeout durations for protocol
// handlers. Zero values use defaults.
type Timeouts struct {
	HTTPClientTimeout   time.Duration
	TCPDialTimeout      time.Duration
	TCPReadTimeout      time.Duration
	UDPReadTimeout      time.Duration
	PostgresDialTimeout time.Duration
	PostgresReadTimeout time.Duration
}

// DefaultTimeouts returns sane defaults matching the
// original hardcoded values.
func DefaultTimeouts() Timeouts {
	return Timeouts{
		HTTPClientTimeout:   60 * time.Second,
		TCPDialTimeout:      30 * time.Second,
		TCPReadTimeout:      30 * time.Second,
		UDPReadTimeout:      10 * time.Second,
		PostgresDialTimeout: 30 * time.Second,
		PostgresReadTimeout: 60 * time.Second,
	}
}

// BufferSizes configures read buffer sizes for protocol
// handlers. Zero values use defaults.
type BufferSizes struct {
	TCPReadBuffer      int
	UDPReadBuffer      int
	PostgresReadBuffer int
}

// DefaultBufferSizes returns sane defaults matching
// the original hardcoded values.
func DefaultBufferSizes() BufferSizes {
	return BufferSizes{
		TCPReadBuffer:      64 * 1024,
		UDPReadBuffer:      64 * 1024,
		PostgresReadBuffer: 64 * 1024,
	}
}

// Handler implements agent.RequestHandler and dispatches
// requests to the appropriate protocol handler.
type Handler struct {
	httpClient *http.Client
	k8sClient  *k8s.Client
	policy     *policy.Policy
	timeouts   Timeouts
	bufSizes   BufferSizes
}

// NewHandler creates a new proxy request handler.
func NewHandler(
	k8sClient *k8s.Client,
	pol *policy.Policy,
	timeouts Timeouts,
	bufSizes BufferSizes,
) *Handler {
	if timeouts.HTTPClientTimeout == 0 {
		timeouts = DefaultTimeouts()
	}
	if bufSizes.TCPReadBuffer == 0 {
		bufSizes = DefaultBufferSizes()
	}
	return &Handler{
		httpClient: &http.Client{
			Timeout: timeouts.HTTPClientTimeout,
			// Do not follow redirects to prevent
			// SSRF via open-redirect chains.
			CheckRedirect: func(
				req *http.Request,
				via []*http.Request,
			) error {
				return http.ErrUseLastResponse
			},
		},
		k8sClient: k8sClient,
		policy:    pol,
		timeouts:  timeouts,
		bufSizes:  bufSizes,
	}
}

// checkPolicy is the single, centralized enforcement
// point for the endpoint whitelist. Every protocol
// must be checked here.
func (h *Handler) checkPolicy(
	req *agent.ProxyRequest,
) *agent.ProxyResponse {
	if h.policy == nil {
		return nil
	}

	var err error
	switch req.Protocol {
	case ProtoHTTP:
		err = h.policy.CheckHTTPURL(req.URL)
	case ProtoTCP, ProtoUDP, ProtoPostgres:
		err = h.policy.CheckAddress(req.Address)
	case ProtoK8sMeta:
		err = h.policy.CheckK8sAccess(
			req.K8sResource,
			req.K8sNamespace,
		)
	case ProtoPing, ProtoTraceroute:
		var p struct {
			Host string `json:"host"`
		}
		if json.Unmarshal(req.Body, &p) == nil &&
			p.Host != "" {
			err = h.policy.CheckHost(p.Host)
		}
	case ProtoDNS:
		var d struct {
			Nameserver string `json:"nameserver"`
		}
		if json.Unmarshal(req.Body, &d) == nil &&
			d.Nameserver != "" {
			ns := d.Nameserver
			if !strings.Contains(ns, ":") {
				ns = ns + ":53"
			}
			err = h.policy.CheckAddress(ns)
		}
	case ProtoSSL:
		var s struct {
			Host string `json:"host"`
			Port int    `json:"port"`
		}
		if json.Unmarshal(req.Body, &s) == nil &&
			s.Host != "" {
			port := s.Port
			if port == 0 {
				port = 443
			}
			addr := fmt.Sprintf(
				"%s:%d",
				s.Host,
				port,
			)
			err = h.policy.CheckAddress(addr)
		}
	}

	if err != nil {
		return &agent.ProxyResponse{
			Error: err.Error(),
		}
	}
	return nil
}

// HandleRequest routes the request to the correct
// protocol handler.
func (h *Handler) HandleRequest(
	ctx context.Context,
	req *agent.ProxyRequest,
) *agent.ProxyResponse {
	// Enforce endpoint whitelist for address-based
	// protocols.
	if resp := h.checkPolicy(req); resp != nil {
		return resp
	}

	switch req.Protocol {
	case ProtoHTTP:
		return h.handleHTTP(ctx, req)
	case ProtoTCP:
		return h.handleTCP(ctx, req)
	case ProtoUDP:
		return h.handleUDP(ctx, req)
	case ProtoPostgres:
		return h.handlePostgres(ctx, req)
	case ProtoK8sMeta:
		return h.handleK8sMetadata(ctx, req)
	case ProtoPing:
		return h.handlePing(ctx, req)
	case ProtoDNS:
		return h.handleDNS(ctx, req)
	case ProtoSSL:
		return h.handleSSL(ctx, req)
	case ProtoTraceroute:
		return h.handleTraceroute(ctx, req)
	default:
		return &agent.ProxyResponse{
			Error: fmt.Sprintf(
				"unsupported protocol: %s",
				req.Protocol,
			),
		}
	}
}

func (h *Handler) handleHTTP(
	ctx context.Context,
	req *agent.ProxyRequest,
) *agent.ProxyResponse {
	method := req.Method
	if method == "" {
		method = http.MethodGet
	}
	log.Printf("HTTP %s %s", method, req.URL)

	httpReq, err := http.NewRequestWithContext(
		ctx,
		method,
		req.URL,
		bytes.NewReader(req.Body),
	)
	if err != nil {
		log.Printf(
			"HTTP create request error: %s: %v",
			req.URL,
			err,
		)
		return &agent.ProxyResponse{
			Error: fmt.Sprintf(
				"create request: %v",
				err,
			),
		}
	}

	for k, v := range req.Headers {
		httpReq.Header.Set(k, v)
	}

	resp, err := h.httpClient.Do(httpReq)
	if err != nil {
		log.Printf(
			"HTTP request error: %s: %v",
			req.URL,
			err,
		)
		return &agent.ProxyResponse{
			Error: fmt.Sprintf("HTTP request: %v", err),
		}
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return &agent.ProxyResponse{
			Error: fmt.Sprintf(
				"read response: %v",
				err,
			),
		}
	}

	headers := make(map[string]string)
	for k, vals := range resp.Header {
		if len(vals) > 0 {
			headers[k] = vals[0]
		}
	}

	return &agent.ProxyResponse{
		StatusCode: resp.StatusCode,
		Headers:    headers,
		Body:       body,
	}
}

func (h *Handler) handleTCP(
	ctx context.Context,
	req *agent.ProxyRequest,
) *agent.ProxyResponse {
	if req.Address == "" {
		return &agent.ProxyResponse{
			Error: "TCP address is required",
		}
	}
	log.Printf("TCP dial %s", req.Address)

	conn, err := net.DialTimeout(
		"tcp",
		req.Address,
		h.timeouts.TCPDialTimeout,
	)
	if err != nil {
		log.Printf(
			"TCP dial error: %s: %v",
			req.Address,
			err,
		)
		return &agent.ProxyResponse{
			Error: fmt.Sprintf("TCP dial: %v", err),
		}
	}
	defer conn.Close()

	// No body = connectivity check only
	if len(req.Body) == 0 {
		return &agent.ProxyResponse{
			StatusCode: 200,
		}
	}

	conn.SetDeadline(
		time.Now().Add(h.timeouts.TCPReadTimeout),
	)

	if _, err := conn.Write(req.Body); err != nil {
		return &agent.ProxyResponse{
			Error: fmt.Sprintf(
				"TCP write: %v",
				err,
			),
		}
	}

	buf := make([]byte, h.bufSizes.TCPReadBuffer)
	n, err := conn.Read(buf)
	if err != nil && err != io.EOF {
		return &agent.ProxyResponse{
			Error: fmt.Sprintf("TCP read: %v", err),
		}
	}

	return &agent.ProxyResponse{
		StatusCode: 200,
		Body:       buf[:n],
	}
}

func (h *Handler) handleUDP(
	ctx context.Context,
	req *agent.ProxyRequest,
) *agent.ProxyResponse {
	if req.Address == "" {
		return &agent.ProxyResponse{
			Error: "UDP address is required",
		}
	}
	log.Printf("UDP dial %s", req.Address)

	addr, err := net.ResolveUDPAddr(
		"udp",
		req.Address,
	)
	if err != nil {
		return &agent.ProxyResponse{
			Error: fmt.Sprintf(
				"resolve UDP addr: %v",
				err,
			),
		}
	}

	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		log.Printf(
			"UDP dial error: %s: %v",
			req.Address,
			err,
		)
		return &agent.ProxyResponse{
			Error: fmt.Sprintf("UDP dial: %v", err),
		}
	}
	defer conn.Close()

	conn.SetDeadline(
		time.Now().Add(h.timeouts.UDPReadTimeout),
	)

	if _, err := conn.Write(req.Body); err != nil {
		return &agent.ProxyResponse{
			Error: fmt.Sprintf("UDP write: %v", err),
		}
	}

	buf := make([]byte, h.bufSizes.UDPReadBuffer)
	n, err := conn.Read(buf)
	if err != nil {
		return &agent.ProxyResponse{
			Error: fmt.Sprintf("UDP read: %v", err),
		}
	}

	return &agent.ProxyResponse{
		Body: buf[:n],
	}
}

func (h *Handler) handlePostgres(
	ctx context.Context,
	req *agent.ProxyRequest,
) *agent.ProxyResponse {
	// Postgres proxy: forward raw TCP bytes to the
	// Postgres server. The gateway client should send
	// properly formatted Postgres wire protocol messages.
	if req.Address == "" {
		return &agent.ProxyResponse{
			Error: "Postgres address is required",
		}
	}
	log.Printf("Postgres connect %s", req.Address)

	conn, err := net.DialTimeout(
		"tcp",
		req.Address,
		h.timeouts.PostgresDialTimeout,
	)
	if err != nil {
		log.Printf(
			"Postgres connect error: %s: %v",
			req.Address,
			err,
		)
		return &agent.ProxyResponse{
			Error: fmt.Sprintf(
				"Postgres connect: %v",
				err,
			),
		}
	}
	defer conn.Close()

	conn.SetDeadline(
		time.Now().Add(
			h.timeouts.PostgresReadTimeout,
		),
	)

	if len(req.Body) > 0 {
		if _, err := conn.Write(req.Body); err != nil {
			return &agent.ProxyResponse{
				Error: fmt.Sprintf(
					"Postgres write: %v",
					err,
				),
			}
		}
	}

	var allData []byte
	buf := make([]byte, h.bufSizes.PostgresReadBuffer)
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			allData = append(allData, buf[:n]...)
		}
		if err != nil {
			break
		}
		// Check if the last complete Postgres
		// message is ReadyForQuery ('Z').
		// Wire format: type(1) + length(4) + body.
		// ReadyForQuery is: 'Z' + len=5 + 1 byte
		// status = 6 bytes total.
		if endsWithReadyForQuery(allData) {
			break
		}
	}

	return &agent.ProxyResponse{
		Body: allData,
	}
}

func (h *Handler) handleK8sMetadata(
	ctx context.Context,
	req *agent.ProxyRequest,
) *agent.ProxyResponse {
	if h.k8sClient == nil {
		return &agent.ProxyResponse{
			Error: "Kubernetes client not available",
		}
	}

	log.Printf(
		"K8s metadata %s/%s/%s",
		req.K8sResource,
		req.K8sNamespace,
		req.K8sName,
	)

	data, err := h.k8sClient.GetResource(
		ctx,
		req.K8sResource,
		req.K8sNamespace,
		req.K8sName,
	)
	if err != nil {
		log.Printf(
			"K8s metadata error: %s/%s/%s: %v",
			req.K8sResource,
			req.K8sNamespace,
			req.K8sName,
			err,
		)
		return &agent.ProxyResponse{
			Error: fmt.Sprintf(
				"K8s metadata: %v",
				err,
			),
		}
	}

	return &agent.ProxyResponse{
		StatusCode: 200,
		Body:       data,
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
	}
}

// PingRequest is the JSON body for a ping protocol
// request.
type PingRequest struct {
	Host       string `json:"host"`
	Count      int    `json:"count,omitempty"`
	IntervalMs int    `json:"interval_ms,omitempty"`
	TimeoutMs  int64  `json:"timeout_ms,omitempty"`
}

// PingResponse is returned as JSON in the response body.
type PingResponse struct {
	PacketsSent     int     `json:"packets_sent"`
	PacketsReceived int     `json:"packets_received"`
	PacketLoss      float64 `json:"packet_loss"`
	MinRTTMs        float64 `json:"min_rtt_ms"`
	MaxRTTMs        float64 `json:"max_rtt_ms"`
	AvgRTTMs        float64 `json:"avg_rtt_ms"`
}

func (h *Handler) handlePing(
	ctx context.Context,
	req *agent.ProxyRequest,
) *agent.ProxyResponse {
	var pr PingRequest
	if err := json.Unmarshal(
		req.Body,
		&pr,
	); err != nil {
		return &agent.ProxyResponse{
			Error: fmt.Sprintf(
				"invalid ping request: %v",
				err,
			),
		}
	}

	if pr.Host == "" {
		return &agent.ProxyResponse{
			Error: "ping host is required",
		}
	}

	count := pr.Count
	if count <= 0 {
		count = 3
	}

	intervalMs := pr.IntervalMs
	if intervalMs <= 0 {
		intervalMs = 1000
	}

	timeout := 30 * time.Second
	if pr.TimeoutMs > 0 {
		timeout = time.Duration(
			pr.TimeoutMs,
		) * time.Millisecond
	}

	log.Printf("Ping %s (count=%d)", pr.Host, count)

	pinger, err := probing.NewPinger(pr.Host)
	if err != nil {
		log.Printf(
			"Ping create error: %s: %v",
			pr.Host,
			err,
		)
		return &agent.ProxyResponse{
			Error: fmt.Sprintf(
				"create pinger: %v",
				err,
			),
		}
	}

	pinger.Count = count
	pinger.Timeout = timeout
	pinger.Interval = time.Duration(
		intervalMs,
	) * time.Millisecond
	pinger.SetPrivileged(true)

	if err := pinger.RunWithContext(ctx); err != nil {
		log.Printf(
			"Ping failed: %s: %v",
			pr.Host,
			err,
		)
		return &agent.ProxyResponse{
			Error: fmt.Sprintf(
				"ping failed: %v",
				err,
			),
		}
	}

	stats := pinger.Statistics()
	resp := PingResponse{
		PacketsSent:     stats.PacketsSent,
		PacketsReceived: stats.PacketsRecv,
		PacketLoss:      stats.PacketLoss,
	}
	if stats.PacketsRecv > 0 {
		resp.MinRTTMs = float64(
			stats.MinRtt.Milliseconds(),
		)
		resp.MaxRTTMs = float64(
			stats.MaxRtt.Milliseconds(),
		)
		resp.AvgRTTMs = float64(
			stats.AvgRtt.Milliseconds(),
		)
	}

	body, _ := json.Marshal(resp)
	return &agent.ProxyResponse{
		StatusCode: 200,
		Body:       body,
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
	}
}

// DNSRequest is the JSON body for a DNS protocol
// request.
type DNSRequest struct {
	Domain     string `json:"domain"`
	RecordType string `json:"record_type"`
	Nameserver string `json:"nameserver,omitempty"`
}

// DNSResponse is returned as JSON in the response body.
type DNSResponse struct {
	Records []string `json:"records"`
}

func (h *Handler) handleDNS(
	ctx context.Context,
	req *agent.ProxyRequest,
) *agent.ProxyResponse {
	var dr DNSRequest
	if err := json.Unmarshal(
		req.Body,
		&dr,
	); err != nil {
		return &agent.ProxyResponse{
			Error: fmt.Sprintf(
				"invalid dns request: %v",
				err,
			),
		}
	}

	if dr.Domain == "" {
		return &agent.ProxyResponse{
			Error: "dns domain is required",
		}
	}

	resolver := net.DefaultResolver
	if dr.Nameserver != "" {
		resolver = &net.Resolver{
			PreferGo: true,
			Dial: func(
				ctx context.Context,
				network, address string,
			) (net.Conn, error) {
				d := net.Dialer{}
				ns := dr.Nameserver
				if !strings.Contains(ns, ":") {
					ns = ns + ":53"
				}
				return d.DialContext(
					ctx,
					network,
					ns,
				)
			},
		}
	}

	recordType := strings.ToUpper(dr.RecordType)
	if recordType == "" {
		recordType = "A"
	}
	log.Printf(
		"DNS lookup %s %s",
		recordType,
		dr.Domain,
	)

	var records []string
	var lookupErr error

	switch recordType {
	case "A":
		ips, err := resolver.LookupIP(
			ctx,
			"ip4",
			dr.Domain,
		)
		lookupErr = err
		for _, ip := range ips {
			records = append(records, ip.String())
		}
	case "AAAA":
		ips, err := resolver.LookupIP(
			ctx,
			"ip6",
			dr.Domain,
		)
		lookupErr = err
		for _, ip := range ips {
			records = append(records, ip.String())
		}
	case "CNAME":
		cname, err := resolver.LookupCNAME(
			ctx,
			dr.Domain,
		)
		lookupErr = err
		if cname != "" {
			records = []string{cname}
		}
	case "MX":
		mxs, err := resolver.LookupMX(
			ctx,
			dr.Domain,
		)
		lookupErr = err
		for _, mx := range mxs {
			records = append(
				records,
				fmt.Sprintf(
					"%s (priority: %d)",
					mx.Host,
					mx.Pref,
				),
			)
		}
	case "TXT":
		records, lookupErr = resolver.LookupTXT(
			ctx,
			dr.Domain,
		)
	case "NS":
		nss, err := resolver.LookupNS(
			ctx,
			dr.Domain,
		)
		lookupErr = err
		for _, ns := range nss {
			records = append(records, ns.Host)
		}
	default:
		return &agent.ProxyResponse{
			Error: fmt.Sprintf(
				"unsupported record type: %s",
				dr.RecordType,
			),
		}
	}

	if lookupErr != nil {
		log.Printf(
			"DNS lookup error: %s %s: %v",
			recordType,
			dr.Domain,
			lookupErr,
		)
		return &agent.ProxyResponse{
			Error: fmt.Sprintf(
				"dns lookup failed: %v",
				lookupErr,
			),
		}
	}

	resp := DNSResponse{Records: records}
	body, _ := json.Marshal(resp)
	return &agent.ProxyResponse{
		StatusCode: 200,
		Body:       body,
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
	}
}

// SSLRequest is the JSON body for an SSL protocol
// request.
type SSLRequest struct {
	Host      string `json:"host"`
	Port      int    `json:"port,omitempty"`
	TimeoutMs int64  `json:"timeout_ms,omitempty"`
}

// SSLResponse is returned as JSON in the response body.
type SSLResponse struct {
	ExpiryEpochMs int64  `json:"expiry_epoch_ms"`
	Issuer        string `json:"issuer"`
	Subject       string `json:"subject"`
	DaysUntil     int    `json:"days_until_expiry"`
}

func (h *Handler) handleSSL(
	ctx context.Context,
	req *agent.ProxyRequest,
) *agent.ProxyResponse {
	var sr SSLRequest
	if err := json.Unmarshal(
		req.Body,
		&sr,
	); err != nil {
		return &agent.ProxyResponse{
			Error: fmt.Sprintf(
				"invalid ssl request: %v",
				err,
			),
		}
	}

	if sr.Host == "" {
		return &agent.ProxyResponse{
			Error: "ssl host is required",
		}
	}

	port := sr.Port
	if port == 0 {
		port = 443
	}

	timeout := 30 * time.Second
	if sr.TimeoutMs > 0 {
		timeout = time.Duration(
			sr.TimeoutMs,
		) * time.Millisecond
	}

	address := fmt.Sprintf("%s:%d", sr.Host, port)
	log.Printf("SSL check %s", address)

	dialer := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(
		dialer,
		"tcp",
		address,
		&tls.Config{
			ServerName: sr.Host,
		},
	)
	if err != nil {
		log.Printf(
			"SSL connect error: %s: %v",
			address,
			err,
		)
		return &agent.ProxyResponse{
			Error: fmt.Sprintf(
				"tls connect failed: %v",
				err,
			),
		}
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return &agent.ProxyResponse{
			Error: "no certificates found",
		}
	}

	cert := state.PeerCertificates[0]
	daysUntil := int(
		time.Until(cert.NotAfter).Hours() / 24,
	)

	resp := SSLResponse{
		ExpiryEpochMs: cert.NotAfter.UnixMilli(),
		Issuer:        cert.Issuer.String(),
		Subject:       cert.Subject.String(),
		DaysUntil:     daysUntil,
	}

	body, _ := json.Marshal(resp)
	return &agent.ProxyResponse{
		StatusCode: 200,
		Body:       body,
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
	}
}

// TracerouteRequest is the JSON body for a traceroute
// protocol request.
type TracerouteRequest struct {
	Host            string `json:"host"`
	MaxHops         int    `json:"max_hops,omitempty"`
	TimeoutPerHopMs int    `json:"timeout_per_hop_ms,omitempty"`
}

// TracerouteHop represents a single hop result.
type TracerouteHop struct {
	HopNumber int     `json:"hop_number"`
	Address   string  `json:"address,omitempty"`
	Hostname  string  `json:"hostname,omitempty"`
	RTTMs     float64 `json:"rtt_ms,omitempty"`
	Timeout   bool    `json:"timeout,omitempty"`
}

// TracerouteResponse is returned as JSON in the
// response body.
type TracerouteResponse struct {
	Hops []TracerouteHop `json:"hops"`
}

func (h *Handler) handleTraceroute(
	ctx context.Context,
	req *agent.ProxyRequest,
) *agent.ProxyResponse {
	var tr TracerouteRequest
	if err := json.Unmarshal(
		req.Body,
		&tr,
	); err != nil {
		return &agent.ProxyResponse{
			Error: fmt.Sprintf(
				"invalid traceroute request: %v",
				err,
			),
		}
	}

	if tr.Host == "" {
		return &agent.ProxyResponse{
			Error: "traceroute host is required",
		}
	}

	maxHops := tr.MaxHops
	if maxHops <= 0 {
		maxHops = 30
	}

	timeoutPerHop := tr.TimeoutPerHopMs
	if timeoutPerHop <= 0 {
		timeoutPerHop = 1000
	}

	log.Printf(
		"Traceroute %s (max_hops=%d)",
		tr.Host,
		maxHops,
	)

	opts := gotraceroute.TracerouteOptions{}
	opts.SetMaxHops(maxHops)
	opts.SetTimeoutMs(timeoutPerHop)
	opts.SetRetries(2)

	trResult, err := gotraceroute.Traceroute(
		tr.Host,
		&opts,
	)
	if err != nil {
		log.Printf(
			"Traceroute error: %s: %v",
			tr.Host,
			err,
		)
		return &agent.ProxyResponse{
			Error: fmt.Sprintf(
				"traceroute failed: %v",
				err,
			),
		}
	}

	var hops []TracerouteHop
	for _, hop := range trResult.Hops {
		h := TracerouteHop{
			HopNumber: hop.TTL,
			Timeout:   !hop.Success,
		}
		if hop.Success {
			h.Address = hop.AddressString()
			h.Hostname = hop.HostOrAddressString()
			h.RTTMs = float64(
				hop.ElapsedTime.Microseconds(),
			) / 1000.0
		}
		hops = append(hops, h)
	}

	resp := TracerouteResponse{Hops: hops}
	body, _ := json.Marshal(resp)
	return &agent.ProxyResponse{
		StatusCode: 200,
		Body:       body,
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
	}
}

// endsWithReadyForQuery checks if the last complete
// Postgres wire protocol message in data is a
// ReadyForQuery ('Z') message.
//
// Postgres backend message format:
//
//	type (1 byte) + length (4 bytes big-endian,
//	includes self) + body
//
// ReadyForQuery: type='Z', length=5, body=1 byte
// (transaction status). Total: 6 bytes.
func endsWithReadyForQuery(data []byte) bool {
	// Minimum ReadyForQuery message is 6 bytes:
	// 'Z' + 4-byte length (5) + 1-byte status.
	if len(data) < 6 {
		return false
	}

	// Walk forward through complete messages to find
	// the last one.
	pos := 0
	lastMsgType := byte(0)
	lastMsgLen := uint32(0)
	for pos < len(data) {
		if pos+5 > len(data) {
			// Incomplete message header.
			break
		}
		msgType := data[pos]
		msgLen := uint32(data[pos+1])<<24 |
			uint32(data[pos+2])<<16 |
			uint32(data[pos+3])<<8 |
			uint32(data[pos+4])
		totalLen := 1 + int(msgLen)
		if pos+totalLen > len(data) {
			// Incomplete message body.
			break
		}
		lastMsgType = msgType
		lastMsgLen = msgLen
		pos += totalLen
	}

	return lastMsgType == 'Z' && lastMsgLen == 5
}
