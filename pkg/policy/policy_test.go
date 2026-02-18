package policy

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCheckAddress_RestrictionsDisabled(t *testing.T) {
	p := Default()
	if err := p.CheckAddress("10.0.0.1:5432"); err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
}

func TestCheckAddress_NilPolicy(t *testing.T) {
	var p *Policy
	if err := p.CheckAddress("10.0.0.1:5432"); err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
}

func TestCheckAddress_ExactMatch(t *testing.T) {
	p := &Policy{
		EnableAccessRestrictions: true,
		AllowedEndpoints:         []string{"10.0.0.1:5432"},
	}
	if err := p.compile(); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		addr    string
		wantErr bool
	}{
		{"allowed", "10.0.0.1:5432", false},
		{"wrong port", "10.0.0.1:3306", true},
		{"wrong host", "10.0.0.2:5432", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := p.CheckAddress(tt.addr)
			if (err != nil) != tt.wantErr {
				t.Errorf(
					"CheckAddress(%q) err=%v, wantErr=%v",
					tt.addr,
					err,
					tt.wantErr,
				)
			}
		})
	}
}

func TestCheckAddress_HostOnly(t *testing.T) {
	p := &Policy{
		EnableAccessRestrictions: true,
		AllowedEndpoints: []string{
			"monitoring.internal",
		},
	}
	if err := p.compile(); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		addr    string
		wantErr bool
	}{
		{"any port", "monitoring.internal:9090", false},
		{"another port", "monitoring.internal:443", false},
		{"wrong host", "other.internal:9090", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := p.CheckAddress(tt.addr)
			if (err != nil) != tt.wantErr {
				t.Errorf(
					"CheckAddress(%q) err=%v, wantErr=%v",
					tt.addr,
					err,
					tt.wantErr,
				)
			}
		})
	}
}

func TestCheckAddress_WildcardHost(t *testing.T) {
	p := &Policy{
		EnableAccessRestrictions: true,
		AllowedEndpoints: []string{
			"*.example.com:443",
		},
	}
	if err := p.compile(); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		addr    string
		wantErr bool
	}{
		{
			"subdomain match",
			"api.example.com:443",
			false,
		},
		{
			"deep subdomain",
			"a.b.example.com:443",
			false,
		},
		{
			"wrong port",
			"api.example.com:80",
			true,
		},
		{
			"different domain",
			"api.other.com:443",
			true,
		},
		{
			"bare domain no match",
			"example.com:443",
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := p.CheckAddress(tt.addr)
			if (err != nil) != tt.wantErr {
				t.Errorf(
					"CheckAddress(%q) err=%v, wantErr=%v",
					tt.addr,
					err,
					tt.wantErr,
				)
			}
		})
	}
}

func TestCheckAddress_WildcardPort(t *testing.T) {
	p := &Policy{
		EnableAccessRestrictions: true,
		AllowedEndpoints:         []string{"*:5432"},
	}
	if err := p.compile(); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		addr    string
		wantErr bool
	}{
		{"any host", "10.0.0.1:5432", false},
		{"another host", "db.internal:5432", false},
		{"wrong port", "db.internal:3306", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := p.CheckAddress(tt.addr)
			if (err != nil) != tt.wantErr {
				t.Errorf(
					"CheckAddress(%q) err=%v, wantErr=%v",
					tt.addr,
					err,
					tt.wantErr,
				)
			}
		})
	}
}

func TestCheckAddress_EmptyWhitelist(t *testing.T) {
	p := &Policy{
		EnableAccessRestrictions: true,
		AllowedEndpoints:         []string{},
	}
	if err := p.compile(); err != nil {
		t.Fatal(err)
	}

	if err := p.CheckAddress("10.0.0.1:80"); err == nil {
		t.Fatal("expected deny, got nil")
	}
}

func TestCheckAddress_CaseInsensitive(t *testing.T) {
	p := &Policy{
		EnableAccessRestrictions: true,
		AllowedEndpoints: []string{
			"API.Example.COM:443",
		},
	}
	if err := p.compile(); err != nil {
		t.Fatal(err)
	}

	err := p.CheckAddress("api.example.com:443")
	if err != nil {
		t.Fatalf("expected match, got %v", err)
	}
}

func TestCheckHost(t *testing.T) {
	p := &Policy{
		EnableAccessRestrictions: true,
		AllowedEndpoints: []string{
			"monitoring.internal",
			"*.example.com:443",
		},
	}
	if err := p.compile(); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		host    string
		wantErr bool
	}{
		{"exact host", "monitoring.internal", false},
		{
			"glob host matches (no port check)",
			"api.example.com",
			false,
		},
		{"unknown host", "unknown.host", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := p.CheckHost(tt.host)
			if (err != nil) != tt.wantErr {
				t.Errorf(
					"CheckHost(%q) err=%v, wantErr=%v",
					tt.host,
					err,
					tt.wantErr,
				)
			}
		})
	}
}

func TestCheckHTTPURL(t *testing.T) {
	p := &Policy{
		EnableAccessRestrictions: true,
		AllowedEndpoints: []string{
			"api.internal:8080",
			"*.secure.com:443",
			"legacy.internal:80",
		},
	}
	if err := p.compile(); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{
			"exact",
			"http://api.internal:8080/path",
			false,
		},
		{
			"https default port",
			"https://app.secure.com/api",
			false,
		},
		{
			"http default port",
			"http://legacy.internal/old",
			false,
		},
		{
			"wrong port",
			"http://api.internal:9090/path",
			true,
		},
		{
			"wrong host",
			"http://other.internal:8080/path",
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := p.CheckHTTPURL(tt.url)
			if (err != nil) != tt.wantErr {
				t.Errorf(
					"CheckHTTPURL(%q) err=%v, wantErr=%v",
					tt.url,
					err,
					tt.wantErr,
				)
			}
		})
	}
}

func TestCheckK8sAccess(t *testing.T) {
	p := &Policy{
		EnableAccessRestrictions: true,
		Kubernetes: &KubernetesPolicy{
			AllowedNamespaces: []string{
				"default",
				"production",
			},
			AllowedResources: []string{
				"pods",
				"deployments",
				"services",
			},
			DenyResources: []string{
				"secrets",
			},
		},
	}

	tests := []struct {
		name      string
		resource  string
		namespace string
		wantErr   bool
	}{
		{
			"allowed resource + namespace",
			"pods",
			"default",
			false,
		},
		{
			"singular form",
			"pod",
			"production",
			false,
		},
		{
			"denied resource",
			"secrets",
			"default",
			true,
		},
		{
			"denied singular",
			"secret",
			"default",
			true,
		},
		{
			"disallowed namespace",
			"pods",
			"kube-system",
			true,
		},
		{
			"disallowed resource",
			"configmaps",
			"default",
			true,
		},
		{
			"empty namespace (cluster-scoped)",
			"pods",
			"",
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := p.CheckK8sAccess(
				tt.resource,
				tt.namespace,
			)
			if (err != nil) != tt.wantErr {
				t.Errorf(
					"CheckK8sAccess(%q, %q) "+
						"err=%v, wantErr=%v",
					tt.resource,
					tt.namespace,
					err,
					tt.wantErr,
				)
			}
		})
	}
}

func TestCheckK8sAccess_DenyTakesPrecedence(t *testing.T) {
	p := &Policy{
		EnableAccessRestrictions: true,
		Kubernetes: &KubernetesPolicy{
			AllowedResources: []string{
				"secrets",
				"pods",
			},
			DenyResources: []string{"secrets"},
		},
	}

	err := p.CheckK8sAccess("secrets", "")
	if err == nil {
		t.Fatal(
			"expected deny for secrets even when " +
				"in allowed list",
		)
	}
}

func TestLoadFromBytes(t *testing.T) {
	yamlData := `
enable_access_restrictions: true
allowed_endpoints:
  - "10.0.0.1:5432"
  - "*.example.com:443"
  - "monitoring.internal"
kubernetes:
  allowed_namespaces:
    - default
  allowed_resources:
    - pods
  deny_resources:
    - secrets
`
	p, err := LoadFromBytes([]byte(yamlData))
	if err != nil {
		t.Fatalf("LoadFromBytes: %v", err)
	}
	if !p.EnableAccessRestrictions {
		t.Fatal("expected restrictions enabled")
	}
	if len(p.AllowedEndpoints) != 3 {
		t.Fatalf(
			"expected 3 endpoints, got %d",
			len(p.AllowedEndpoints),
		)
	}
	if len(p.compiled) != 3 {
		t.Fatalf(
			"expected 3 compiled, got %d",
			len(p.compiled),
		)
	}

	// Verify it works end-to-end.
	if err := p.CheckAddress(
		"10.0.0.1:5432",
	); err != nil {
		t.Errorf("expected allowed: %v", err)
	}
	if err := p.CheckAddress(
		"10.0.0.2:5432",
	); err == nil {
		t.Error("expected denied")
	}
}

func TestLoadFromFile(t *testing.T) {
	yamlData := `
enable_access_restrictions: true
allowed_endpoints:
  - "db.internal:5432"
`
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(
		path,
		[]byte(yamlData),
		0644,
	); err != nil {
		t.Fatal(err)
	}

	p, err := LoadFromFile(path)
	if err != nil {
		t.Fatalf("LoadFromFile: %v", err)
	}
	if err := p.CheckAddress(
		"db.internal:5432",
	); err != nil {
		t.Errorf("expected allowed: %v", err)
	}
}

func TestMultipleEndpoints(t *testing.T) {
	p := &Policy{
		EnableAccessRestrictions: true,
		AllowedEndpoints: []string{
			"10.0.0.1:5432",
			"api.internal:8080",
			"*.example.com:443",
			"monitoring.internal",
			"*:5432",
		},
	}
	if err := p.compile(); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		addr    string
		wantErr bool
	}{
		{"exact 1", "10.0.0.1:5432", false},
		{"exact 2", "api.internal:8080", false},
		{"glob", "sub.example.com:443", false},
		{"host any port", "monitoring.internal:9999", false},
		{"wildcard port", "random.host:5432", false},
		{"no match", "random.host:9999", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := p.CheckAddress(tt.addr)
			if (err != nil) != tt.wantErr {
				t.Errorf(
					"CheckAddress(%q) err=%v, wantErr=%v",
					tt.addr,
					err,
					tt.wantErr,
				)
			}
		})
	}
}
