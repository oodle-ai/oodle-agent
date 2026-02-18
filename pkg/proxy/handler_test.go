package proxy

import (
	"context"
	"encoding/binary"
	"testing"

	"github.com/oodle-ai/oodle-agent/pkg/agent"
	"github.com/oodle-ai/oodle-agent/pkg/policy"
)

func TestEndsWithReadyForQuery(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want bool
	}{
		{
			"empty",
			nil,
			false,
		},
		{
			"too short",
			[]byte{1, 2, 3},
			false,
		},
		{
			"valid ReadyForQuery",
			buildPgMsg('Z', []byte{'I'}),
			true,
		},
		{
			"ReadyForQuery after other msg",
			append(
				buildPgMsg('T', []byte{0, 1}),
				buildPgMsg('Z', []byte{'I'})...,
			),
			true,
		},
		{
			"not ReadyForQuery",
			buildPgMsg('T', []byte{0, 1, 2}),
			false,
		},
		{
			"Z at wrong position but not RFQ",
			buildPgMsg('Z', []byte{1, 2, 3}),
			false,
		},
		{
			"incomplete message",
			[]byte{'Z', 0, 0, 0},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := endsWithReadyForQuery(tt.data)
			if got != tt.want {
				t.Errorf(
					"endsWithReadyForQuery() = %v, "+
						"want %v",
					got,
					tt.want,
				)
			}
		})
	}
}

// buildPgMsg builds a Postgres backend message:
// type (1 byte) + length (4 bytes, includes self) +
// body.
func buildPgMsg(
	msgType byte,
	body []byte,
) []byte {
	length := uint32(4 + len(body))
	msg := make([]byte, 1+4+len(body))
	msg[0] = msgType
	binary.BigEndian.PutUint32(msg[1:5], length)
	copy(msg[5:], body)
	return msg
}

func TestPolicyEnforcement_HTTP(t *testing.T) {
	pol := &policy.Policy{
		EnableAccessRestrictions: true,
		AllowedEndpoints: []string{
			"allowed.host:80",
		},
	}
	// Manually compile since we constructed inline.
	polBytes := []byte(
		"enable_access_restrictions: true\n" +
			"allowed_endpoints:\n" +
			"  - \"allowed.host:80\"\n",
	)
	p, err := policy.LoadFromBytes(polBytes)
	if err != nil {
		t.Fatal(err)
	}
	_ = pol // unused, we use p below

	h := NewHandler(
		nil,
		p,
		DefaultTimeouts(),
		DefaultBufferSizes(),
	)

	resp := h.HandleRequest(
		context.Background(),
		&agent.ProxyRequest{
			Protocol: ProtoHTTP,
			URL:      "http://denied.host/path",
		},
	)
	if resp.Error == "" {
		t.Fatal("expected policy violation error")
	}

	resp = h.HandleRequest(
		context.Background(),
		&agent.ProxyRequest{
			Protocol: ProtoHTTP,
			URL:      "http://allowed.host/path",
		},
	)
	// This will fail with a network error (no
	// server), but should NOT be a policy violation.
	if resp.Error != "" &&
		contains(resp.Error, "policy violation") {
		t.Fatalf(
			"unexpected policy violation: %s",
			resp.Error,
		)
	}
}

func TestPolicyEnforcement_K8s(t *testing.T) {
	polBytes := []byte(
		"enable_access_restrictions: true\n" +
			"allowed_endpoints: []\n" +
			"kubernetes:\n" +
			"  allowed_namespaces:\n" +
			"    - default\n" +
			"  allowed_resources:\n" +
			"    - pods\n" +
			"  deny_resources:\n" +
			"    - secrets\n",
	)
	p, err := policy.LoadFromBytes(polBytes)
	if err != nil {
		t.Fatal(err)
	}

	h := NewHandler(
		nil,
		p,
		DefaultTimeouts(),
		DefaultBufferSizes(),
	)

	// Denied resource.
	resp := h.HandleRequest(
		context.Background(),
		&agent.ProxyRequest{
			Protocol:     ProtoK8sMeta,
			K8sResource:  "secrets",
			K8sNamespace: "default",
		},
	)
	if resp.Error == "" {
		t.Fatal("expected policy violation for secrets")
	}

	// Denied namespace.
	resp = h.HandleRequest(
		context.Background(),
		&agent.ProxyRequest{
			Protocol:     ProtoK8sMeta,
			K8sResource:  "pods",
			K8sNamespace: "kube-system",
		},
	)
	if resp.Error == "" {
		t.Fatal(
			"expected policy violation for " +
				"kube-system",
		)
	}
}

func TestPolicyDisabled(t *testing.T) {
	p := policy.Default()
	h := NewHandler(
		nil,
		p,
		DefaultTimeouts(),
		DefaultBufferSizes(),
	)

	// Should not be blocked by policy.
	resp := h.HandleRequest(
		context.Background(),
		&agent.ProxyRequest{
			Protocol: ProtoHTTP,
			URL:      "http://any.host/path",
		},
	)
	// May fail with network error, but not policy.
	if resp.Error != "" &&
		contains(resp.Error, "policy violation") {
		t.Fatalf(
			"unexpected policy violation: %s",
			resp.Error,
		)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) &&
		searchSubstring(s, substr)
}

func searchSubstring(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
