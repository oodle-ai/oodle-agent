package agent

import (
	"testing"
	"time"
)

func TestBinaryStreamFrame_RoundTrip(t *testing.T) {
	tests := []struct {
		name     string
		streamID string
		data     []byte
	}{
		{
			"simple",
			"s-123-agent",
			[]byte("hello world"),
		},
		{
			"empty data",
			"s-456",
			[]byte{},
		},
		{
			"binary data",
			"stream-1",
			[]byte{0x00, 0xFF, 0x01, 0xFE},
		},
		{
			"long stream ID",
			"s-1234567890123456789-myagent",
			[]byte("payload"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			frame := encodeBinaryStreamFrame(
				tt.streamID,
				tt.data,
			)
			gotID, gotData, err :=
				decodeBinaryStreamFrame(frame)
			if err != nil {
				t.Fatalf("decode error: %v", err)
			}
			if gotID != tt.streamID {
				t.Errorf(
					"streamID = %q, want %q",
					gotID,
					tt.streamID,
				)
			}
			if len(gotData) != len(tt.data) {
				t.Errorf(
					"data len = %d, want %d",
					len(gotData),
					len(tt.data),
				)
			}
		})
	}
}

func TestDecodeBinaryStreamFrame_Errors(t *testing.T) {
	tests := []struct {
		name  string
		frame []byte
	}{
		{"nil", nil},
		{"too short", []byte{0, 0}},
		{
			"invalid length",
			[]byte{0, 0, 0, 100},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := decodeBinaryStreamFrame(
				tt.frame,
			)
			if err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestTimestampValidation(t *testing.T) {
	a := &Agent{
		config: Config{
			TimestampMaxAge: 60 * time.Second,
		},
	}

	tests := []struct {
		name    string
		ts      int64
		wantErr bool
	}{
		{
			"zero timestamp (rejected)",
			0,
			true,
		},
		{
			"current timestamp",
			time.Now().UnixMilli(),
			false,
		},
		{
			"10 seconds ago",
			time.Now().Add(
				-10 * time.Second,
			).UnixMilli(),
			false,
		},
		{
			"2 minutes ago (too old)",
			time.Now().Add(
				-2 * time.Minute,
			).UnixMilli(),
			true,
		},
		{
			"2 minutes in future (too far)",
			time.Now().Add(
				2 * time.Minute,
			).UnixMilli(),
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := &Message{Timestamp: tt.ts}
			err := a.validateTimestamp(msg)
			if (err != nil) != tt.wantErr {
				t.Errorf(
					"validateTimestamp() err=%v, "+
						"wantErr=%v",
					err,
					tt.wantErr,
				)
			}
		})
	}
}

func TestRequestIDDedup(t *testing.T) {
	c := &connection{
		requestIDCache: make(map[string]time.Time),
	}

	// First add should succeed.
	if !c.addRequestID("req-1") {
		t.Fatal("expected first add to succeed")
	}

	// Duplicate should fail.
	if c.addRequestID("req-1") {
		t.Fatal("expected duplicate to fail")
	}

	// Different ID should succeed.
	if !c.addRequestID("req-2") {
		t.Fatal(
			"expected different ID to succeed",
		)
	}
}

func TestConfigDefaults(t *testing.T) {
	a := New(Config{
		GatewayURLs: []string{"wss://gw:9030/ws"},
	})
	if a.config.MaxConcurrentStreams != 100 {
		t.Errorf(
			"MaxConcurrentStreams = %d, want 100",
			a.config.MaxConcurrentStreams,
		)
	}
	if a.config.MaxConcurrentRequests != 50 {
		t.Errorf(
			"MaxConcurrentRequests = %d, want 50",
			a.config.MaxConcurrentRequests,
		)
	}
	if a.config.StreamInactivityTimeout !=
		5*time.Minute {
		t.Errorf(
			"StreamInactivityTimeout = %v, "+
				"want 5m",
			a.config.StreamInactivityTimeout,
		)
	}
	if a.config.TimestampMaxAge !=
		60*time.Second {
		t.Errorf(
			"TimestampMaxAge = %v, want 60s",
			a.config.TimestampMaxAge,
		)
	}
	if a.config.ReconnectInterval !=
		5*time.Second {
		t.Errorf(
			"ReconnectInterval = %v, want 5s",
			a.config.ReconnectInterval,
		)
	}
}
