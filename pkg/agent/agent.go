package agent

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

// authError is a fatal authentication failure that
// should not be retried.
type authError struct {
	msg string
}

func (e *authError) Error() string {
	return e.msg
}

// Message types matching the gateway server protocol.
const (
	MsgTypeAuth         = "auth"
	MsgTypeAuthResponse = "auth_response"
	MsgTypeHeartbeat    = "heartbeat"
	MsgTypeHeartbeatAck = "heartbeat_ack"
	MsgTypeRequest      = "request"
	MsgTypeResponse     = "response"
	MsgTypeError        = "error"

	// Stream message types for TCP tunneling.
	MsgTypeStreamOpen    = "stream_open"
	MsgTypeStreamOpenAck = "stream_open_ack"
	MsgTypeStreamData    = "stream_data"
	MsgTypeStreamClose   = "stream_close"
	MsgTypeStreamError   = "stream_error"
)

// Message is the WebSocket message envelope.
type Message struct {
	Type      string          `json:"type"`
	RequestID string          `json:"request_id,omitempty"`
	Timestamp int64           `json:"timestamp,omitempty"`
	Payload   json.RawMessage `json:"payload"`
}

// AuthPayload is sent during the handshake.
// With mTLS, identity is verified by the TLS layer;
// these fields are used for routing and versioning.
type AuthPayload struct {
	Instance     string   `json:"instance"`
	AgentID      string   `json:"agent_id"`
	AgentName    string   `json:"agent_name"`
	Version      string   `json:"version,omitempty"`
	Capabilities []string `json:"capabilities,omitempty"`

	// Registration flow (first time).
	RegistrationToken string `json:"registration_token,omitempty"`
	CSR               string `json:"csr,omitempty"`

	// Cert-based reconnect.
	ClientCert string `json:"client_cert,omitempty"`
	Signature  []byte `json:"signature,omitempty"`
	SignedData []byte `json:"signed_data,omitempty"`
}

// AuthResponse from the server.
type AuthResponse struct {
	Success    bool   `json:"success"`
	Error      string `json:"error,omitempty"`
	SignedCert string `json:"signed_cert,omitempty"`
	CACert     string `json:"ca_cert,omitempty"`
}

// PolicyChecker is an interface for endpoint policy
// enforcement. This avoids importing the policy
// package directly to keep the agent package
// dependency-free.
type PolicyChecker interface {
	CheckAddress(address string) error
}

// Config is the agent configuration.
type Config struct {
	// Instance is the Oodle customer instance ID.
	Instance string
	// AgentID is the unique agent identifier.
	AgentID string
	// AgentName is the human-readable agent name.
	AgentName string
	// Version is the agent semver version string,
	// sent during auth for enforcement.
	Version string
	// TLSCertFile is the path to the client TLS
	// certificate for mTLS authentication.
	TLSCertFile string
	// TLSKeyFile is the path to the client TLS
	// private key.
	TLSKeyFile string
	// CACertFile is the path to the CA certificate
	// for verifying the gateway's TLS certificate.
	CACertFile string
	// PinnedCACertFile is the path to the pinned
	// Amazon CA certificate. If set, the agent will
	// only trust this CA for gateway connections.
	PinnedCACertFile string
	// GatewayURLs are the WebSocket URLs for the
	// gateway servers (typically 2 for HA).
	GatewayURLs []string
	// ReconnectInterval is the wait time between
	// reconnection attempts.
	ReconnectInterval time.Duration
	// RequestHandler processes incoming proxy
	// requests.
	RequestHandler RequestHandler
	// Policy enforces endpoint whitelist restrictions
	// on stream_open requests. Nil means no
	// restrictions.
	Policy PolicyChecker
	// MaxConcurrentStreams limits active TCP tunnel
	// streams per connection. 0 means default (100).
	MaxConcurrentStreams int
	// MaxConcurrentRequests limits in-flight proxy
	// requests per connection. 0 means default (50).
	MaxConcurrentRequests int
	// StreamInactivityTimeout closes idle streams.
	// 0 means default (5 minutes).
	StreamInactivityTimeout time.Duration
	// TimestampMaxAge is the maximum acceptable age
	// of a message timestamp. 0 means default (60s).
	TimestampMaxAge time.Duration
	// RegistrationToken is the one-time token for
	// initial mTLS bootstrap. Empty if already
	// registered (has cert).
	RegistrationToken string
	// CertStore persists mTLS certs to K8s Secret.
	// Nil disables cert persistence.
	CertStore CertStore
}

// CertStore is an interface for persisting agent
// mTLS certificates. Implemented by certsecret.Store.
type CertStore interface {
	SaveCert(
		ctx context.Context,
		certPEM, keyPEM, caPEM []byte,
	) error
}

// RequestHandler processes proxy requests from the
// gateway server.
type RequestHandler interface {
	HandleRequest(
		ctx context.Context,
		req *ProxyRequest,
	) *ProxyResponse
}

// ProxyRequest from the gateway server.
type ProxyRequest struct {
	Protocol     string            `json:"protocol"`
	Method       string            `json:"method,omitempty"`
	URL          string            `json:"url,omitempty"`
	Headers      map[string]string `json:"headers,omitempty"`
	Body         []byte            `json:"body,omitempty"`
	Address      string            `json:"address,omitempty"`
	K8sResource  string            `json:"k8s_resource,omitempty"`
	K8sNamespace string            `json:"k8s_namespace,omitempty"`
	K8sName      string            `json:"k8s_name,omitempty"`
}

// ProxyResponse to send back to the gateway.
type ProxyResponse struct {
	StatusCode int               `json:"status_code,omitempty"`
	Headers    map[string]string `json:"headers,omitempty"`
	Body       []byte            `json:"body,omitempty"`
	Error      string            `json:"error,omitempty"`
}

// StreamTLSConfig carries TLS configuration from the
// gateway for the agent to use when connecting to the
// target Postgres server.
type StreamTLSConfig struct {
	SSLMode    string `json:"ssl_mode"`
	CACert     string `json:"ca_cert,omitempty"`
	ClientCert string `json:"client_cert,omitempty"`
	ClientKey  string `json:"client_key,omitempty"`
}

// StreamOpenPayload is received from the gateway asking
// the agent to open a TCP connection.
type StreamOpenPayload struct {
	StreamID  string           `json:"stream_id"`
	Address   string           `json:"address"`
	TLSConfig *StreamTLSConfig `json:"tls_config,omitempty"`
}

// StreamOpenAckPayload is sent back to confirm whether
// the TCP connection was opened.
type StreamOpenAckPayload struct {
	StreamID string `json:"stream_id"`
	Success  bool   `json:"success"`
	Error    string `json:"error,omitempty"`
}

// StreamDataPayload carries raw bytes for a stream.
type StreamDataPayload struct {
	StreamID string `json:"stream_id"`
	Data     []byte `json:"data"`
}

// StreamClosePayload signals stream closure.
type StreamClosePayload struct {
	StreamID string `json:"stream_id"`
}

// StreamErrorPayload signals a stream error.
type StreamErrorPayload struct {
	StreamID string `json:"stream_id"`
	Error    string `json:"error"`
}

// Default resource limits.
const (
	defaultMaxStreams      = 100
	defaultMaxRequests     = 50
	defaultStreamTimeout   = 5 * time.Minute
	defaultTimestampMaxAge = 60 * time.Second
	streamTCPReadBuf       = 32 * 1024
	// requestIDCacheSize is the max entries in the
	// dedup cache.
	requestIDCacheSize = 10000
)

// Agent connects to gateway servers and handles
// proxy requests.
type Agent struct {
	config Config
	conns  []*connection
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	// pendingKeyPEM holds the private key generated
	// during registration, until the signed cert is
	// received and saved.
	pendingKeyPEM []byte
}

// stream wraps a TCP connection with a write channel
// for non-blocking writes from the read loop.
type stream struct {
	conn      net.Conn
	dataCh    chan []byte
	done      chan struct{}
	closeOnce sync.Once
}

type connection struct {
	url    string
	conn   *websocket.Conn
	mu     sync.Mutex
	active bool

	// streams tracks active TCP tunnel streams keyed
	// by stream ID.
	streams      map[string]*stream
	streamsMu    sync.Mutex
	streamCount  atomic.Int32
	requestCount atomic.Int32

	// requestIDCache is a bounded dedup cache for
	// replay prevention.
	requestIDCache   map[string]time.Time
	requestIDCacheMu sync.Mutex
}

func (c *connection) addRequestID(
	id string,
) bool {
	c.requestIDCacheMu.Lock()
	defer c.requestIDCacheMu.Unlock()

	if c.requestIDCache == nil {
		c.requestIDCache = make(map[string]time.Time)
	}

	// Evict expired entries when cache is full.
	if len(c.requestIDCache) >= requestIDCacheSize {
		now := time.Now()
		for k, v := range c.requestIDCache {
			if now.Sub(v) > 2*time.Minute {
				delete(c.requestIDCache, k)
			}
		}
	}

	if _, exists := c.requestIDCache[id]; exists {
		return false // duplicate
	}
	c.requestIDCache[id] = time.Now()
	return true
}

// New creates a new agent.
func New(config Config) *Agent {
	if config.ReconnectInterval == 0 {
		config.ReconnectInterval = 5 * time.Second
	}
	if config.MaxConcurrentStreams == 0 {
		config.MaxConcurrentStreams = defaultMaxStreams
	}
	if config.MaxConcurrentRequests == 0 {
		config.MaxConcurrentRequests = defaultMaxRequests
	}
	if config.StreamInactivityTimeout == 0 {
		config.StreamInactivityTimeout = defaultStreamTimeout
	}
	if config.TimestampMaxAge == 0 {
		config.TimestampMaxAge = defaultTimestampMaxAge
	}
	ctx, cancel := context.WithCancel(
		context.Background(),
	)
	conns := make(
		[]*connection,
		len(config.GatewayURLs),
	)
	for i, url := range config.GatewayURLs {
		conns[i] = &connection{
			url:            url,
			streams:        make(map[string]*stream),
			requestIDCache: make(map[string]time.Time),
		}
	}
	return &Agent{
		config: config,
		conns:  conns,
		ctx:    ctx,
		cancel: cancel,
	}
}

// Start connects to all gateway servers and begins
// processing requests.
func (a *Agent) Start() error {
	for i, c := range a.conns {
		a.wg.Add(1)
		go a.connectLoop(i, c)
	}
	log.Printf(
		"Agent %s started, connecting to %d gateways",
		a.config.AgentName,
		len(a.conns),
	)
	return nil
}

// Stop gracefully disconnects from all gateways.
func (a *Agent) Stop() {
	a.cancel()
	for _, c := range a.conns {
		c.mu.Lock()
		if c.conn != nil {
			c.conn.Close()
		}
		c.mu.Unlock()
	}
	a.wg.Wait()
	log.Printf("Agent %s stopped", a.config.AgentName)
}

func (a *Agent) connectLoop(
	idx int,
	c *connection,
) {
	defer a.wg.Done()

	for {
		select {
		case <-a.ctx.Done():
			return
		default:
		}

		err := a.connect(c)
		if err != nil {
			var ae *authError
			if errors.As(err, &ae) {
				log.Fatalf(
					"Connection %d to %s: %v",
					idx,
					c.url,
					err,
				)
			}
			log.Printf(
				"Connection %d to %s failed: %v, "+
					"reconnecting in %v",
				idx,
				c.url,
				err,
				a.config.ReconnectInterval,
			)
			select {
			case <-time.After(
				a.config.ReconnectInterval,
			):
			case <-a.ctx.Done():
				return
			}
			continue
		}

		// Connection established, run read loop.
		a.readLoop(c)

		c.mu.Lock()
		c.active = false
		if c.conn != nil {
			c.conn.Close()
			c.conn = nil
		}
		c.mu.Unlock()

		select {
		case <-a.ctx.Done():
			return
		case <-time.After(
			a.config.ReconnectInterval,
		):
		}
	}
}

func (a *Agent) connect(c *connection) error {
	tlsCfg, err := a.buildTLSConfig()
	if err != nil {
		return fmt.Errorf("TLS config: %w", err)
	}
	dialer := &websocket.Dialer{
		TLSClientConfig:  tlsCfg,
		HandshakeTimeout: 30 * time.Second,
	}
	conn, _, err := dialer.Dial(c.url, nil)
	if err != nil {
		return fmt.Errorf("dial %s: %w", c.url, err)
	}

	// Build auth payload based on whether we have
	// a client cert (reconnect) or need to register.
	auth := AuthPayload{
		Instance:  a.config.Instance,
		AgentID:   a.config.AgentID,
		AgentName: a.config.AgentName,
		Version:   a.config.Version,
	}

	hasCert := a.config.TLSCertFile != "" &&
		a.config.TLSKeyFile != ""

	if hasCert {
		// Cert-based reconnect: sign a challenge
		// to prove key possession.
		if err := a.buildCertAuth(&auth); err != nil {
			conn.Close()
			return fmt.Errorf(
				"build cert auth: %w", err,
			)
		}
	} else if a.config.RegistrationToken != "" {
		// First-time registration: generate key
		// pair + CSR and send with token.
		if err := a.buildRegistrationAuth(
			&auth,
		); err != nil {
			conn.Close()
			return fmt.Errorf(
				"build registration auth: %w", err,
			)
		}
	} else {
		conn.Close()
		return fmt.Errorf(
			"no client certificate and no " +
				"registration token -- cannot " +
				"authenticate",
		)
	}

	authBytes, err := json.Marshal(auth)
	if err != nil {
		conn.Close()
		return fmt.Errorf("marshal auth: %w", err)
	}
	authMsg := Message{
		Type:    MsgTypeAuth,
		Payload: authBytes,
	}
	msgBytes, err := json.Marshal(authMsg)
	if err != nil {
		conn.Close()
		return fmt.Errorf(
			"marshal auth message: %w", err,
		)
	}
	if err := conn.WriteMessage(
		websocket.TextMessage,
		msgBytes,
	); err != nil {
		conn.Close()
		return fmt.Errorf("send auth: %w", err)
	}

	// Read auth response.
	conn.SetReadDeadline(
		time.Now().Add(30 * time.Second),
	)
	_, respBytes, err := conn.ReadMessage()
	if err != nil {
		conn.Close()
		return fmt.Errorf(
			"read auth response: %w", err,
		)
	}
	conn.SetReadDeadline(time.Time{})

	var msg Message
	if err := json.Unmarshal(
		respBytes, &msg,
	); err != nil {
		conn.Close()
		return fmt.Errorf(
			"unmarshal auth response: %w", err,
		)
	}

	var authResp AuthResponse
	if err := json.Unmarshal(
		msg.Payload, &authResp,
	); err != nil {
		conn.Close()
		return fmt.Errorf(
			"unmarshal auth payload: %w", err,
		)
	}

	if !authResp.Success {
		conn.Close()
		return &authError{
			msg: fmt.Sprintf(
				"authentication failed: %s",
				authResp.Error,
			),
		}
	}

	// If we just registered, save the cert.
	if authResp.SignedCert != "" {
		if err := a.handleRegistrationResponse(
			&authResp,
		); err != nil {
			conn.Close()
			return fmt.Errorf(
				"save registration cert: %w", err,
			)
		}
	}

	c.mu.Lock()
	c.conn = conn
	c.active = true
	c.mu.Unlock()

	log.Printf("Connected to %s", c.url)
	return nil
}

// buildCertAuth reads the agent's client cert and
// signs a challenge (sha256 of timestamp|agentID)
// to prove private key possession.
func (a *Agent) buildCertAuth(
	auth *AuthPayload,
) error {
	certPEM, err := os.ReadFile(
		a.config.TLSCertFile,
	)
	if err != nil {
		return fmt.Errorf(
			"read cert %s: %w",
			a.config.TLSCertFile,
			err,
		)
	}
	keyPEM, err := os.ReadFile(
		a.config.TLSKeyFile,
	)
	if err != nil {
		return fmt.Errorf(
			"read key %s: %w",
			a.config.TLSKeyFile,
			err,
		)
	}

	// Parse private key.
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return fmt.Errorf("no PEM block in key file")
	}
	privKey, err := x509.ParseECPrivateKey(
		block.Bytes,
	)
	if err != nil {
		return fmt.Errorf(
			"parse private key: %w", err,
		)
	}

	// Sign challenge: sha256(timestamp|agentID).
	signedData := []byte(fmt.Sprintf(
		"%d|%s",
		time.Now().UnixMilli(),
		a.config.AgentID,
	))
	digest := sha256.Sum256(signedData)
	sig, err := ecdsa.SignASN1(
		rand.Reader, privKey, digest[:],
	)
	if err != nil {
		return fmt.Errorf("sign challenge: %w", err)
	}

	auth.ClientCert = string(certPEM)
	auth.Signature = sig
	auth.SignedData = signedData
	return nil
}

// buildRegistrationAuth generates an ECDSA key pair
// and CSR, attaches them to the auth payload along
// with the registration token.
func (a *Agent) buildRegistrationAuth(
	auth *AuthPayload,
) error {
	key, err := ecdsa.GenerateKey(
		elliptic.P256(), rand.Reader,
	)
	if err != nil {
		return fmt.Errorf("generate key: %w", err)
	}

	csrTemplate := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: a.config.AgentID,
			Organization: []string{
				"oodle-agent",
			},
		},
		DNSNames: []string{
			a.config.AgentID,
			a.config.Instance,
		},
	}
	csrDER, err := x509.CreateCertificateRequest(
		rand.Reader, csrTemplate, key,
	)
	if err != nil {
		return fmt.Errorf("create CSR: %w", err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	})

	// Marshal private key for later storage.
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return fmt.Errorf(
			"marshal private key: %w", err,
		)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyDER,
	})

	// Stash key PEM for handleRegistrationResponse.
	a.pendingKeyPEM = keyPEM

	auth.RegistrationToken = a.config.RegistrationToken
	auth.CSR = string(csrPEM)
	return nil
}

// handleRegistrationResponse saves the signed cert
// returned by the gateway to disk and K8s Secret.
func (a *Agent) handleRegistrationResponse(
	resp *AuthResponse,
) error {
	certPEM := []byte(resp.SignedCert)
	caPEM := []byte(resp.CACert)
	keyPEM := a.pendingKeyPEM
	a.pendingKeyPEM = nil

	if len(keyPEM) == 0 {
		return fmt.Errorf(
			"no pending key from registration",
		)
	}

	// Write to local files.
	certDir := "/tmp/oodle-certs"
	certPath := certDir + "/tls.crt"
	keyPath := certDir + "/tls.key"
	caPath := certDir + "/ca.crt"

	if err := os.MkdirAll(certDir, 0700); err != nil {
		return fmt.Errorf(
			"create cert dir: %w", err,
		)
	}
	if err := os.WriteFile(
		certPath, certPEM, 0600,
	); err != nil {
		return fmt.Errorf(
			"write cert: %w", err,
		)
	}
	if err := os.WriteFile(
		keyPath, keyPEM, 0600,
	); err != nil {
		return fmt.Errorf(
			"write key: %w", err,
		)
	}
	if len(caPEM) > 0 {
		if err := os.WriteFile(
			caPath, caPEM, 0600,
		); err != nil {
			return fmt.Errorf(
				"write CA cert: %w", err,
			)
		}
		a.config.CACertFile = caPath
	}

	// Update config so reconnects use cert auth.
	a.config.TLSCertFile = certPath
	a.config.TLSKeyFile = keyPath
	a.config.RegistrationToken = ""

	log.Printf(
		"Registration complete: cert saved to %s",
		certPath,
	)

	// Persist to K8s Secret if configured.
	if a.config.CertStore != nil {
		ctx := context.Background()
		if err := a.config.CertStore.SaveCert(
			ctx, certPEM, keyPEM, caPEM,
		); err != nil {
			log.Printf(
				"WARNING: failed to save cert "+
					"to K8s secret: %v",
				err,
			)
		}
	}

	return nil
}

// buildTLSConfig creates the TLS configuration for
// gateway connections with certificate pinning and
// optional mTLS client certificates.
func (a *Agent) buildTLSConfig() (
	*tls.Config, error,
) {
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	// Load pinned CA for gateway TLS certificate
	// verification. This is required -- the agent
	// must only trust the specific CA that signs the
	// gateway's TLS certificate (e.g. Amazon Root
	// CA), not the full system CA bundle.
	if a.config.PinnedCACertFile == "" {
		return nil, fmt.Errorf(
			"pinned CA cert file is required " +
				"(--pinned-ca-cert-file or " +
				"OODLE_PINNED_CA_CERT_FILE)",
		)
	}
	caPEM, err := os.ReadFile(
		a.config.PinnedCACertFile,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"read pinned CA cert %s: %w",
			a.config.PinnedCACertFile,
			err,
		)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf(
			"failed to parse pinned CA cert %s",
			a.config.PinnedCACertFile,
		)
	}
	tlsCfg.RootCAs = pool

	// Load client certificate for mTLS and check
	// expiry before attempting to connect.
	if a.config.TLSCertFile != "" &&
		a.config.TLSKeyFile != "" {
		cert, err := tls.LoadX509KeyPair(
			a.config.TLSCertFile,
			a.config.TLSKeyFile,
		)
		if err != nil {
			return nil, fmt.Errorf(
				"load client cert: %w",
				err,
			)
		}
		// Check expiry on the leaf certificate.
		if len(cert.Certificate) > 0 {
			leaf, pErr := x509.ParseCertificate(
				cert.Certificate[0],
			)
			if pErr == nil {
				remaining := time.Until(
					leaf.NotAfter,
				)
				if remaining <= 0 {
					return nil, fmt.Errorf(
						"client certificate "+
							"expired at %s",
						leaf.NotAfter.Format(
							time.RFC3339,
						),
					)
				}
				if remaining < 30*24*time.Hour {
					log.Printf(
						"WARNING: client cert "+
							"expires in %d days",
						int(
							remaining.Hours()/24,
						),
					)
				}
			}
		}
		tlsCfg.Certificates = []tls.Certificate{
			cert,
		}
	}

	return tlsCfg, nil
}

// validateTimestamp checks that the message timestamp is
// within the acceptable age. Returns an error if the
// message is too old or has a future timestamp.
func (a *Agent) validateTimestamp(
	msg *Message,
) error {
	if msg.Timestamp == 0 {
		return fmt.Errorf(
			"missing timestamp in message",
		)
	}
	now := time.Now().UnixMilli()
	diff := now - msg.Timestamp
	if diff < 0 {
		diff = -diff
	}
	maxAge := a.config.TimestampMaxAge.Milliseconds()
	if diff > maxAge {
		return fmt.Errorf(
			"message timestamp too old: "+
				"age=%dms, max=%dms",
			diff,
			maxAge,
		)
	}
	return nil
}

func (a *Agent) readLoop(c *connection) {
	for {
		select {
		case <-a.ctx.Done():
			return
		default:
		}

		messageType, msgBytes, err := c.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(
				err,
				websocket.CloseGoingAway,
				websocket.CloseNormalClosure,
			) {
				log.Printf(
					"Read error from %s: %v",
					c.url,
					err,
				)
			}
			return
		}

		// Handle binary frames as stream_data
		// from gateway.
		if messageType == websocket.BinaryMessage {
			a.handleBinaryStreamData(c, msgBytes)
			continue
		}

		var msg Message
		if err := json.Unmarshal(
			msgBytes,
			&msg,
		); err != nil {
			log.Printf(
				"Failed to unmarshal message: %v",
				err,
			)
			continue
		}

		switch msg.Type {
		case MsgTypeHeartbeat:
			a.sendHeartbeatAck(c)

		case MsgTypeRequest:
			// Validate timestamp.
			if err := a.validateTimestamp(
				&msg,
			); err != nil {
				log.Printf(
					"Request %s rejected: %v",
					msg.RequestID,
					err,
				)
				a.sendError(
					c,
					msg.RequestID,
					"policy_violation: "+
						err.Error(),
				)
				continue
			}
			// Dedup request ID.
			if msg.RequestID != "" &&
				!c.addRequestID(msg.RequestID) {
				log.Printf(
					"Duplicate request ID: %s",
					msg.RequestID,
				)
				continue
			}
			// Enforce request concurrency limit.
			cur := c.requestCount.Load()
			if cur >= int32(
				a.config.MaxConcurrentRequests,
			) {
				a.sendError(
					c,
					msg.RequestID,
					"busy: too many concurrent "+
						"requests",
				)
				continue
			}
			c.requestCount.Add(1)
			go func() {
				defer c.requestCount.Add(-1)
				a.handleRequest(c, &msg)
			}()

		case MsgTypeStreamOpen:
			// Validate timestamp.
			if err := a.validateTimestamp(
				&msg,
			); err != nil {
				log.Printf(
					"Stream open rejected: %v",
					err,
				)
				// Try to extract stream ID for
				// the error ack.
				var p StreamOpenPayload
				if json.Unmarshal(
					msg.Payload,
					&p,
				) == nil {
					a.sendStreamOpenAck(
						c,
						p.StreamID,
						false,
						"policy_violation: "+
							err.Error(),
					)
				}
				continue
			}
			go a.handleStreamOpen(c, &msg)

		case MsgTypeStreamData:
			a.handleStreamData(c, &msg)

		case MsgTypeStreamClose:
			a.handleStreamClose(c, &msg)

		default:
			log.Printf(
				"Unknown message type %q, "+
					"ignoring",
				msg.Type,
			)
		}
	}
}

func (a *Agent) sendHeartbeatAck(c *connection) {
	payload, err := json.Marshal(
		map[string]int64{
			"ts": time.Now().UnixMilli(),
		},
	)
	if err != nil {
		log.Printf(
			"Failed to marshal heartbeat ack: %v",
			err,
		)
		return
	}
	msg := Message{
		Type:    MsgTypeHeartbeatAck,
		Payload: payload,
	}
	msgBytes, err := json.Marshal(msg)
	if err != nil {
		log.Printf(
			"Failed to marshal heartbeat ack msg: %v",
			err,
		)
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil {
		if err := c.conn.WriteMessage(
			websocket.TextMessage,
			msgBytes,
		); err != nil {
			log.Printf(
				"Failed to send heartbeat ack: %v",
				err,
			)
		}
	}
}

func (a *Agent) handleRequest(
	c *connection,
	msg *Message,
) {
	var req ProxyRequest
	if err := json.Unmarshal(
		msg.Payload,
		&req,
	); err != nil {
		a.sendError(c, msg.RequestID, err.Error())
		return
	}

	resp := a.config.RequestHandler.HandleRequest(
		a.ctx,
		&req,
	)

	respPayload, err := json.Marshal(resp)
	if err != nil {
		log.Printf(
			"Failed to marshal response: %v",
			err,
		)
		a.sendError(
			c,
			msg.RequestID,
			"internal: marshal error",
		)
		return
	}
	respMsg := Message{
		Type:      MsgTypeResponse,
		RequestID: msg.RequestID,
		Payload:   respPayload,
	}
	msgBytes, err := json.Marshal(respMsg)
	if err != nil {
		log.Printf(
			"Failed to marshal response msg: %v",
			err,
		)
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil {
		if err := c.conn.WriteMessage(
			websocket.TextMessage,
			msgBytes,
		); err != nil {
			log.Printf(
				"Failed to send response for %s: %v",
				msg.RequestID,
				err,
			)
		}
	}
}

func (a *Agent) sendError(
	c *connection,
	requestID string,
	errMsg string,
) {
	resp := ProxyResponse{Error: errMsg}
	respPayload, err := json.Marshal(resp)
	if err != nil {
		log.Printf(
			"Failed to marshal error response: %v",
			err,
		)
		return
	}
	msg := Message{
		Type:      MsgTypeResponse,
		RequestID: requestID,
		Payload:   respPayload,
	}
	msgBytes, err := json.Marshal(msg)
	if err != nil {
		log.Printf(
			"Failed to marshal error msg: %v",
			err,
		)
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil {
		if err := c.conn.WriteMessage(
			websocket.TextMessage,
			msgBytes,
		); err != nil {
			log.Printf(
				"Failed to send error response: %v",
				err,
			)
		}
	}
}

// --- Stream handlers for TCP tunneling ---

func (a *Agent) handleStreamOpen(
	c *connection,
	msg *Message,
) {
	var payload StreamOpenPayload
	if err := json.Unmarshal(
		msg.Payload,
		&payload,
	); err != nil {
		log.Printf(
			"Failed to unmarshal stream open: %v",
			err,
		)
		return
	}

	// Enforce max concurrent streams limit.
	cur := c.streamCount.Load()
	if cur >= int32(
		a.config.MaxConcurrentStreams,
	) {
		a.sendStreamOpenAck(
			c,
			payload.StreamID,
			false,
			"busy: too many concurrent streams",
		)
		return
	}

	// Enforce endpoint whitelist policy.
	if a.config.Policy != nil {
		if err := a.config.Policy.CheckAddress(
			payload.Address,
		); err != nil {
			log.Printf(
				"Stream %s: policy denied %s: %v",
				payload.StreamID,
				payload.Address,
				err,
			)
			a.sendStreamOpenAck(
				c,
				payload.StreamID,
				false,
				err.Error(),
			)
			return
		}
	}

	// Open a TCP connection to the target address.
	log.Printf(
		"Stream %s: connecting to %s",
		payload.StreamID,
		payload.Address,
	)
	tcpConn, err := net.DialTimeout(
		"tcp",
		payload.Address,
		15*time.Second,
	)

	if err != nil {
		log.Printf(
			"Stream %s: dial error for %s: %v",
			payload.StreamID,
			payload.Address,
			err,
		)
		a.sendStreamOpenAck(
			c,
			payload.StreamID,
			false,
			err.Error(),
		)
		return
	}

	// If TLS config is present, perform Postgres SSL
	// negotiation and upgrade to TLS before relaying.
	var conn net.Conn = tcpConn
	if payload.TLSConfig != nil &&
		payload.TLSConfig.SSLMode != "" &&
		payload.TLSConfig.SSLMode != "disable" {
		conn, err = a.upgradePgTLS(
			tcpConn,
			payload.Address,
			payload.TLSConfig,
		)
		if err != nil {
			log.Printf(
				"Stream %s: TLS upgrade failed "+
					"for %s: %v",
				payload.StreamID,
				payload.Address,
				err,
			)
			tcpConn.Close()
			a.sendStreamOpenAck(
				c,
				payload.StreamID,
				false,
				fmt.Sprintf(
					"TLS upgrade: %v",
					err,
				),
			)
			return
		}
	}

	// Create stream with a write channel.
	s := &stream{
		conn:   conn,
		dataCh: make(chan []byte, 256),
		done:   make(chan struct{}),
	}

	// Register the stream.
	c.streamsMu.Lock()
	c.streams[payload.StreamID] = s
	c.streamsMu.Unlock()
	c.streamCount.Add(1)

	a.sendStreamOpenAck(
		c,
		payload.StreamID,
		true,
		"",
	)

	// Start the per-stream write goroutine.
	go a.streamWriteLoop(
		c,
		payload.StreamID,
		s,
	)

	// Start reading from TCP and forwarding to
	// gateway.
	go a.streamTCPToWS(c, payload.StreamID, s)
}

// handleBinaryStreamData processes binary WebSocket
// frames carrying stream data from the gateway.
func (a *Agent) handleBinaryStreamData(
	c *connection,
	frame []byte,
) {
	streamID, data, err := decodeBinaryStreamFrame(
		frame,
	)
	if err != nil {
		log.Printf(
			"Failed to decode binary stream frame: %v",
			err,
		)
		return
	}

	c.streamsMu.Lock()
	s, ok := c.streams[streamID]
	c.streamsMu.Unlock()

	if !ok {
		return
	}

	select {
	case s.dataCh <- data:
	default:
		log.Printf(
			"Stream %s: write channel full, closing",
			streamID,
		)
		a.closeStream(c, streamID)
	}
}

// handleStreamData dispatches data to the per-stream
// write channel instead of blocking the read loop.
func (a *Agent) handleStreamData(
	c *connection,
	msg *Message,
) {
	var payload StreamDataPayload
	if err := json.Unmarshal(
		msg.Payload,
		&payload,
	); err != nil {
		log.Printf(
			"Failed to unmarshal stream data: %v",
			err,
		)
		return
	}

	c.streamsMu.Lock()
	s, ok := c.streams[payload.StreamID]
	c.streamsMu.Unlock()

	if !ok {
		return
	}

	// Non-blocking send to the per-stream writer.
	select {
	case s.dataCh <- payload.Data:
	default:
		// Channel full -- stream is too slow.
		log.Printf(
			"Stream %s: write channel full, closing",
			payload.StreamID,
		)
		a.closeStream(c, payload.StreamID)
	}
}

// streamWriteLoop drains the data channel and writes to
// the TCP connection. This runs in its own goroutine so
// the read loop is never blocked by slow TCP writes.
func (a *Agent) streamWriteLoop(
	c *connection,
	streamID string,
	s *stream,
) {
	defer func() {
		a.closeStream(c, streamID)
	}()

	for {
		select {
		case data, ok := <-s.dataCh:
			if !ok {
				return
			}
			// Set inactivity deadline.
			s.conn.SetWriteDeadline(
				time.Now().Add(
					a.config.StreamInactivityTimeout,
				),
			)
			if _, err := s.conn.Write(data); err != nil {
				log.Printf(
					"Stream %s: write error: %v",
					streamID,
					err,
				)
				return
			}
		case <-s.done:
			return
		case <-a.ctx.Done():
			return
		}
	}
}

func (a *Agent) handleStreamClose(
	c *connection,
	msg *Message,
) {
	var payload StreamClosePayload
	if err := json.Unmarshal(
		msg.Payload,
		&payload,
	); err != nil {
		log.Printf(
			"Failed to unmarshal stream close: %v",
			err,
		)
		return
	}
	a.closeStream(c, payload.StreamID)
}

// streamTCPToWS reads from the TCP connection and sends
// stream_data messages back through the WebSocket.
func (a *Agent) streamTCPToWS(
	c *connection,
	streamID string,
	s *stream,
) {
	buf := make([]byte, streamTCPReadBuf)
	for {
		// Set inactivity deadline on reads.
		s.conn.SetReadDeadline(
			time.Now().Add(
				a.config.StreamInactivityTimeout,
			),
		)
		n, err := s.conn.Read(buf)
		if n > 0 {
			data := make([]byte, n)
			copy(data, buf[:n])
			a.sendStreamData(c, streamID, data)
		}
		if err != nil {
			if err != io.EOF {
				log.Printf(
					"Stream %s: TCP read error: %v",
					streamID,
					err,
				)
			}
			a.closeStream(c, streamID)
			a.sendStreamClose(c, streamID)
			return
		}
	}
}

// upgradePgTLS performs the Postgres SSL negotiation
// and upgrades a plain TCP connection to TLS.
//
// Postgres SSL flow:
//  1. Client sends SSLRequest (8 bytes)
//  2. Server responds 'S' (supports) or 'N' (no)
//  3. If 'S', TLS handshake proceeds
func (a *Agent) upgradePgTLS(
	tcpConn net.Conn,
	address string,
	cfg *StreamTLSConfig,
) (net.Conn, error) {
	// Send Postgres SSLRequest message:
	// 4 bytes length (8) + 4 bytes code (80877103).
	var sslReq [8]byte
	binary.BigEndian.PutUint32(sslReq[0:4], 8)
	binary.BigEndian.PutUint32(
		sslReq[4:8],
		80877103,
	)

	tcpConn.SetDeadline(
		time.Now().Add(15 * time.Second),
	)
	defer tcpConn.SetDeadline(time.Time{})

	if _, err := tcpConn.Write(sslReq[:]); err != nil {
		return nil, fmt.Errorf(
			"send SSLRequest: %w",
			err,
		)
	}

	// Read single-byte response.
	var resp [1]byte
	if _, err := io.ReadFull(
		tcpConn,
		resp[:],
	); err != nil {
		return nil, fmt.Errorf(
			"read SSL response: %w",
			err,
		)
	}

	if resp[0] != 'S' {
		return nil, fmt.Errorf(
			"server does not support SSL "+
				"(response=%c)",
			resp[0],
		)
	}

	// Build tls.Config based on SSL mode.
	tlsCfg := &tls.Config{}

	switch cfg.SSLMode {
	case "require":
		tlsCfg.InsecureSkipVerify = true
	case "verify-ca":
		tlsCfg.InsecureSkipVerify = false
		// Disable hostname verification; only
		// verify against CA.
		tlsCfg.VerifyConnection = func(
			cs tls.ConnectionState,
		) error {
			return nil
		}
		// Still need InsecureSkipVerify=true so
		// the default verifier doesn't check
		// hostname. We verify the cert chain via
		// VerifyPeerCertificate instead.
		tlsCfg.InsecureSkipVerify = true
		if cfg.CACert != "" {
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(
				[]byte(cfg.CACert),
			) {
				return nil, fmt.Errorf(
					"failed to parse CA cert",
				)
			}
			tlsCfg.VerifyPeerCertificate = func(
				rawCerts [][]byte,
				_ [][]*x509.Certificate,
			) error {
				return verifyCACert(
					rawCerts,
					pool,
				)
			}
		}
	case "verify-full":
		tlsCfg.InsecureSkipVerify = false
		// Extract hostname for SNI.
		host := address
		if idx := strings.LastIndex(
			host,
			":",
		); idx >= 0 {
			host = host[:idx]
		}
		tlsCfg.ServerName = host
		if cfg.CACert != "" {
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(
				[]byte(cfg.CACert),
			) {
				return nil, fmt.Errorf(
					"failed to parse CA cert",
				)
			}
			tlsCfg.RootCAs = pool
		}
	default:
		tlsCfg.InsecureSkipVerify = true
	}

	// Load client certificate if provided.
	if cfg.ClientCert != "" &&
		cfg.ClientKey != "" {
		cert, err := tls.X509KeyPair(
			[]byte(cfg.ClientCert),
			[]byte(cfg.ClientKey),
		)
		if err != nil {
			return nil, fmt.Errorf(
				"load client cert: %w",
				err,
			)
		}
		tlsCfg.Certificates = []tls.Certificate{
			cert,
		}
	}

	// Perform TLS handshake.
	tlsConn := tls.Client(tcpConn, tlsCfg)
	if err := tlsConn.Handshake(); err != nil {
		return nil, fmt.Errorf(
			"TLS handshake: %w",
			err,
		)
	}

	return tlsConn, nil
}

// verifyCACert verifies the server certificate chain
// against the CA pool without hostname verification
// (for verify-ca mode).
func verifyCACert(
	rawCerts [][]byte,
	pool *x509.CertPool,
) error {
	if len(rawCerts) == 0 {
		return fmt.Errorf("no server certificates")
	}
	cert, err := x509.ParseCertificate(
		rawCerts[0],
	)
	if err != nil {
		return fmt.Errorf(
			"parse server cert: %w",
			err,
		)
	}

	intermediates := x509.NewCertPool()
	for _, raw := range rawCerts[1:] {
		ic, err := x509.ParseCertificate(raw)
		if err != nil {
			continue
		}
		intermediates.AddCert(ic)
	}

	_, err = cert.Verify(x509.VerifyOptions{
		Roots:         pool,
		Intermediates: intermediates,
	})
	return err
}

func (a *Agent) closeStream(
	c *connection,
	streamID string,
) {
	c.streamsMu.Lock()
	s, ok := c.streams[streamID]
	if ok {
		delete(c.streams, streamID)
		c.streamCount.Add(-1)
	}
	c.streamsMu.Unlock()

	if ok && s != nil {
		s.closeOnce.Do(func() {
			close(s.done)
			close(s.dataCh)
			s.conn.Close()
		})
	}
}

func (a *Agent) sendStreamOpenAck(
	c *connection,
	streamID string,
	success bool,
	errMsg string,
) {
	payload, err := json.Marshal(StreamOpenAckPayload{
		StreamID: streamID,
		Success:  success,
		Error:    errMsg,
	})
	if err != nil {
		log.Printf(
			"Failed to marshal stream open ack: %v",
			err,
		)
		return
	}
	msg := Message{
		Type:    MsgTypeStreamOpenAck,
		Payload: payload,
	}
	msgBytes, err := json.Marshal(msg)
	if err != nil {
		log.Printf(
			"Failed to marshal stream open ack "+
				"msg: %v",
			err,
		)
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil {
		if err := c.conn.WriteMessage(
			websocket.TextMessage,
			msgBytes,
		); err != nil {
			log.Printf(
				"Failed to send stream open ack: %v",
				err,
			)
		}
	}
}

// sendStreamData sends raw bytes on a stream using a
// binary WebSocket frame to avoid base64 overhead.
//
// Binary frame format:
//
//	[4 bytes: streamID length (big-endian)]
//	[streamID bytes]
//	[payload bytes]
func (a *Agent) sendStreamData(
	c *connection,
	streamID string,
	data []byte,
) {
	frame := encodeBinaryStreamFrame(
		streamID,
		data,
	)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil {
		if err := c.conn.WriteMessage(
			websocket.BinaryMessage,
			frame,
		); err != nil {
			log.Printf(
				"Failed to send stream data: %v",
				err,
			)
		}
	}
}

// encodeBinaryStreamFrame builds a binary frame for
// stream data: [4B streamID len][streamID][payload].
func encodeBinaryStreamFrame(
	streamID string,
	data []byte,
) []byte {
	idLen := len(streamID)
	frame := make([]byte, 4+idLen+len(data))
	binary.BigEndian.PutUint32(
		frame[0:4],
		uint32(idLen),
	)
	copy(frame[4:4+idLen], streamID)
	copy(frame[4+idLen:], data)
	return frame
}

// decodeBinaryStreamFrame parses a binary frame back
// to streamID + data.
func decodeBinaryStreamFrame(
	frame []byte,
) (string, []byte, error) {
	if len(frame) < 4 {
		return "", nil, fmt.Errorf(
			"binary frame too short",
		)
	}
	idLen := binary.BigEndian.Uint32(frame[0:4])
	if idLen > 256 {
		return "", nil, fmt.Errorf(
			"binary frame: streamID length "+
				"too large: %d",
			idLen,
		)
	}
	if int(4+idLen) > len(frame) {
		return "", nil, fmt.Errorf(
			"binary frame: invalid streamID length",
		)
	}
	streamID := string(frame[4 : 4+idLen])
	data := frame[4+idLen:]
	return streamID, data, nil
}

func (a *Agent) sendStreamClose(
	c *connection,
	streamID string,
) {
	payload, err := json.Marshal(StreamClosePayload{
		StreamID: streamID,
	})
	if err != nil {
		log.Printf(
			"Failed to marshal stream close: %v",
			err,
		)
		return
	}
	msg := Message{
		Type:    MsgTypeStreamClose,
		Payload: payload,
	}
	msgBytes, err := json.Marshal(msg)
	if err != nil {
		log.Printf(
			"Failed to marshal stream close msg: %v",
			err,
		)
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil {
		if err := c.conn.WriteMessage(
			websocket.TextMessage,
			msgBytes,
		); err != nil {
			log.Printf(
				"Failed to send stream close: %v",
				err,
			)
		}
	}
}
