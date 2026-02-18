package cert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

// GenerateKeyPair generates an ECDSA P-256 key pair.
func GenerateKeyPair() (
	*ecdsa.PrivateKey, error,
) {
	return ecdsa.GenerateKey(
		elliptic.P256(),
		rand.Reader,
	)
}

// CreateCSR creates a PKCS#10 certificate signing
// request with the given agent identity.
func CreateCSR(
	key *ecdsa.PrivateKey,
	agentID string,
	instance string,
) ([]byte, error) {
	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   agentID,
			Organization: []string{"oodle-agent"},
		},
		DNSNames: []string{
			agentID,
			instance,
		},
	}
	csrDER, err := x509.CreateCertificateRequest(
		rand.Reader,
		template,
		key,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"create CSR: %w",
			err,
		)
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	}), nil
}

// StoreCert writes certificate and key PEM files with
// restricted permissions (0600).
func StoreCert(
	certPEM []byte,
	keyPEM []byte,
	certPath string,
	keyPath string,
) error {
	certDir := filepath.Dir(certPath)
	if err := os.MkdirAll(certDir, 0700); err != nil {
		return fmt.Errorf(
			"create cert dir: %w",
			err,
		)
	}
	keyDir := filepath.Dir(keyPath)
	if err := os.MkdirAll(keyDir, 0700); err != nil {
		return fmt.Errorf(
			"create key dir: %w",
			err,
		)
	}

	if err := os.WriteFile(
		certPath,
		certPEM,
		0600,
	); err != nil {
		return fmt.Errorf(
			"write cert: %w",
			err,
		)
	}
	if err := os.WriteFile(
		keyPath,
		keyPEM,
		0600,
	); err != nil {
		return fmt.Errorf(
			"write key: %w",
			err,
		)
	}
	return nil
}

// LoadCert loads a certificate from PEM file and
// returns its parsed x509 representation.
func LoadCert(
	certPath string,
) (*x509.Certificate, error) {
	data, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf(
			"read cert %s: %w",
			certPath,
			err,
		)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf(
			"no PEM block in %s",
			certPath,
		)
	}
	return x509.ParseCertificate(block.Bytes)
}

// DaysUntilExpiry returns the number of days until
// the certificate expires. Returns 0 if the cert is
// already expired.
func DaysUntilExpiry(
	cert *x509.Certificate,
) int {
	remaining := time.Until(cert.NotAfter)
	if remaining <= 0 {
		return 0
	}
	return int(remaining.Hours() / 24)
}

// MarshalPrivateKey encodes an ECDSA private key
// to PEM format.
func MarshalPrivateKey(
	key *ecdsa.PrivateKey,
) ([]byte, error) {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf(
			"marshal private key: %w",
			err,
		)
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: der,
	}), nil
}

// CertExists checks if both cert and key files exist
// at the given paths.
func CertExists(
	certPath string,
	keyPath string,
) bool {
	if _, err := os.Stat(certPath); err != nil {
		return false
	}
	if _, err := os.Stat(keyPath); err != nil {
		return false
	}
	return true
}

// SelfSignForTesting creates a self-signed cert for
// testing purposes only. Not used in production.
func SelfSignForTesting(
	key *ecdsa.PrivateKey,
	agentID string,
	validity time.Duration,
) ([]byte, error) {
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   agentID,
			Organization: []string{"oodle-agent"},
		},
		DNSNames:  []string{agentID},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(validity),
		KeyUsage: x509.KeyUsageDigitalSignature |
			x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
		},
	}
	certDER, err := x509.CreateCertificate(
		rand.Reader,
		template,
		template,
		&key.PublicKey,
		key,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"create self-signed cert: %w",
			err,
		)
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	}), nil
}
