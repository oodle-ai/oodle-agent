package certsecret

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// Secret data keys for the mTLS certificate and key.
const (
	KeyTLSCert = "tls.crt"
	KeyTLSKey  = "tls.key"
	KeyCACert  = "ca.crt"
)

// Store reads and writes agent mTLS certificates
// to/from the agent's Kubernetes Secret. This ensures
// certificates survive pod rescheduling without
// requiring a PersistentVolume.
type Store struct {
	clientset *kubernetes.Clientset
	namespace string
	name      string
}

// NewStore creates a cert secret store. The secret
// must already exist (created during agent
// installation with the registration token).
func NewStore(
	clientset *kubernetes.Clientset,
	namespace string,
	secretName string,
) *Store {
	return &Store{
		clientset: clientset,
		namespace: namespace,
		name:      secretName,
	}
}

// HasCert checks whether the Secret already contains
// a client certificate.
func (s *Store) HasCert(
	ctx context.Context,
) (bool, error) {
	secret, err := s.clientset.CoreV1().
		Secrets(s.namespace).
		Get(ctx, s.name, metav1.GetOptions{})
	if err != nil {
		return false, fmt.Errorf(
			"get secret %s/%s: %w",
			s.namespace,
			s.name,
			err,
		)
	}
	_, hasCert := secret.Data[KeyTLSCert]
	_, hasKey := secret.Data[KeyTLSKey]
	return hasCert && hasKey, nil
}

// LoadCert reads the TLS certificate, key, and
// optionally the CA cert from the Secret. Returns
// nil slices for missing keys.
func (s *Store) LoadCert(
	ctx context.Context,
) (certPEM, keyPEM, caPEM []byte, err error) {
	secret, err := s.clientset.CoreV1().
		Secrets(s.namespace).
		Get(ctx, s.name, metav1.GetOptions{})
	if err != nil {
		return nil, nil, nil, fmt.Errorf(
			"get secret %s/%s: %w",
			s.namespace,
			s.name,
			err,
		)
	}
	return secret.Data[KeyTLSCert],
		secret.Data[KeyTLSKey],
		secret.Data[KeyCACert],
		nil
}

// SaveCert writes the TLS certificate, key, and CA
// cert into the existing Secret. Preserves any other
// keys already in the Secret (e.g. registration-token).
func (s *Store) SaveCert(
	ctx context.Context,
	certPEM []byte,
	keyPEM []byte,
	caPEM []byte,
) error {
	secret, err := s.clientset.CoreV1().
		Secrets(s.namespace).
		Get(ctx, s.name, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf(
			"get secret %s/%s: %w",
			s.namespace,
			s.name,
			err,
		)
	}

	if secret.Data == nil {
		secret.Data = make(map[string][]byte)
	}
	secret.Data[KeyTLSCert] = certPEM
	secret.Data[KeyTLSKey] = keyPEM
	if len(caPEM) > 0 {
		secret.Data[KeyCACert] = caPEM
	}

	// Remove the registration token now that we have
	// a signed certificate. The token is single-use
	// and should not persist in the Secret.
	delete(secret.Data, "registration-token")

	_, err = s.clientset.CoreV1().
		Secrets(s.namespace).
		Update(ctx, secret, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf(
			"update secret %s/%s: %w",
			s.namespace,
			s.name,
			err,
		)
	}

	log.Printf(
		"Saved mTLS certificate to secret %s/%s",
		s.namespace,
		s.name,
	)
	return nil
}

// WriteCertToFiles loads the cert from the Secret and
// writes it to local files for the TLS stack to use.
// This is called on startup before connecting.
func (s *Store) WriteCertToFiles(
	ctx context.Context,
	certPath string,
	keyPath string,
	caPath string,
) error {
	certPEM, keyPEM, caPEM, err := s.LoadCert(ctx)
	if err != nil {
		return err
	}
	if len(certPEM) == 0 || len(keyPEM) == 0 {
		return fmt.Errorf(
			"no certificate in secret %s/%s",
			s.namespace,
			s.name,
		)
	}

	if err := writeFile(
		certPath, certPEM,
	); err != nil {
		return err
	}
	if err := writeFile(
		keyPath, keyPEM,
	); err != nil {
		return err
	}
	if len(caPEM) > 0 && caPath != "" {
		if err := writeFile(
			caPath, caPEM,
		); err != nil {
			return err
		}
	}

	log.Printf(
		"Loaded mTLS certificate from secret "+
			"%s/%s to disk",
		s.namespace,
		s.name,
	)
	return nil
}

// writeFile writes data to a file with restricted
// permissions (0600), creating parent dirs as needed.
func writeFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf(
			"create dir %s: %w", dir, err,
		)
	}
	if err := os.WriteFile(
		path, data, 0600,
	); err != nil {
		return fmt.Errorf(
			"write %s: %w", path, err,
		)
	}
	return nil
}
