package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/oodle-ai/oodle-agent/pkg/agent"
	"github.com/oodle-ai/oodle-agent/pkg/certsecret"
	"github.com/oodle-ai/oodle-agent/pkg/k8s"
	"github.com/oodle-ai/oodle-agent/pkg/policy"
	"github.com/oodle-ai/oodle-agent/pkg/proxy"
	"github.com/oodle-ai/oodle-agent/pkg/version"
)

// Default local paths for cert files loaded from
// the K8s Secret. These are written to an emptyDir
// or tmpfs volume.
const (
	defaultCertDir  = "/tmp/oodle-certs"
	defaultCertFile = defaultCertDir + "/tls.crt"
	defaultKeyFile  = defaultCertDir + "/tls.key"
	defaultCAFile   = defaultCertDir + "/ca.crt"
)

func main() {
	// Core flags.
	instance := flag.String(
		"instance", envOr("OODLE_INSTANCE", ""),
		"Oodle instance ID",
	)
	agentID := flag.String(
		"agent-id", envOr("OODLE_AGENT_ID", ""),
		"Unique agent ID",
	)
	agentName := flag.String(
		"agent-name", envOr("OODLE_AGENT_NAME", ""),
		"Human-readable agent name",
	)
	gatewayURLs := flag.String(
		"gateway-urls",
		envOr("OODLE_GATEWAY_URLS", ""),
		"Comma-separated gateway WebSocket URLs",
	)

	// K8s / Secret flags.
	kubeconfig := flag.String(
		"kubeconfig", envOr("KUBECONFIG", ""),
		"Path to kubeconfig (optional)",
	)
	secretName := flag.String(
		"secret-name",
		envOr("OODLE_SECRET_NAME", ""),
		"K8s Secret name for cert storage",
	)
	secretNamespace := flag.String(
		"secret-namespace",
		envOr(
			"OODLE_SECRET_NAMESPACE",
			"oodle-monitoring",
		),
		"K8s namespace for the agent Secret",
	)

	// Registration token for first-time mTLS bootstrap.
	registrationToken := flag.String(
		"registration-token",
		envOr("OODLE_REGISTRATION_TOKEN", ""),
		"One-time registration token for "+
			"initial mTLS certificate bootstrap",
	)

	// TLS / mTLS flags (manual override; usually
	// certs are loaded from the K8s Secret).
	tlsCertFile := flag.String(
		"tls-cert-file",
		envOr("OODLE_TLS_CERT_FILE", ""),
		"Path to client TLS certificate (mTLS)",
	)
	tlsKeyFile := flag.String(
		"tls-key-file",
		envOr("OODLE_TLS_KEY_FILE", ""),
		"Path to client TLS private key (mTLS)",
	)
	caCertFile := flag.String(
		"ca-cert-file",
		envOr("OODLE_CA_CERT_FILE", ""),
		"Path to CA certificate for gateway",
	)
	pinnedCACertFile := flag.String(
		"pinned-ca-cert-file",
		envOr("OODLE_PINNED_CA_CERT_FILE", ""),
		"Path to pinned Amazon CA certificate",
	)

	// Policy flag.
	policyFile := flag.String(
		"policy-file",
		envOr("OODLE_POLICY_FILE", ""),
		"Path to YAML policy file",
	)

	// Tuning flags.
	reconnectInterval := flag.Duration(
		"reconnect-interval",
		5*time.Second,
		"Reconnect interval on disconnect",
	)

	// Meta flags.
	showVersion := flag.Bool(
		"version", false,
		"Print version and exit",
	)

	flag.Parse()

	if *showVersion {
		s := fmt.Sprintf("oodle-agent %s", version.Version)
		if version.GitCommit != "" &&
			version.GitCommit != "unknown" {
			s += fmt.Sprintf(" (commit=%s)", version.GitCommit)
		}
		if version.BuildTime != "" &&
			version.BuildTime != "unknown" {
			s += fmt.Sprintf(" (built=%s)", version.BuildTime)
		}
		fmt.Println(s)
		os.Exit(0)
	}

	// Validate required flags.
	if *instance == "" {
		log.Fatal(
			"--instance or OODLE_INSTANCE is required",
		)
	}
	if *agentID == "" {
		log.Fatal(
			"--agent-id or OODLE_AGENT_ID is required",
		)
	}
	if *gatewayURLs == "" {
		log.Fatal(
			"--gateway-urls or OODLE_GATEWAY_URLS " +
				"is required",
		)
	}

	urls := strings.Split(*gatewayURLs, ",")
	for i := range urls {
		urls[i] = strings.TrimSpace(urls[i])
	}

	// Load policy.
	var pol *policy.Policy
	if *policyFile != "" {
		var err error
		pol, err = policy.LoadFromFile(*policyFile)
		if err != nil {
			log.Fatalf("load policy: %v", err)
		}
		log.Printf(
			"Loaded policy from %s "+
				"(restrictions=%v, %d endpoints)",
			*policyFile,
			pol.EnableAccessRestrictions,
			len(pol.AllowedEndpoints),
		)
	} else {
		pol = policy.Default()
	}

	// Init K8s client (best-effort; not fatal).
	k8sClient, err := k8s.NewClient(*kubeconfig)
	if err != nil {
		log.Printf(
			"WARNING: K8s client init failed: %v "+
				"(K8s metadata won't be available)",
			err,
		)
	}

	// Load mTLS certs from K8s Secret if configured.
	// This ensures certs survive pod rescheduling.
	var certStore *certsecret.Store
	if *secretName != "" && k8sClient != nil {
		certStore = certsecret.NewStore(
			k8sClient.Clientset(),
			*secretNamespace,
			*secretName,
		)
		ctx := context.Background()
		hasCert, chkErr := certStore.HasCert(ctx)
		if chkErr != nil {
			log.Printf(
				"WARNING: check cert secret: %v",
				chkErr,
			)
		} else if hasCert {
			// Cert exists in Secret -- write to
			// local files for TLS stack.
			if wErr := certStore.WriteCertToFiles(
				ctx,
				defaultCertFile,
				defaultKeyFile,
				defaultCAFile,
			); wErr != nil {
				log.Fatalf(
					"load cert from secret: %v",
					wErr,
				)
			}
			// Use these paths unless explicitly
			// overridden by flags.
			if *tlsCertFile == "" {
				*tlsCertFile = defaultCertFile
			}
			if *tlsKeyFile == "" {
				*tlsKeyFile = defaultKeyFile
			}
			if *caCertFile == "" {
				*caCertFile = defaultCAFile
			}
			log.Printf(
				"Loaded mTLS cert from secret "+
					"%s/%s",
				*secretNamespace,
				*secretName,
			)
		} else {
			log.Printf(
				"No certificate in secret %s/%s "+
					"-- will register with token",
				*secretNamespace,
				*secretName,
			)
		}
	}

	// Build proxy handler.
	handler := proxy.NewHandler(
		k8sClient,
		pol,
		proxy.Timeouts{},
		proxy.BufferSizes{},
	)

	// Build agent config.
	cfg := agent.Config{
		Instance:          *instance,
		AgentID:           *agentID,
		AgentName:         *agentName,
		Version:           version.Version,
		TLSCertFile:       *tlsCertFile,
		TLSKeyFile:        *tlsKeyFile,
		CACertFile:        *caCertFile,
		PinnedCACertFile:  *pinnedCACertFile,
		GatewayURLs:       urls,
		ReconnectInterval: *reconnectInterval,
		RequestHandler:    handler,
		Policy:            pol,
		RegistrationToken: *registrationToken,
	}
	if certStore != nil {
		cfg.CertStore = certStore
	}

	a := agent.New(cfg)

	if version.GitCommit != "" &&
		version.GitCommit != "unknown" {
		log.Printf(
			"Starting oodle-agent %s (commit=%s)",
			version.Version,
			version.GitCommit,
		)
	} else {
		log.Printf(
			"Starting oodle-agent %s",
			version.Version,
		)
	}

	if err := a.Start(); err != nil {
		log.Fatalf("agent start: %v", err)
	}

	// Wait for termination signal.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(
		sigCh, syscall.SIGINT, syscall.SIGTERM,
	)
	sig := <-sigCh
	log.Printf("Received %s, shutting down...", sig)

	a.Stop()
	log.Println("Agent stopped")
}

// envOr returns the env var value or the fallback.
func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
