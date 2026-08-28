package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/storage"
)

func TestBuildMTLSEndpoints(t *testing.T) {
	issuer, err := fapi.ParseIssuerURL("https://as.example:8443")
	if err != nil {
		t.Fatalf("ParseIssuerURL: %v", err)
	}

	t.Run("without ciba", func(t *testing.T) {
		got, err := buildMTLSEndpoints(issuer, "0.0.0.0:8444", false)
		if err != nil {
			t.Fatalf("buildMTLSEndpoints: %v", err)
		}
		if got.Token.String() != "https://as.example:8444/token" {
			t.Errorf("Token = %q", got.Token.String())
		}
		if got.PushedAuthorizationRequest.String() != "https://as.example:8444/par" {
			t.Errorf("PushedAuthorizationRequest = %q", got.PushedAuthorizationRequest.String())
		}
		if !got.BackchannelAuthentication.IsZero() {
			t.Errorf("BackchannelAuthentication = %q, want zero", got.BackchannelAuthentication.String())
		}
	})

	t.Run("with ciba", func(t *testing.T) {
		got, err := buildMTLSEndpoints(issuer, "0.0.0.0:8444", true)
		if err != nil {
			t.Fatalf("buildMTLSEndpoints: %v", err)
		}
		if got.BackchannelAuthentication.String() != "https://as.example:8444/backchannel-authenticate" {
			t.Errorf("BackchannelAuthentication = %q", got.BackchannelAuthentication.String())
		}
	})

	t.Run("rejects a malformed mtls listen addr", func(t *testing.T) {
		if _, err := buildMTLSEndpoints(issuer, "not-a-host-port", false); err == nil {
			t.Fatalf("buildMTLSEndpoints(malformed addr) = nil error, want error")
		}
	})
}

func TestResolveClientSenderConstrain(t *testing.T) {
	base := ClientConfig{
		ID:                       "client-1",
		RedirectURIs:             []string{"https://rp.example/callback"},
		ClientAssertionAlgorithm: "ES256",
		JWKSURI:                  "https://rp.example/jwks",
	}

	t.Run("empty defaults to dpop", func(t *testing.T) {
		registered, _, err := resolveClient(base)
		if err != nil {
			t.Fatalf("resolveClient: %v", err)
		}
		if registered.SenderConstrain() != storage.SenderConstrainDPoP {
			t.Fatalf("SenderConstrain() = %v, want SenderConstrainDPoP", registered.SenderConstrain())
		}
	})

	t.Run("dpop explicit", func(t *testing.T) {
		c := base
		c.SenderConstrain = "dpop"
		registered, _, err := resolveClient(c)
		if err != nil {
			t.Fatalf("resolveClient: %v", err)
		}
		if registered.SenderConstrain() != storage.SenderConstrainDPoP {
			t.Fatalf("SenderConstrain() = %v, want SenderConstrainDPoP", registered.SenderConstrain())
		}
	})

	t.Run("mtls", func(t *testing.T) {
		c := base
		c.SenderConstrain = "mtls"
		registered, _, err := resolveClient(c)
		if err != nil {
			t.Fatalf("resolveClient: %v", err)
		}
		if registered.SenderConstrain() != storage.SenderConstrainMTLS {
			t.Fatalf("SenderConstrain() = %v, want SenderConstrainMTLS", registered.SenderConstrain())
		}
	})

	t.Run("rejects an unknown value", func(t *testing.T) {
		c := base
		c.SenderConstrain = "bogus"
		if _, _, err := resolveClient(c); err == nil {
			t.Fatalf("resolveClient(sender_constrain=bogus) = nil error, want error")
		}
	})
}

func TestResolveMTLSEndpoints(t *testing.T) {
	issuer, err := fapi.ParseIssuerURL("https://as.example:8443")
	if err != nil {
		t.Fatalf("ParseIssuerURL: %v", err)
	}
	base := ResolvedConfig{Issuer: issuer, MTLSListenAddr: "0.0.0.0:8444"}

	t.Run("success", func(t *testing.T) {
		got, err := resolveMTLSEndpoints(false, base, false)
		if err != nil {
			t.Fatalf("resolveMTLSEndpoints: %v", err)
		}
		if got.Token.String() != "https://as.example:8444/token" {
			t.Errorf("Token = %q", got.Token.String())
		}
	})

	t.Run("rejects insecure-http", func(t *testing.T) {
		if _, err := resolveMTLSEndpoints(true, base, false); err == nil {
			t.Fatalf("resolveMTLSEndpoints(insecureHTTP=true) = nil error, want error")
		}
	})

	t.Run("rejects a missing mtls_listen_addr", func(t *testing.T) {
		resolved := base
		resolved.MTLSListenAddr = ""
		if _, err := resolveMTLSEndpoints(false, resolved, false); err == nil {
			t.Fatalf("resolveMTLSEndpoints(no listen addr) = nil error, want error")
		}
	})
}

// writeTestCertKeyPair writes a throwaway self-signed ECDSA cert/key
// pair to dir as cert.pem/key.pem — the on-disk shape
// tls.LoadX509KeyPair (and so newMTLSServer) needs, unlike
// selfSignedCert's own in-memory tls.Certificate.
func writeTestCertKeyPair(t *testing.T, dir string) (certFile, keyFile string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}

	certFile = filepath.Join(dir, "cert.pem")
	keyFile = filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return certFile, keyFile
}

func TestNewMTLSServer(t *testing.T) {
	certFile, keyFile := writeTestCertKeyPair(t, t.TempDir())
	resolved := ResolvedConfig{MTLSListenAddr: "127.0.0.1:0", TLSCertFile: certFile, TLSKeyFile: keyFile}
	mux := http.NewServeMux()

	srv, err := newMTLSServer(resolved, mux)
	if err != nil {
		t.Fatalf("newMTLSServer: %v", err)
	}
	if srv.Addr != resolved.MTLSListenAddr {
		t.Errorf("Addr = %q, want %q", srv.Addr, resolved.MTLSListenAddr)
	}
	if srv.TLSConfig.ClientAuth != tls.RequestClientCert {
		t.Errorf("ClientAuth = %v, want RequestClientCert", srv.TLSConfig.ClientAuth)
	}
	if len(srv.TLSConfig.Certificates) != 1 {
		t.Errorf("Certificates = %d, want 1", len(srv.TLSConfig.Certificates))
	}
}

func TestNewMTLSServerRejectsMissingCertFile(t *testing.T) {
	resolved := ResolvedConfig{MTLSListenAddr: "127.0.0.1:0", TLSCertFile: "/nonexistent/cert.pem", TLSKeyFile: "/nonexistent/key.pem"}
	if _, err := newMTLSServer(resolved, http.NewServeMux()); err == nil {
		t.Fatalf("newMTLSServer(missing cert) = nil error, want error")
	}
}
