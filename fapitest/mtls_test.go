package fapitest_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/url"
	"testing"
	"time"

	"github.com/idfoundry/fapigo/fapitest"
	"github.com/idfoundry/fapigo/resource"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
)

// TestAuthorizationCodeFlowMTLSBinding is TestAuthorizationCodeFlowBaseline's
// storage.SenderConstrainMTLS counterpart — the first genuine
// client-to-AS integration coverage mTLS has ever had in this repo.
// Every other mTLS test has one side faked: server/mtls_test.go fakes
// the client, client/mtls_test.go fakes the AS. This drives a real
// client.Client against a real server.Server over an actual TLS
// connection, with an actual client certificate presented (see
// Harness.MTLSCertificate/authserver.go's own mtls-conditional
// httptest.Server) — proving the whole chain (client presents a
// certificate, server binds cnf.x5t#S256 to it, resource verifies
// against the same certificate) is mutually consistent over the real
// wire, not just that each role's own unit tests pass in isolation.
func TestAuthorizationCodeFlowMTLSBinding(t *testing.T) {
	h := fapitest.New(t, fapitest.Config{
		Profile:         server.ProfileFAPISecurity,
		SenderConstrain: storage.SenderConstrainMTLS,
	})
	ctx := context.Background()

	tokens, err := h.RunAuthorizationCodeFlow(ctx, []string{"openid", "accounts", "offline_access"})
	if err != nil {
		t.Fatalf("RunAuthorizationCodeFlow: %v", err)
	}
	if tokens.AccessToken.Reveal() == "" {
		t.Fatalf("AccessToken is empty")
	}
	if tokens.TokenType != "Bearer" {
		t.Errorf("TokenType = %q, want Bearer (RFC 8705 §3.4)", tokens.TokenType)
	}
	if !tokens.HasIDToken || tokens.Subject != fapitest.Subject {
		t.Errorf("HasIDToken=%v Subject=%q, want true/%q", tokens.HasIDToken, tokens.Subject, fapitest.Subject)
	}
	if !tokens.HasRefreshToken {
		t.Errorf("HasRefreshToken = false, want true (offline_access was granted)")
	}
	if h.MTLSCertificate == nil {
		t.Fatalf("MTLSCertificate is nil, want the certificate presented during the flow above")
	}

	target, err := url.Parse("https://rs.fapitest.internal/accounts")
	if err != nil {
		t.Fatalf("parse target url: %v", err)
	}

	authz, err := h.Resource.Verify(ctx, resource.VerifyRequest{
		Method: "GET", URL: target,
		Authorization:   "Bearer " + tokens.AccessToken.Reveal(),
		PeerCertificate: h.MTLSCertificate,
	})
	if err != nil {
		t.Fatalf("resource.Verify(matching certificate): %v", err)
	}
	if authz.Subject != fapitest.Subject {
		t.Errorf("Subject = %q, want %q", authz.Subject, fapitest.Subject)
	}
	if authz.ClientID != fapitest.ClientID.String() {
		t.Errorf("ClientID = %q, want %q", authz.ClientID, fapitest.ClientID.String())
	}

	// The negative half of the same proof: some *other* certificate
	// must not satisfy the binding this access token actually carries
	// — confirming resource.Verify is genuinely checking the presented
	// certificate's thumbprint against cnf.x5t#S256, not just accepting
	// any certificate (or none) once the bearer token itself is valid.
	if _, err := h.Resource.Verify(ctx, resource.VerifyRequest{
		Method: "GET", URL: target,
		Authorization:   "Bearer " + tokens.AccessToken.Reveal(),
		PeerCertificate: otherTestCertificate(t),
	}); err == nil {
		t.Fatalf("resource.Verify(wrong certificate) = nil error, want error")
	}
}

// otherTestCertificate generates a throwaway self-signed certificate,
// standing in for some other client's own — this package's black-box
// test package can't reach fapitest's own unexported selfSignedClientCert,
// so this mirrors it directly, the same way every other *_test.go's own
// selfSignedTestClientCert helper in this repo does for its own package.
func otherTestCertificate(t *testing.T) *x509.Certificate {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		t.Fatalf("generate serial: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "some-other-client"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return cert
}
