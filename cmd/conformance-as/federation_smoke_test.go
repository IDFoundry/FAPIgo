package main

import (
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/federation"
	intfed "github.com/idfoundry/fapigo/internal/federation"
	"github.com/idfoundry/fapigo/internal/jose"
	"github.com/idfoundry/fapigo/keys/ephemeral"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
)

// TestSmokeFederationWellKnownEndpoint is the go/no-go gate before
// pointing a real OIDF Federation conformance run at this binary's
// -federation-enabled wiring: it starts the real production mux
// (newServerMux) with Config.Federation set, fetches
// /.well-known/openid-federation over real TLS, and verifies the
// returned Entity Configuration self-verifies and carries the
// openid_provider metadata this AS actually serves at
// /.well-known/openid-configuration, plus
// client_registration_types_supported (OpenID Federation 1.0 §12.1's
// own MUST for an OP that supports Automatic Registration).
func TestSmokeFederationWellKnownEndpoint(t *testing.T) {
	cert, pool := selfSignedCert(t)
	tcpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	tlsListener := tls.NewListener(tcpListener, &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	})

	issuer, err := fapi.ParseIssuerURL(fmt.Sprintf("https://%s", tcpListener.Addr().String()))
	if err != nil {
		t.Fatalf("parse issuer: %v", err)
	}

	// A minimal static client, just to satisfy newServerMux's own
	// "at least one registered client" requirement — this test only
	// exercises the well-known endpoint, not automatic registration
	// itself (that needs a real Trust Anchor and peer entity, covered
	// live against the OIDF suite instead).
	const testClientID = fapi.ClientID("federation-smoke-test-client")
	registered, err := storage.NewRegisteredClient(storage.RegisteredClientConfig{
		ID:                       testClientID,
		RedirectURIs:             []fapi.RegisteredRedirectURI{"https://rp.smoketest.internal/callback"},
		ClientAssertionAlgorithm: fapi.ES256,
		AllowedScopes:            []string{"openid"},
	})
	if err != nil {
		t.Fatalf("build registered client: %v", err)
	}

	// Trust Anchor content is irrelevant to this test (no automatic
	// registration is exercised) — any well-formed entry satisfies
	// Resolve's own validation.
	dummyAnchorJWKS := json.RawMessage(`{"keys":[]}`)

	resolved := ResolvedConfig{
		ListenAddr:        tcpListener.Addr().String(),
		Issuer:            issuer,
		Profile:           server.ProfileFAPISecurity,
		DefaultSubject:    smokeSubject,
		Algorithms:        server.RecommendedAlgorithms(),
		Limits:            server.RecommendedLimits(),
		AccessTokenFormat: AccessTokenFormatJWT,
		Clients:           []storage.RegisteredClient{registered},
		ClientKeys:        []ephemeral.ClientKeySpec{{ClientID: testClientID, JWKS: json.RawMessage(`{"keys":[]}`)}},
		AdvertisedScopes:  []string{"openid"},
		Federation: &ResolvedFederation{
			EntityID:      issuer.String(),
			TrustAnchors:  []federation.TrustAnchor{{EntityID: "https://ta.smoketest.internal", JWKS: dummyAnchorJWKS}},
			AllowedScopes: []string{"openid"},
		},
	}

	mux, err := newServerMux(resolved, false, false, false, false, false, "", false)
	if err != nil {
		t.Fatalf("build server mux: %v", err)
	}
	httpServer := &http.Server{Handler: mux}
	go httpServer.Serve(tlsListener) //nolint:errcheck
	t.Cleanup(func() { httpServer.Close() })

	httpClient := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}

	// The listener may not have accepted its first connection yet the
	// instant Serve's goroutine is scheduled — retry briefly rather
	// than introduce a fixed sleep.
	var resp *http.Response
	deadline := time.Now().Add(5 * time.Second)
	for {
		resp, err = httpClient.Get(issuer.String() + federation.WellKnownPath)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("GET %s: %v", federation.WellKnownPath, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: status = %d, want 200", federation.WellKnownPath, resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Type"); got != federation.EntityStatementContentType {
		t.Errorf("Content-Type = %q, want %q", got, federation.EntityStatementContentType)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	stmt, err := intfed.Parse(string(body))
	if err != nil {
		t.Fatalf("intfed.Parse: %v", err)
	}
	if stmt.ClaimedIssuer() != issuer.String() || stmt.ClaimedSubject() != issuer.String() {
		t.Errorf("iss/sub = %q/%q, want both equal to the issuer", stmt.ClaimedIssuer(), stmt.ClaimedSubject())
	}

	candidates, err := jose.ParseJWKSet(stmt.ClaimedJWKS())
	if err != nil {
		t.Fatalf("jose.ParseJWKSet(ClaimedJWKS): %v", err)
	}
	if len(candidates) != 1 {
		t.Fatalf("ParseJWKSet returned %d keys, want 1", len(candidates))
	}
	claims, err := stmt.Verify(candidates[0].PublicKey, intfed.VerifyPolicy{
		ExpectedIssuer: issuer.String(), ExpectedSubject: issuer.String(),
		Algorithm: fapi.ES256, Now: time.Now(), MaxLifetime: 2 * time.Hour,
	})
	if err != nil {
		t.Fatalf("Verify(self-issued statement against its own claimed key): %v", err)
	}

	op, ok := claims.Metadata["openid_provider"]
	if !ok {
		t.Fatalf("Metadata missing openid_provider: %v", claims.Metadata)
	}
	var opMeta struct {
		Issuer                           string   `json:"issuer"`
		ClientRegistrationTypesSupported []string `json:"client_registration_types_supported"`
	}
	if err := json.Unmarshal(op, &opMeta); err != nil {
		t.Fatalf("unmarshal openid_provider metadata: %v", err)
	}
	if opMeta.Issuer != issuer.String() {
		t.Errorf("openid_provider.issuer = %q, want %q", opMeta.Issuer, issuer.String())
	}
	if len(opMeta.ClientRegistrationTypesSupported) != 1 || opMeta.ClientRegistrationTypesSupported[0] != "automatic" {
		t.Errorf("openid_provider.client_registration_types_supported = %v, want [\"automatic\"]", opMeta.ClientRegistrationTypesSupported)
	}
}

// minimalFederationResolvedConfig builds the smallest ResolvedConfig
// newServerMux accepts with Federation set — the same shape
// TestSmokeFederationWellKnownEndpoint uses, factored out for the
// newServerMux-level unit tests below, which don't need a real TLS
// listener at all (they only exercise wiring/config-validation errors,
// never make a request against the built mux).
func minimalFederationResolvedConfig(t *testing.T) ResolvedConfig {
	t.Helper()
	const testClientID = fapi.ClientID("federation-unit-test-client")
	registered, err := storage.NewRegisteredClient(storage.RegisteredClientConfig{
		ID:                       testClientID,
		RedirectURIs:             []fapi.RegisteredRedirectURI{"https://rp.unittest.internal/callback"},
		ClientAssertionAlgorithm: fapi.ES256,
		AllowedScopes:            []string{"openid"},
	})
	if err != nil {
		t.Fatalf("build registered client: %v", err)
	}
	issuer, err := fapi.ParseIssuerURL("https://as.unittest.internal")
	if err != nil {
		t.Fatalf("parse issuer: %v", err)
	}
	return ResolvedConfig{
		ListenAddr:        "127.0.0.1:0",
		Issuer:            issuer,
		Profile:           server.ProfileFAPISecurity,
		DefaultSubject:    smokeSubject,
		Algorithms:        server.RecommendedAlgorithms(),
		Limits:            server.RecommendedLimits(),
		AccessTokenFormat: AccessTokenFormatJWT,
		Clients:           []storage.RegisteredClient{registered},
		ClientKeys:        []ephemeral.ClientKeySpec{{ClientID: testClientID, JWKS: json.RawMessage(`{"keys":[]}`)}},
		AdvertisedScopes:  []string{"openid"},
		Federation: &ResolvedFederation{
			EntityID:      issuer.String(),
			TrustAnchors:  []federation.TrustAnchor{{EntityID: "https://ta.unittest.internal", JWKS: json.RawMessage(`{"keys":[]}`)}},
			AllowedScopes: []string{"openid"},
		},
	}
}

// writePEMCertFile PEM-encodes cert's own DER bytes to a temp file and
// returns its path — the on-disk shape newServerMux's federationFetcher
// construction reads via resolved.TLSCertFile (selfSignedCert itself
// stays deliberately in-memory-only; see its own doc comment).
func writePEMCertFile(t *testing.T, cert tls.Certificate) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "server.crt")
	f, err := os.Create(path) // #nosec G304 -- t.TempDir()'s own path, not untrusted input
	if err != nil {
		t.Fatalf("create cert file: %v", err)
	}
	defer f.Close()
	if err := pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}); err != nil {
		t.Fatalf("pem.Encode: %v", err)
	}
	return path
}

// TestNewServerMuxPinsFederationPeerCert confirms newServerMux, given a
// real on-disk TLS cert file, builds successfully (the federationFetcher
// construction path added for cmd/conformance-federation-trust-anchor's
// own peer — reading the file, parsing it into a *x509.CertPool — never
// errors against a well-formed cert).
func TestNewServerMuxPinsFederationPeerCert(t *testing.T) {
	cert, _ := selfSignedCert(t)
	resolved := minimalFederationResolvedConfig(t)
	resolved.TLSCertFile = writePEMCertFile(t, cert)

	if _, err := newServerMux(resolved, false, false, false, false, false, "", false); err != nil {
		t.Fatalf("newServerMux: %v", err)
	}
}

// TestNewServerMuxRejectsMissingCertFile confirms a configured but
// nonexistent TLSCertFile surfaces as an error from newServerMux, rather
// than a federationFetcher silently built without TLS trust.
func TestNewServerMuxRejectsMissingCertFile(t *testing.T) {
	resolved := minimalFederationResolvedConfig(t)
	resolved.TLSCertFile = filepath.Join(t.TempDir(), "does-not-exist.crt")

	if _, err := newServerMux(resolved, false, false, false, false, false, "", false); err == nil {
		t.Fatalf("newServerMux(missing cert file) = nil error, want error")
	}
}

// TestNewServerMuxRejectsInvalidTrustAnchorEntityID confirms a
// syntactically malformed trust anchor entity_id — not caught by
// Config.Resolve's own validation, which only checks non-empty (see
// config.go) — is still rejected here, when newServerMux tries to parse
// it into an AllowedPrivateHosts hostname.
func TestNewServerMuxRejectsInvalidTrustAnchorEntityID(t *testing.T) {
	resolved := minimalFederationResolvedConfig(t)
	resolved.Federation.TrustAnchors[0].EntityID = "https://ta.example.org/%zz"

	if _, err := newServerMux(resolved, false, false, false, false, false, "", false); err == nil {
		t.Fatalf("newServerMux(malformed trust anchor entity id) = nil error, want error")
	}
}
