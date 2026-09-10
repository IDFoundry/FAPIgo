package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
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

	mux, err := newServerMux(resolved, false, false, false, false, false, "")
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
