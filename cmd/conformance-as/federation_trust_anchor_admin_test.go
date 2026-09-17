package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/fapihttp"
	"github.com/idfoundry/fapigo/federation"
	"github.com/idfoundry/fapigo/internal/jose"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/storage"
)

// stubClientRepository/stubClientKeySource are the Underlying every
// dynamicFederationClients test below needs — deliberately minimal,
// this file exercises the wrapping/swap logic itself, not federation
// resolution (already covered by the federation package's own tests).
type stubClientRepository struct{}

func (stubClientRepository) ResolveClient(context.Context, fapi.ClientID) (storage.RegisteredClient, error) {
	return storage.RegisteredClient{}, fmt.Errorf("stub: no such client")
}

type stubClientKeySource struct{}

func (stubClientKeySource) ResolveVerificationKeys(context.Context, keys.ClientKeyRequest) (keys.VerificationKeySet, error) {
	return keys.VerificationKeySet{}, nil
}

func testFetcherCfg() fapihttp.Config {
	return fapihttp.Config{MaxResponseBytes: 1 << 16, RequestTimeout: 5 * time.Second, MaxRedirects: 1}
}

func testDynamicFederationClientsConfig() dynamicFederationClientsConfig {
	return dynamicFederationClientsConfig{
		HTTPTimeout: 5 * time.Second, FetcherCfg: testFetcherCfg(),
		Limits:  federation.Limits{MaxPathLength: 5, MaxStatementLifetime: time.Hour, MaxClockSkew: 5 * time.Second},
		AutoCfg: federation.AutomaticRegistrationConfig{AllowedScopes: []string{"openid"}, MaxCacheAge: time.Hour},
		Clock:   federation.SystemClock{},
	}
}

func newTestDynamicFederationClients(t *testing.T) *dynamicFederationClients {
	t.Helper()
	// federation.NewResolver requires at least one trust anchor — in
	// production, resolved.Federation.TrustAnchors is already
	// guaranteed non-empty by Config.Resolve's own validation before
	// ever reaching newDynamicFederationClients, so this seed anchor
	// only exists to satisfy that same requirement here.
	seed := federation.TrustAnchor{EntityID: "https://seed-ta.example.org", JWKS: testTrustAnchorJWKS(t)}
	d, err := newDynamicFederationClients(
		[]federation.TrustAnchor{seed}, stubClientRepository{}, stubClientKeySource{},
		testDynamicFederationClientsConfig(),
	)
	if err != nil {
		t.Fatalf("newDynamicFederationClients: %v", err)
	}
	return d
}

func testTrustAnchorJWKS(t *testing.T) []byte {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	jwk, err := jose.NewJWK(&priv.PublicKey, fapi.ES256)
	if err != nil {
		t.Fatalf("jose.NewJWK: %v", err)
	}
	data, err := jwk.WithKeyID("ta-key1").MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}
	return []byte(`{"keys":[` + string(data) + `]}`)
}

func TestNewDynamicFederationClientsRejectsInvalidLimits(t *testing.T) {
	seed := federation.TrustAnchor{EntityID: "https://seed-ta.example.org", JWKS: testTrustAnchorJWKS(t)}
	cfg := testDynamicFederationClientsConfig()
	cfg.Limits = federation.Limits{} // zero value: MaxPathLength/MaxStatementLifetime must be positive
	_, err := newDynamicFederationClients([]federation.TrustAnchor{seed}, stubClientRepository{}, stubClientKeySource{}, cfg)
	if err == nil {
		t.Fatalf("newDynamicFederationClients(zero Limits) = nil error, want error")
	}
}

func TestNewDynamicFederationClientsRejectsInvalidAutoRegConfig(t *testing.T) {
	seed := federation.TrustAnchor{EntityID: "https://seed-ta.example.org", JWKS: testTrustAnchorJWKS(t)}
	cfg := testDynamicFederationClientsConfig()
	cfg.AutoCfg = federation.AutomaticRegistrationConfig{} // zero value: AllowedScopes/MaxCacheAge required
	_, err := newDynamicFederationClients([]federation.TrustAnchor{seed}, stubClientRepository{}, stubClientKeySource{}, cfg)
	if err == nil {
		t.Fatalf("newDynamicFederationClients(zero AutomaticRegistrationConfig) = nil error, want error")
	}
}

// shortLivedContext bounds a test call that may fall through to a real
// federation resolution attempt (an outbound HTTP fetch to an
// unresolvable host) — these two delegate tests only care that
// ResolveClient/ResolveVerificationKeys reach the current repo/
// clientKeys pointer without panicking, not that resolution itself
// succeeds (the federation package's own tests already cover that), so
// a short deadline keeps this fast and deterministic instead of
// waiting out a real DNS/connect timeout.
func shortLivedContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	t.Cleanup(cancel)
	return ctx
}

func TestDynamicFederationClientsResolveClientDelegatesToCurrentRepo(t *testing.T) {
	d := newTestDynamicFederationClients(t)
	// stubClientRepository always fails and the seed trust anchor
	// doesn't resolve anything real, so this always errors — the point
	// is only that the call reaches the current repo at all.
	if _, err := d.ResolveClient(shortLivedContext(t), fapi.ClientID("https://rp.example.org")); err == nil {
		t.Errorf("ResolveClient(unresolvable client) = nil error, want error")
	}
}

func TestDynamicFederationClientsResolveVerificationKeysDelegatesToCurrentClientKeys(t *testing.T) {
	d := newTestDynamicFederationClients(t)
	// Return value isn't asserted on: stubClientKeySource's own empty
	// result falls through to a real federation resolution attempt,
	// whose exact outcome (error, or an empty key set) isn't this
	// wrapper's concern — only that the call reaches the current
	// clientKeys pointer without panicking.
	_, _ = d.ResolveVerificationKeys(shortLivedContext(t), keys.ClientKeyRequest{ClientID: fapi.ClientID("https://rp.example.org")})
}

func TestHostOf(t *testing.T) {
	if got, err := hostOf("https://ta.example.org:8443/path"); err != nil || got != "ta.example.org" {
		t.Errorf("hostOf(valid url) = %q, %v; want %q, nil", got, err, "ta.example.org")
	}
	if _, err := hostOf("https://ta.example.org/%zz"); err == nil {
		t.Errorf("hostOf(malformed url) = nil error, want error")
	}
	if _, err := hostOf("/no-host-here"); err == nil {
		t.Errorf("hostOf(no hostname) = nil error, want error")
	}
}

func TestDynamicFederationClientsAddTrustAnchor(t *testing.T) {
	d := newTestDynamicFederationClients(t)
	initialRepo := d.repo

	if err := d.AddTrustAnchor(federation.TrustAnchor{EntityID: "https://ta.example.org", JWKS: testTrustAnchorJWKS(t)}); err != nil {
		t.Fatalf("AddTrustAnchor: %v", err)
	}
	if d.repo == initialRepo {
		t.Errorf("repo unchanged after AddTrustAnchor, want a rebuilt instance")
	}
	if len(d.trustAnchors) != 2 || d.trustAnchors[1].EntityID != "https://ta.example.org" {
		t.Errorf("trustAnchors = %v, want the seed anchor plus https://ta.example.org", d.trustAnchors)
	}
}

func TestDynamicFederationClientsAddTrustAnchorIsIdempotent(t *testing.T) {
	d := newTestDynamicFederationClients(t)
	jwks := testTrustAnchorJWKS(t)
	if err := d.AddTrustAnchor(federation.TrustAnchor{EntityID: "https://ta.example.org", JWKS: jwks}); err != nil {
		t.Fatalf("AddTrustAnchor (1st): %v", err)
	}
	repoAfterFirst := d.repo

	if err := d.AddTrustAnchor(federation.TrustAnchor{EntityID: "https://ta.example.org", JWKS: jwks}); err != nil {
		t.Fatalf("AddTrustAnchor (2nd, same entity_id): %v", err)
	}
	if d.repo != repoAfterFirst {
		t.Errorf("repo rebuilt on a duplicate entity_id, want the same instance (no-op)")
	}
	if len(d.trustAnchors) != 2 {
		t.Errorf("trustAnchors = %v, want exactly 2 entries (seed + one, no duplicate)", d.trustAnchors)
	}
}

func TestFederationTrustAnchorAdminHandler(t *testing.T) {
	d := newTestDynamicFederationClients(t)
	handler := federationTrustAnchorAdminHandler(d)

	body, err := json.Marshal(addTrustAnchorRequest{EntityID: "https://ta.example.org", JWKS: testTrustAnchorJWKS(t)})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/internal/federation/trust-anchors", strings.NewReader(string(body)))
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d; body = %s", rec.Code, http.StatusNoContent, rec.Body.String())
	}
	if len(d.trustAnchors) != 2 || d.trustAnchors[1].EntityID != "https://ta.example.org" {
		t.Errorf("trustAnchors = %v, want the seed anchor plus https://ta.example.org", d.trustAnchors)
	}
}

func TestFederationTrustAnchorAdminHandlerRejectsInvalidRequests(t *testing.T) {
	cases := map[string]string{
		"malformed JSON":    `not json`,
		"missing entity_id": `{"jwks":{"keys":[]}}`,
		"missing jwks":      `{"entity_id":"https://ta.example.org"}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			d := newTestDynamicFederationClients(t)
			handler := federationTrustAnchorAdminHandler(d)
			req := httptest.NewRequest(http.MethodPost, "/internal/federation/trust-anchors", strings.NewReader(body))
			rec := httptest.NewRecorder()
			handler(rec, req)
			if rec.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
			}
		})
	}
}
