package client_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/client"
)

// discoverWithIssParameterSupport spins up a minimal discovery document
// (just enough for a successful Discover — the browser-flow endpoints
// and ES256 for id_token) advertising
// authorization_response_iss_parameter_supported as issSupported, and
// returns the resulting DiscoveredMetadata.
func discoverWithIssParameterSupport(t *testing.T, issSupported bool) client.DiscoveredMetadata {
	t.Helper()
	var ts *httptest.Server
	ts = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		doc := discoveryDoc{
			Issuer:                             ts.URL,
			AuthorizationEndpoint:              ts.URL + "/authorize",
			TokenEndpoint:                      ts.URL + "/token",
			PushedAuthorizationRequestEndpoint: ts.URL + "/par",
			JWKSURI:                            ts.URL + "/jwks",
			IDTokenSigningAlgValuesSupported:   []string{"ES256"},
			AuthorizationResponseIssParameterSupported: issSupported,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(doc) //nolint:errcheck
	}))
	t.Cleanup(ts.Close)

	tsIssuer, err := fapi.ParseIssuerURL(ts.URL, fapi.AllowLoopbackHTTP())
	if err != nil {
		t.Fatalf("ParseIssuerURL(ts.URL): %v", err)
	}
	md, err := client.Discover(context.Background(), newDiscoveryFetcher(t, ts), tsIssuer, fapi.AllowLoopbackHTTP())
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	return md
}

// TestNewFromDiscoverySucceedsWhenAlgorithmsMatch covers the base case:
// a Config whose declared algorithms are all among what discovered
// advertises constructs successfully, exactly like plain New.
func TestNewFromDiscoverySucceedsWhenAlgorithmsMatch(t *testing.T) {
	discovered := discoverForAlgorithmTests(t)
	cfg := validConfig(t)
	cfg.Issuer = discovered.Issuer()
	cfg.Algorithms.IDToken = fapi.ES256

	if _, err := client.NewFromDiscovery(discovered, cfg, validDependencies(t)); err != nil {
		t.Fatalf("NewFromDiscovery(matching algorithms): %v", err)
	}
}

// TestNewFromDiscoveryRejectsUnsupportedAlgorithm covers the entire
// point of this constructor: a declared algorithm the issuer never
// advertised is caught here, even though plain New has no way to know
// and would accept the identical Config.
func TestNewFromDiscoveryRejectsUnsupportedAlgorithm(t *testing.T) {
	discovered := discoverForAlgorithmTests(t)
	cfg := validConfig(t)
	cfg.Issuer = discovered.Issuer()
	cfg.Algorithms.IDToken = fapi.PS256 // discoverForAlgorithmTests only ever advertises ES256

	if _, err := client.NewFromDiscovery(discovered, cfg, validDependencies(t)); err == nil {
		t.Fatal("NewFromDiscovery(unadvertised id_token algorithm) = nil error, want error")
	}
	if _, err := client.New(cfg, validDependencies(t)); err != nil {
		t.Fatalf("New(same config): %v, want success — proves NewFromDiscovery's check is the delta, not a New-side rejection", err)
	}
}

// TestNewFromDiscoveryLeavesConfigEndpointsAlone covers explicitly set
// endpoints: NewFromDiscovery fills cfg.Endpoints only when it's
// entirely zero, so a Config already pointing at a different set of
// endpoints than the ones just discovered (as after a caller applied
// its own MTLSEndpoints.ApplyForSenderConstrain/ApplyForClientAuth
// override) still constructs successfully, using exactly the Config it
// was given.
func TestNewFromDiscoveryLeavesConfigEndpointsAlone(t *testing.T) {
	discovered := discoverForAlgorithmTests(t)
	cfg := validConfig(t) // endpoints at testIssuer, unrelated to discovered's own httptest server
	cfg.Issuer = discovered.Issuer()
	cfg.Algorithms.IDToken = fapi.ES256

	if _, err := client.NewFromDiscovery(discovered, cfg, validDependencies(t)); err != nil {
		t.Fatalf("NewFromDiscovery(config endpoints independent of discovered): %v", err)
	}
}

// beginAndCallbackWithoutIss drives BeginAuthorization then
// HandleAuthorizationResponse with a callback carrying every required
// parameter except "iss", against a client built via NewFromDiscovery
// with discovered's own iss-parameter-support signal.
func beginAndCallbackWithoutIss(t *testing.T, discovered client.DiscoveredMetadata) error {
	t.Helper()
	as := newFakeAS(t, testIssuer, false)
	ts := httptest.NewServer(as.handler())
	t.Cleanup(ts.Close)

	cfg := validConfig(t)
	cfg.Issuer = discovered.Issuer()
	cfg.Algorithms.IDToken = fapi.ES256
	parURL, err := fapi.ParseEndpointURL(ts.URL+"/par", fapi.AllowLoopbackHTTP())
	if err != nil {
		t.Fatalf("ParseEndpointURL(par): %v", err)
	}
	cfg.Endpoints.PushedAuthorizationRequest = parURL

	deps := validDependencies(t)
	deps.HTTP = ts.Client()

	c, err := client.NewFromDiscovery(discovered, cfg, deps)
	if err != nil {
		t.Fatalf("NewFromDiscovery: %v", err)
	}

	ctx := context.Background()
	session, err := c.BeginAuthorization(ctx, client.BeginAuthorizationRequest{Scope: []string{"openid"}})
	if err != nil {
		t.Fatalf("BeginAuthorization: %v", err)
	}

	q := url.Values{}
	q.Set("state", session.Handle().String())
	q.Set("code", "auth-code-no-iss")
	// deliberately no "iss"

	_, err = c.HandleAuthorizationResponse(ctx, client.AuthorizationCallback{RawQuery: q.Encode(), Session: session.Handle()})
	return err
}

// TestNewFromDiscoveryEnablesIssEnforcementWhenAdvertised covers Ask
// 3's whole point: when discovered.AuthorizationResponseIssSupported
// is true, NewFromDiscovery sets AuthorizationResponseIssPolicy to
// RequireAuthorizationResponseIss even though the caller never touched
// it, so a callback missing "iss" is now rejected — RFC 9207 §2.4's
// MUST, applied automatically.
func TestNewFromDiscoveryEnablesIssEnforcementWhenAdvertised(t *testing.T) {
	discovered := discoverWithIssParameterSupport(t, true)
	if err := beginAndCallbackWithoutIss(t, discovered); err == nil {
		t.Fatal("HandleAuthorizationResponse(missing iss, issuer advertises support) = nil error, want error")
	}
}

// TestNewFromDiscoveryLeavesIssEnforcementOffWhenNotAdvertised is the
// contrast case: when discovery never advertised
// authorization_response_iss_parameter_supported, NewFromDiscovery
// leaves AuthorizationResponseIssPolicy at whatever the caller already
// set (TolerateAbsentAuthorizationResponseIss here, exactly like plain
// New) — a missing "iss" is not an error here (RFC 9207's MUST only
// applies once the issuer is known to support the parameter).
func TestNewFromDiscoveryLeavesIssEnforcementOffWhenNotAdvertised(t *testing.T) {
	discovered := discoverWithIssParameterSupport(t, false)
	if err := beginAndCallbackWithoutIss(t, discovered); err != nil {
		t.Fatalf("HandleAuthorizationResponse(missing iss, issuer never advertised support): %v, want success", err)
	}
}

// TestNewFromDiscoveryNeverDisablesExplicitIssEnforcement guards the
// direction NewFromDiscovery must never go: it only ever raises
// AuthorizationResponseIssPolicy to RequireAuthorizationResponseIss,
// never lowers a value the caller already set, even when discovery
// itself never advertised support.
func TestNewFromDiscoveryNeverDisablesExplicitIssEnforcement(t *testing.T) {
	discovered := discoverWithIssParameterSupport(t, false)
	as := newFakeAS(t, testIssuer, false)
	ts := httptest.NewServer(as.handler())
	t.Cleanup(ts.Close)

	cfg := validConfig(t)
	cfg.Issuer = discovered.Issuer()
	cfg.Algorithms.IDToken = fapi.ES256
	cfg.AuthorizationResponseIssPolicy = client.RequireAuthorizationResponseIss
	parURL, err := fapi.ParseEndpointURL(ts.URL+"/par", fapi.AllowLoopbackHTTP())
	if err != nil {
		t.Fatalf("ParseEndpointURL(par): %v", err)
	}
	cfg.Endpoints.PushedAuthorizationRequest = parURL

	deps := validDependencies(t)
	deps.HTTP = ts.Client()

	c, err := client.NewFromDiscovery(discovered, cfg, deps)
	if err != nil {
		t.Fatalf("NewFromDiscovery: %v", err)
	}

	ctx := context.Background()
	session, err := c.BeginAuthorization(ctx, client.BeginAuthorizationRequest{Scope: []string{"openid"}})
	if err != nil {
		t.Fatalf("BeginAuthorization: %v", err)
	}
	q := url.Values{}
	q.Set("state", session.Handle().String())
	q.Set("code", "auth-code-no-iss")
	if _, err := c.HandleAuthorizationResponse(ctx, client.AuthorizationCallback{RawQuery: q.Encode(), Session: session.Handle()}); err == nil {
		t.Fatal("HandleAuthorizationResponse(missing iss, caller explicitly required it) = nil error, want error")
	}
}

// TestNewFromDiscoveryFillsIssuerAndEndpoints covers a Config that
// leaves Issuer and Endpoints to discovery: plain New would reject it,
// NewFromDiscovery completes it.
func TestNewFromDiscoveryFillsIssuerAndEndpoints(t *testing.T) {
	discovered := discoverForAlgorithmTests(t)
	if discovered.Issuer().IsZero() {
		t.Fatal("Discover returned no Issuer()")
	}
	cfg := validConfig(t)
	cfg.Issuer = fapi.URL{}
	cfg.Endpoints = client.Endpoints{}
	cfg.Algorithms.IDToken = fapi.ES256

	if _, err := client.New(cfg, validDependencies(t)); err == nil {
		t.Fatal("New(no issuer, no endpoints) = nil error — the test needs a Config New rejects")
	}
	if _, err := client.NewFromDiscovery(discovered, cfg, validDependencies(t)); err != nil {
		t.Fatalf("NewFromDiscovery(issuer and endpoints from discovery): %v", err)
	}
}

// TestNewFromDiscoveryRejectsMismatchedIssuer covers pairing one
// issuer's metadata with another issuer's identifier.
func TestNewFromDiscoveryRejectsMismatchedIssuer(t *testing.T) {
	discovered := discoverForAlgorithmTests(t)
	cfg := validConfig(t) // testIssuer, not discovered's httptest server
	cfg.Algorithms.IDToken = fapi.ES256

	_, err := client.NewFromDiscovery(discovered, cfg, validDependencies(t))
	if err == nil {
		t.Fatal("NewFromDiscovery(another issuer's identifier) = nil error, want error")
	}
	if !strings.Contains(err.Error(), "doesn't match the discovered issuer") {
		t.Fatalf("error = %v, want the issuer mismatch", err)
	}
}

// TestNewFromDiscoveryHandBuiltMetadataNeedsIssuer covers a
// DiscoveredMetadata assembled by hand: there's no verified issuer to
// fill in, so Config.Issuer stays required.
func TestNewFromDiscoveryHandBuiltMetadataNeedsIssuer(t *testing.T) {
	cfg := validConfig(t)
	discovered := client.DiscoveredMetadata{Endpoints: cfg.Endpoints, IDTokenAlgorithms: []fapi.SignatureAlgorithm{fapi.ES256}}
	cfg.Algorithms.IDToken = fapi.ES256
	if _, err := client.NewFromDiscovery(discovered, cfg, validDependencies(t)); err != nil {
		t.Fatalf("NewFromDiscovery(hand-built, issuer set): %v", err)
	}
	cfg.Issuer = fapi.URL{}
	if _, err := client.NewFromDiscovery(discovered, cfg, validDependencies(t)); err == nil {
		t.Fatal("NewFromDiscovery(hand-built, no issuer) = nil error, want error")
	}
}

// TestDiscoverHasNoResolvedEntity covers plain OIDC/RFC 8414 discovery:
// there's no Trust Chain to report.
func TestDiscoverHasNoResolvedEntity(t *testing.T) {
	if _, ok := discoverForAlgorithmTests(t).ResolvedEntity(); ok {
		t.Error("ResolvedEntity() ok = true for Discover metadata, want false")
	}
}

// TestNewFromDiscoveryWithoutRedirectURI covers a client with no
// redirect URI — one using only CIBA or client credentials: discovery
// fills its endpoints without the redirect-based flow's, so it needs no
// RedirectURI and can't begin that flow.
func TestNewFromDiscoveryWithoutRedirectURI(t *testing.T) {
	discovered := discoverForAlgorithmTests(t)
	if discovered.Endpoints.Authorization.IsZero() {
		t.Fatal("test setup: discovered metadata has no authorization endpoint")
	}
	cfg := validConfig(t)
	cfg.Issuer, cfg.Endpoints, cfg.RedirectURI = discovered.Issuer(), client.Endpoints{}, ""
	cfg.Algorithms.IDToken = fapi.ES256
	c, err := client.NewFromDiscovery(discovered, cfg, validDependencies(t))
	if err != nil {
		t.Fatalf("NewFromDiscovery(no redirect URI): %v", err)
	}
	if _, err := c.BeginAuthorization(context.Background(), client.BeginAuthorizationRequest{Scope: []string{"openid"}}); err == nil {
		t.Error("BeginAuthorization without a redirect URI = nil error, want error")
	}

	cfg.RedirectURI = testRedirect
	if _, err := client.NewFromDiscovery(discovered, cfg, validDependencies(t)); err != nil {
		t.Errorf("NewFromDiscovery(with a redirect URI): %v", err)
	}
}
