package client_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
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
	cfg.Algorithms.IDToken = fapi.PS256 // discoverForAlgorithmTests only ever advertises ES256

	if _, err := client.NewFromDiscovery(discovered, cfg, validDependencies(t)); err == nil {
		t.Fatal("NewFromDiscovery(unadvertised id_token algorithm) = nil error, want error")
	}
	if _, err := client.New(cfg, validDependencies(t)); err != nil {
		t.Fatalf("New(same config): %v, want success — proves NewFromDiscovery's check is the delta, not a New-side rejection", err)
	}
}

// TestNewFromDiscoveryLeavesConfigEndpointsAlone covers the other half
// of NewFromDiscovery's contract: it never reads or overwrites
// cfg.Endpoints with discovered.Endpoints — a Config already pointing
// at a completely different set of endpoints than the ones just
// discovered (as would be the case after a caller already applied its
// own MTLSEndpoints.ApplyForSenderConstrain/ApplyForClientAuth
// override) still constructs successfully, using exactly the Config it
// was given.
func TestNewFromDiscoveryLeavesConfigEndpointsAlone(t *testing.T) {
	discovered := discoverForAlgorithmTests(t)
	cfg := validConfig(t) // endpoints at testIssuer, unrelated to discovered's own httptest server
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

	_, err = c.HandleAuthorizationResponse(ctx, client.AuthorizationCallback{RawQuery: q.Encode()})
	return err
}

// TestNewFromDiscoveryEnablesIssEnforcementWhenAdvertised covers Ask
// 3's whole point: when discovered.AuthorizationResponseIssSupported
// is true, NewFromDiscovery sets RequireAuthorizationResponseIss even
// though the caller never touched it, so a callback missing "iss" is
// now rejected — RFC 9207 §2.4's MUST, applied automatically.
func TestNewFromDiscoveryEnablesIssEnforcementWhenAdvertised(t *testing.T) {
	discovered := discoverWithIssParameterSupport(t, true)
	if err := beginAndCallbackWithoutIss(t, discovered); err == nil {
		t.Fatal("HandleAuthorizationResponse(missing iss, issuer advertises support) = nil error, want error")
	}
}

// TestNewFromDiscoveryLeavesIssEnforcementOffWhenNotAdvertised is the
// contrast case: when discovery never advertised
// authorization_response_iss_parameter_supported, NewFromDiscovery
// leaves RequireAuthorizationResponseIss false, exactly like plain New
// — a missing "iss" is not an error here (RFC 9207's MUST only applies
// once the issuer is known to support the parameter).
func TestNewFromDiscoveryLeavesIssEnforcementOffWhenNotAdvertised(t *testing.T) {
	discovered := discoverWithIssParameterSupport(t, false)
	if err := beginAndCallbackWithoutIss(t, discovered); err != nil {
		t.Fatalf("HandleAuthorizationResponse(missing iss, issuer never advertised support): %v, want success", err)
	}
}

// TestNewFromDiscoveryNeverDisablesExplicitIssEnforcement guards the
// direction NewFromDiscovery must never go: it only ever raises
// RequireAuthorizationResponseIss to true, never lowers a value the
// caller already set, even when discovery itself never advertised
// support.
func TestNewFromDiscoveryNeverDisablesExplicitIssEnforcement(t *testing.T) {
	discovered := discoverWithIssParameterSupport(t, false)
	as := newFakeAS(t, testIssuer, false)
	ts := httptest.NewServer(as.handler())
	t.Cleanup(ts.Close)

	cfg := validConfig(t)
	cfg.Algorithms.IDToken = fapi.ES256
	cfg.RequireAuthorizationResponseIss = true
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
	if _, err := c.HandleAuthorizationResponse(ctx, client.AuthorizationCallback{RawQuery: q.Encode()}); err == nil {
		t.Fatal("HandleAuthorizationResponse(missing iss, caller explicitly required it) = nil error, want error")
	}
}
