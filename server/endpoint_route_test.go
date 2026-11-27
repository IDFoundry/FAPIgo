package server_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
)

const testTokenAlias = "https://mtls.as.example/token"

// routeSetterNames are the setters a route error's cause must name.
var routeSetterNames = []string{"FormRequest.EndpointRoute", "TokenEndpointRequest.SetEndpointRoute"}

// newRouteHarness is a harness whose Config.MTLSEndpoints is set by
// aliases (nil for none).
func newRouteHarness(t *testing.T, aliases func(*server.MTLSEndpoints, func(string) fapi.URL)) harness {
	t.Helper()
	return newAttestationHarness(t, time.Now(), generateKey(t), server.RegisteredAttesterKeys{}, func(cfg *server.Config, _ *storage.RegisteredClientConfig) {
		if aliases != nil {
			aliases(&cfg.MTLSEndpoints, func(raw string) fapi.URL {
				u, err := fapi.ParseEndpointURL(raw)
				if err != nil {
					t.Fatal(err)
				}
				return u
			})
		}
	})
}

func withTokenAlias(raw string) func(*server.MTLSEndpoints, func(string) fapi.URL) {
	return func(e *server.MTLSEndpoints, parse func(string) fapi.URL) { e.Token = parse(raw) }
}

// verifyRouted is VerifyTokenRequestDPoP for a fresh proof naming htu,
// received at route.
func verifyRouted(t *testing.T, h harness, htu string, route server.EndpointRoute) error {
	t.Helper()
	req := clientlessTokenRequest(t, dpopProofAt(t, generateKey(t), htu, "", h.now))
	req.SetEndpointRoute(route)
	_, err := h.server.VerifyTokenRequestDPoP(context.Background(), req)
	return err
}

// wantRouteError checks err is a *server.Error with code and status,
// whose public description is description and whose message contains
// each of causes.
func wantRouteError(t *testing.T, name string, err error, code server.ErrorCode, status int, description string, causes ...string) {
	t.Helper()
	var serr *server.Error
	if !errors.As(err, &serr) {
		t.Fatalf("%s: err = %v, want a *server.Error", name, err)
	}
	if serr.Code() != code || serr.HTTPStatus() != status || serr.PublicDescription() != description {
		t.Errorf("%s: err = %d %s %q, want %d %s %q", name, serr.HTTPStatus(), serr.Code(), serr.PublicDescription(), status, code, description)
	}
	for _, c := range causes {
		if !strings.Contains(err.Error(), c) {
			t.Errorf("%s: err = %v, want it to name %q", name, err, c)
		}
	}
}

// TestVerifyTokenRequestDPoPAtTheMTLSAlias: a proof is checked against
// the one URL its route names. A request received at the alias, so
// marked, verifies a proof naming the alias and refuses one naming the
// primary URL or another server; one marked primary, or not marked at
// all, refuses a proof naming the alias.
func TestVerifyTokenRequestDPoPAtTheMTLSAlias(t *testing.T) {
	h := newRouteHarness(t, withTokenAlias(testTokenAlias))
	for _, c := range []struct {
		htu   string
		route server.EndpointRoute
		ok    bool
	}{
		{testTokenAlias, server.MTLSEndpointAlias, true},
		{testTokenEndpoint, server.MTLSEndpointAlias, false},
		{"https://other.example/token", server.MTLSEndpointAlias, false},
		{testTokenEndpoint, server.PrimaryEndpoint, true},
		{testTokenAlias, server.PrimaryEndpoint, false},
		{testTokenEndpoint, 0, true},
		{testTokenAlias, 0, false},
		{"https://other.example/token", 0, false},
	} {
		err := verifyRouted(t, h, c.htu, c.route)
		if c.ok {
			if err != nil {
				t.Errorf("proof for %s at route %v: %v", c.htu, c.route, err)
			}
			continue
		}
		wantRouteError(t, "proof for "+c.htu+" at route "+c.route.String(), err, server.ErrorInvalidDPoPProof, 400, "DPoP proof verification failed")
	}
}

// TestUnroutedAliasProofNamesTheRouteSetters: a proof naming another
// URL, on a request with no route at an endpoint with a distinct mTLS
// alias, is refused with a cause naming the route setters, for the
// deployment whose alias listener doesn't set one; the public
// description stays the generic one.
func TestUnroutedAliasProofNamesTheRouteSetters(t *testing.T) {
	h := newRouteHarness(t, withTokenAlias(testTokenAlias))
	err := verifyRouted(t, h, testTokenAlias, 0)
	wantRouteError(t, "unrouted alias proof", err, server.ErrorInvalidDPoPProof, 400, "DPoP proof verification failed", append([]string{testTokenAlias, "no endpoint route"}, routeSetterNames...)...)
}

// TestRoutedOrAliaslessMismatchHasNoRouteHint: the route hint is only
// for a request with no route at an endpoint whose alias differs from
// its URL. With a route, with no alias or one equal to the endpoint's
// URL, or for a proof refused for something other than its htu, a
// refusal carries none.
func TestRoutedOrAliaslessMismatchHasNoRouteHint(t *testing.T) {
	aliased := newRouteHarness(t, withTokenAlias(testTokenAlias))
	for name, c := range map[string]struct {
		h     harness
		htu   string
		route server.EndpointRoute
		at    time.Duration
	}{
		"routed primary":   {aliased, testTokenAlias, server.PrimaryEndpoint, 0},
		"no alias":         {newRouteHarness(t, nil), "https://other.example/token", 0, 0},
		"alias is the URL": {newRouteHarness(t, withTokenAlias(testTokenEndpoint)), "https://other.example/token", 0, 0},
		"stale proof":      {aliased, testTokenEndpoint, 0, -time.Hour},
	} {
		req := clientlessTokenRequest(t, dpopProofAt(t, generateKey(t), c.htu, "", c.h.now.Add(c.at)))
		req.SetEndpointRoute(c.route)
		_, err := c.h.server.VerifyTokenRequestDPoP(context.Background(), req)
		wantRouteError(t, name, err, server.ErrorInvalidDPoPProof, 400, "DPoP proof verification failed")
		if strings.Contains(err.Error(), "no endpoint route") {
			t.Errorf("%s: err = %v, want no route hint", name, err)
		}
	}
}

// TestVerifyTokenRequestDPoPRefusesARouteWithNoTarget: the alias route
// on a server configuring no mTLS alias at all, or a route this package
// doesn't define, is the deployment's routing at fault: a 500 naming
// the setters, not a verdict on the proof.
func TestVerifyTokenRequestDPoPRefusesARouteWithNoTarget(t *testing.T) {
	h := newRouteHarness(t, nil)
	for name, route := range map[string]server.EndpointRoute{
		"alias route, no alias": server.MTLSEndpointAlias,
		"unknown route":         server.EndpointRoute(99),
	} {
		err := verifyRouted(t, h, testTokenEndpoint, route)
		wantRouteError(t, name, err, server.ErrorServerError, 500, "cannot determine DPoP request target", routeSetterNames...)
	}
}

// TestAliasRouteAtAnEndpointWithoutAlias: a request received at the
// alias route for an endpoint with no alias of its own, on a server
// advertising aliases for others, called a URL this server doesn't
// advertise: the client's mistake, refused as invalid_dpop_proof.
func TestAliasRouteAtAnEndpointWithoutAlias(t *testing.T) {
	h := newRouteHarness(t, func(e *server.MTLSEndpoints, parse func(string) fapi.URL) {
		e.PushedAuthorizationRequest = parse("https://mtls.as.example/par")
	})
	err := verifyRouted(t, h, testTokenAlias, server.MTLSEndpointAlias)
	wantRouteError(t, "unadvertised alias", err, server.ErrorInvalidDPoPProof, 400, "DPoP proof verification failed", "configures no alias for this endpoint")
}

// TestEndpointRouteString pins each route's name, as logs show it.
func TestEndpointRouteString(t *testing.T) {
	for route, want := range map[server.EndpointRoute]string{
		0:                        "unset",
		server.PrimaryEndpoint:   "primary",
		server.MTLSEndpointAlias: "mtls_alias",
		server.EndpointRoute(7):  "EndpointRoute(7)",
	} {
		if got := route.String(); got != want {
			t.Errorf("EndpointRoute(%d).String() = %q, want %q", uint8(route), got, want)
		}
	}
}
