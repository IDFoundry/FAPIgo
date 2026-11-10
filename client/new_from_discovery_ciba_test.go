package client_test

import (
	"context"
	"crypto"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/client"
	"github.com/idfoundry/fapigo/keys"
)

// TestNewFromDiscoveryKeepsCIBAEndpointOnlyForACIBAClient covers a
// server advertising a backchannel authentication endpoint (and an mTLS
// alias for it): a code-flow client built from its discovered endpoints
// must not inherit the endpoint, since New would then demand CIBA's
// request algorithm and lifetime from a client that never uses CIBA,
// while a client setting either CIBA setting still gets the endpoint.
func TestNewFromDiscoveryKeepsCIBAEndpointOnlyForACIBAClient(t *testing.T) {
	as := newFakeCIBAAS(t)
	ts := httptest.NewServer(as.handler())
	t.Cleanup(ts.Close)
	endpoint := func(path string) fapi.URL {
		u, err := fapi.ParseEndpointURL(ts.URL+path, fapi.AllowLoopbackHTTP())
		if err != nil {
			t.Fatalf("ParseEndpointURL(%s): %v", path, err)
		}
		return u
	}
	base := validConfig(t)
	discovered := client.DiscoveredMetadata{
		Endpoints: client.Endpoints{
			Authorization:              base.Endpoints.Authorization,
			PushedAuthorizationRequest: base.Endpoints.PushedAuthorizationRequest,
			Token:                      endpoint("/token"),
			BackchannelAuthentication:  endpoint("/backchannel-authenticate"),
		},
		MTLSEndpointAliases:                        &client.MTLSEndpoints{BackchannelAuthentication: endpoint("/backchannel-authenticate")},
		IDTokenAlgorithms:                          []fapi.SignatureAlgorithm{fapi.ES256},
		BackchannelAuthenticationRequestAlgorithms: []fapi.SignatureAlgorithm{fapi.ES256},
	}
	deps := validDependencies(t)
	deps.HTTP = ts.Client()
	deps.Keys = newFakeKeyManager(t,
		keys.ClientAuthentication, keys.DPoPProofSigning, keys.BackchannelAuthenticationRequestSigning)
	deps.IssuerKeys = &fakeIssuerKeySource{keys: map[keys.IssuerVerificationPurpose]crypto.PublicKey{
		keys.IDTokenVerification: &as.idTokenKey.PublicKey,
	}}

	for _, useAliases := range []bool{false, true} {
		cfg := base
		cfg.Endpoints = client.Endpoints{}
		cfg.UseMTLSEndpointAliases = useAliases
		c, err := client.NewFromDiscovery(discovered, cfg, deps)
		if err != nil {
			t.Fatalf("aliases=%v: NewFromDiscovery(code-flow client, server offers CIBA): %v", useAliases, err)
		}
		_, err = c.BeginBackchannelAuthentication(context.Background(), client.BeginBackchannelAuthenticationRequest{
			Scope: []string{"openid"}, LoginHint: "user@example.com",
		})
		if err == nil || !strings.Contains(err.Error(), "backchannel authentication is not configured") {
			t.Errorf("aliases=%v: BeginBackchannelAuthentication on a code-flow client = %v, want \"not configured\"", useAliases, err)
		}
	}

	for name, set := range map[string]func(*client.Config){
		"both": func(cfg *client.Config) {
			cfg.Algorithms.BackchannelAuthenticationRequest, cfg.Limits.BackchannelAuthenticationRequestLifetime = fapi.ES256, time.Minute
		},
		"algorithm": func(cfg *client.Config) { cfg.Algorithms.BackchannelAuthenticationRequest = fapi.ES256 },
		"lifetime":  func(cfg *client.Config) { cfg.Limits.BackchannelAuthenticationRequestLifetime = time.Minute },
	} {
		cfg := base
		cfg.Endpoints = client.Endpoints{}
		set(&cfg)
		c, err := client.NewFromDiscovery(discovered, cfg, deps)
		if name != "both" {
			// Either setting alone keeps the endpoint, so New names the
			// missing one instead of CIBA being silently dropped.
			if err == nil || !strings.Contains(err.Error(), "endpoints.backchannel_authentication is set") {
				t.Errorf("%s: NewFromDiscovery = %v, want New's error for the missing CIBA setting", name, err)
			}
			continue
		}
		if err != nil {
			t.Fatalf("%s: NewFromDiscovery(CIBA client): %v", name, err)
		}
		beginTestBackchannelSession(t, c)
		if as.bcCallCount != 1 {
			t.Errorf("%s: backchannel endpoint called %d times, want 1", name, as.bcCallCount)
		}
	}
}
