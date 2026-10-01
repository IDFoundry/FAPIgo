package client_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/client"
	"github.com/idfoundry/fapigo/storage"
)

// signingFreeConfig is a client that signs nothing: client credentials
// only, authenticating with a TLS client certificate, holding
// mTLS-bound tokens. tokenURL is its token endpoint.
func signingFreeConfig(t *testing.T, tokenURL string) client.Config {
	t.Helper()
	cfg := validConfig(t)
	token, err := fapi.ParseEndpointURL(tokenURL, fapi.AllowLoopbackHTTP())
	if err != nil {
		t.Fatalf("ParseEndpointURL(token): %v", err)
	}
	cfg.Endpoints = client.Endpoints{Token: token}
	cfg.RedirectURI = ""
	cfg.OAuthOnly = true
	cfg.ClientAuthMethod = storage.ClientAuthMethodTLSClientAuth
	cfg.SenderConstrain = storage.SenderConstrainMTLS
	cfg.Algorithms = client.Algorithms{}
	cfg.Limits.ClientAssertionLifetime = 0
	cfg.Limits.MaxIDTokenLifetime = 0
	return cfg
}

func signingFreeDependencies(t *testing.T, http client.Dependencies) client.Dependencies {
	t.Helper()
	deps := http
	deps.Keys, deps.IssuerKeys, deps.Sessions = nil, nil, nil
	return deps
}

// TestClientCredentialsWithoutSigningKeys covers a client that signs
// nothing, built without Dependencies.Keys: it gets a token and sends
// it to a protected resource through ClientCredentialsResource, as an
// mTLS-bound Bearer token with no DPoP proof.
func TestClientCredentialsWithoutSigningKeys(t *testing.T) {
	var resourceAuthorization, resourceDPoP string
	mux := http.NewServeMux()
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("token: parse form: %v", err)
		}
		if r.PostForm.Get("client_assertion") != "" || r.Header.Get("DPoP") != "" {
			t.Errorf("token request carries a client assertion or DPoP proof: nothing should be signed")
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "mtls-bound-token", "token_type": "Bearer", "expires_in": 300, "scope": "payroll"})
	})
	mux.HandleFunc("GET /resource", func(w http.ResponseWriter, r *http.Request) {
		resourceAuthorization, resourceDPoP = r.Header.Get("Authorization"), r.Header.Get("DPoP")
		w.WriteHeader(http.StatusNoContent)
	})
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)

	deps := validDependencies(t)
	deps.HTTP = ts.Client()
	c, err := client.New(signingFreeConfig(t, ts.URL+"/token"), signingFreeDependencies(t, deps))
	if err != nil {
		t.Fatalf("client.New(no signing keys): %v", err)
	}
	ctx := context.Background()
	result, err := c.RequestClientCredentialsToken(ctx, client.ClientCredentialsTokenRequest{Scope: []string{"payroll"}})
	if err != nil {
		t.Fatalf("RequestClientCredentialsToken: %v", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/resource", nil)
	if err != nil {
		t.Fatal(err)
	}
	res, err := c.ClientCredentialsResource(result).Do(ctx, req)
	if err != nil {
		t.Fatalf("ClientCredentialsResource.Do: %v", err)
	}
	_ = res.Body.Close()
	if resourceAuthorization != "Bearer mtls-bound-token" || resourceDPoP != "" {
		t.Errorf("resource saw Authorization %q, DPoP %q; want the Bearer token and no DPoP proof", resourceAuthorization, resourceDPoP)
	}
}

// TestNewRequiresKeysWhenSomethingIsSigned covers every configuration
// that has the client sign something: each still requires
// Dependencies.Keys.
func TestNewRequiresKeysWhenSomethingIsSigned(t *testing.T) {
	cases := map[string]func(*client.Config){
		"private_key_jwt": func(c *client.Config) {
			c.ClientAuthMethod = storage.ClientAuthMethodPrivateKeyJWT
			c.Algorithms.ClientAuthentication, c.Limits.ClientAssertionLifetime = fapi.ES256, time.Minute
		},
		"DPoP-bound tokens": func(c *client.Config) {
			c.SenderConstrain = storage.SenderConstrainDPoP
			c.Algorithms.DPoP = fapi.ES256
		},
		"request objects": func(c *client.Config) {
			c.PushedRequestEncoding = client.PushedRequestEncodingRequestObject
			c.Algorithms.RequestObject = fapi.ES256
			c.Limits.RequestObjectLifetime = time.Minute
		},
		"CIBA": func(c *client.Config) {
			bc, err := fapi.ParseEndpointURL(testIssuer + "/backchannel-authenticate")
			if err != nil {
				t.Fatal(err)
			}
			c.Endpoints.BackchannelAuthentication = bc
			c.Algorithms.BackchannelAuthenticationRequest = fapi.ES256
			c.Limits.BackchannelAuthenticationRequestLifetime = time.Minute
		},
		"federation": func(c *client.Config) {
			c.Federation = client.FederationConfig{EntityID: testIssuer + "/rp", Algorithm: fapi.ES256, Lifetime: time.Hour}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := signingFreeConfig(t, testIssuer+"/token")
			mutate(&cfg)
			deps := signingFreeDependencies(t, validDependencies(t))
			if _, err := client.New(cfg, deps); err == nil || !strings.Contains(err.Error(), "keys is required") {
				t.Fatalf("client.New(%s, no keys) = %v, want keys required", name, err)
			}
			deps.Keys = validDependencies(t).Keys
			if _, err := client.New(cfg, deps); err != nil {
				t.Fatalf("client.New(%s, with keys): %v", name, err)
			}
		})
	}
}

// TestNewWithoutSigningKeysUnderProductionAssurance checks that a client
// with no Keys still gets production assurance's other checks.
func TestNewWithoutSigningKeysUnderProductionAssurance(t *testing.T) {
	cfg := signingFreeConfig(t, testIssuer+"/token")
	cfg.Assurance = client.AssuranceProduction
	deps := signingFreeDependencies(t, validDependencies(t))
	deps.Random = nil
	if _, err := client.New(cfg, deps); err == nil {
		t.Fatal("client.New(production, nil Random) = nil error, want error")
	}
}
