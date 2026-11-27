package server_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/mtls"
	"github.com/idfoundry/fapigo/internal/token"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
)

// The tests in this file cover token-endpoint grants whose DPoP proof
// is checked against the URL the request's EndpointRoute names,
// alongside the code exchange and refresh cases in
// client_auth_mtls_test.go: the client_credentials grant. Each runs a
// client authenticated by its certificate (so it calls the token
// endpoint's mTLS alias) with DPoP-bound tokens.

const (
	aliasRouteMTLSToken    = "https://mtls.as.example/token"
	aliasRoutePrimaryToken = testTokenEndpoint
)

// aliasRouteCase is one combination of a request's endpoint route and
// the URL its DPoP proof names, and whether the request is accepted.
type aliasRouteCase struct {
	route    server.EndpointRoute
	proofURL string
	accepted bool
}

// aliasRouteCases: a proof verifies only against the URL the route
// names, and without a route against the primary URL only.
var aliasRouteCases = map[string]aliasRouteCase{
	"alias route, alias proof":     {route: server.MTLSEndpointAlias, proofURL: aliasRouteMTLSToken, accepted: true},
	"no route, alias proof":        {route: 0, proofURL: aliasRouteMTLSToken, accepted: false},
	"no route, primary proof":      {route: 0, proofURL: aliasRoutePrimaryToken, accepted: true},
	"alias route, primary proof":   {route: server.MTLSEndpointAlias, proofURL: aliasRoutePrimaryToken, accepted: false},
	"primary route, primary proof": {route: server.PrimaryEndpoint, proofURL: aliasRoutePrimaryToken, accepted: true},
}

// certAuthClient registers testClientID for self_signed_tls_client_auth
// with DPoP sender-constraining (the default), adjusted by mutate.
func certAuthClient(t *testing.T, cert *x509.Certificate, mutate func(*storage.RegisteredClientConfig)) storage.RegisteredClient {
	t.Helper()
	cfg := storage.RegisteredClientConfig{
		ID:                            testClientID,
		RedirectURIs:                  []fapi.RegisteredRedirectURI{testRedirectURI},
		ClientAuthMethod:              storage.ClientAuthMethodSelfSignedTLSClientAuth,
		ExpectedCertificateThumbprint: mtls.Thumbprint(cert),
		AllowedScopes:                 []string{"openid", "accounts"},
	}
	mutate(&cfg)
	client, err := storage.NewRegisteredClient(cfg)
	if err != nil {
		t.Fatalf("NewRegisteredClient: %v", err)
	}
	return client
}

func aliasRouteMTLSEndpoints(t *testing.T) server.MTLSEndpoints {
	t.Helper()
	mtlsToken, err := fapi.ParseEndpointURL(aliasRouteMTLSToken)
	if err != nil {
		t.Fatalf("ParseEndpointURL: %v", err)
	}
	return server.MTLSEndpoints{Token: mtlsToken}
}

// requireDPoPBoundTo checks result is a DPoP access token whose cnf.jkt
// is key's thumbprint.
func requireDPoPBoundTo(t *testing.T, h harness, result server.TokenResult, key *ecdsa.PrivateKey) {
	t.Helper()
	if result.TokenType != "DPoP" {
		t.Fatalf("TokenType = %q, want %q", result.TokenType, "DPoP")
	}
	parsed, err := token.ParseAccessToken(result.AccessToken.Reveal())
	if err != nil {
		t.Fatalf("ParseAccessToken: %v", err)
	}
	validated, err := parsed.Validate(&h.serverKey.PublicKey, token.AccessTokenValidatePolicy{
		ExpectedIssuer: testIssuer, ExpectedAudience: testIssuer,
		Algorithm: fapi.ES256, Now: h.now, MaxLifetime: 10 * time.Minute,
	})
	if err != nil {
		t.Fatalf("Validate access token: %v", err)
	}
	if want := dpopThumbprint(t, key); validated.JKT != want {
		t.Fatalf("access token cnf.jkt = %q, want %q", validated.JKT, want)
	}
}

// requireAliasRouteOutcome checks one aliasRouteCase's result: tokens
// bound to key when accepted, invalid_dpop_proof when not.
func requireAliasRouteOutcome(t *testing.T, h harness, tc aliasRouteCase, result server.TokenResult, err error, key *ecdsa.PrivateKey) {
	t.Helper()
	if !tc.accepted {
		if serverErrorCode(t, err) != server.ErrorInvalidDPoPProof {
			t.Fatalf("error = %v, want invalid_dpop_proof", err)
		}
		return
	}
	if err != nil {
		t.Fatalf("error = %v, want tokens", err)
	}
	requireDPoPBoundTo(t, h, result, key)
}

// newHarnessWithClientCredentialsAtMTLSAlias is
// newHarnessWithClientCredentialsGrant with testClientID authenticated
// by certificate and the token endpoint's mTLS alias configured.
func newHarnessWithClientCredentialsAtMTLSAlias(t *testing.T) (harness, *x509.Certificate) {
	t.Helper()
	h := newHarnessWithClientCredentialsGrant(t, storage.SenderConstrainDPoP, true)
	cert := selfSignedTestClientCert(t)
	client := certAuthClient(t, cert, func(c *storage.RegisteredClientConfig) {
		c.AllowedScopes = []string{"accounts"}
		c.AllowsClientCredentialsGrant = true
	})
	h.cfg.MTLSEndpoints = aliasRouteMTLSEndpoints(t)
	h.clients = &fakeClientRepository{clients: map[fapi.ClientID]storage.RegisteredClient{testClientID: client}}
	h.deps.Clients = h.clients
	srv, err := server.New(h.cfg, h.deps)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	h.server = srv
	return h, cert
}

// TestRequestClientCredentialsTokenDPoPProofAtMTLSAlias: a
// client_credentials request is checked against the URL its route
// names, as a code exchange is.
func TestRequestClientCredentialsTokenDPoPProofAtMTLSAlias(t *testing.T) {
	for name, tc := range aliasRouteCases {
		t.Run(name, func(t *testing.T) {
			h, cert := newHarnessWithClientCredentialsAtMTLSAlias(t)
			dpopKey := generateKey(t)
			result, err := h.server.RequestClientCredentialsToken(context.Background(), server.ClientCredentialsTokenRequest{
				HTTP: server.FormRequest{EndpointRoute: tc.route, Parameters: []server.FormParameter{
					formParam("client_id", testClientID.String()),
					formParam("grant_type", "client_credentials"),
					formParam("scope", "accounts"),
				}},
				DPoPProofs:      []string{dpopProofForURL(t, dpopKey, tc.proofURL, h.now)},
				PeerCertificate: cert,
			})
			requireAliasRouteOutcome(t, h, tc, result, err, dpopKey)
		})
	}
}
