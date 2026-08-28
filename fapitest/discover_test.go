package fapitest

import (
	"context"
	"crypto/rand"
	"net/http"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/client"
	"github.com/idfoundry/fapigo/fapihttp"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
)

// TestDiscoverEndToEnd proves the full discovery pipeline against a
// genuinely running authorization server, not a hand-crafted document:
// client.Discover fetches this package's own simulated AS's real
// /.well-known/openid-configuration, keys.NewJWKSIssuerKeySource fetches
// its real /jwks, and a client.Client built from nothing but that
// discovered configuration completes a full authorization_code flow —
// the same proof-by-construction fapitest's other tests apply to the
// hand-configured path.
//
// This deliberately does not use Harness.New: that harness's Issuer is
// a fixed, non-resolvable placeholder (see the Issuer constant), which
// is fine for every other test here since nothing else ever dereferences
// it as an HTTP target, but discovery must fetch from the issuer it
// validates against, so this test needs the issuer identifier to be the
// httptest.Server's own real, dynamically assigned URL instead.
func TestDiscoverEndToEnd(t *testing.T) {
	clock := &manualClock{now: time.Now()}
	asKeys := newAlgorithmKeyManager(t, fapi.ES256, keys.JARMSigning, keys.AccessTokenSigning, keys.IDTokenSigning)
	clientKeys := newAlgorithmKeyManager(t, fapi.ES256, keys.ClientAuthentication, keys.RequestObjectSigning, keys.DPoPProofSigning)

	as := newAuthServer(t, clock, AutoApprove{Subject: Subject, ACR: "urn:mace:incommon:iap:silver", AMR: []string{"pwd"}}, false)

	issuer, err := fapi.ParseIssuerURL(as.ts.URL, fapi.AllowLoopbackHTTP())
	if err != nil {
		t.Fatalf("ParseIssuerURL: %v", err)
	}

	registeredClient, err := storage.NewRegisteredClient(storage.RegisteredClientConfig{
		ID:                       ClientID,
		RedirectURIs:             []fapi.RegisteredRedirectURI{RedirectURI},
		ClientAssertionAlgorithm: fapi.ES256,
		RequestObjectAlgorithm:   fapi.ES256,
		AllowedScopes:            []string{"openid", "accounts"},
	})
	if err != nil {
		t.Fatalf("NewRegisteredClient: %v", err)
	}

	srvCfg := server.Config{
		Issuer:    issuer,
		Endpoints: loopbackEndpoints(as.ts.URL),
		Profile:   server.ProfileFAPISecurity,
		Algorithms: server.AlgorithmPolicy{
			ClientAssertion: server.AlgorithmSet{fapi.ES256},
			RequestObject:   server.AlgorithmSet{fapi.ES256},
			IDToken:         fapi.ES256,
		},
		Limits: server.Limits{
			PushedRequestLifetime:      90 * time.Second,
			MaxClientAssertionLifetime: time.Minute,
			MaxRequestObjectLifetime:   time.Minute,
			InteractionLifetime:        5 * time.Minute,
			AuthorizationCodeLifetime:  time.Minute,
			AccessTokenLifetime:        5 * time.Minute,
			IDTokenLifetime:            5 * time.Minute,
			RefreshTokenLifetime:       5 * time.Minute,
			MaxDPoPProofAge:            time.Minute,
			MaxClockSkew:               5 * time.Second,
		},
		Assurance: server.AssuranceDevelopment,
	}
	jwtAccessTokens, err := server.NewJWTAccessTokens(asKeys, fapi.ES256)
	if err != nil {
		t.Fatalf("server.NewJWTAccessTokens: %v", err)
	}
	srvDeps := server.Dependencies{
		Clients:      &memClientRepository{client: registeredClient},
		Transactions: newMemTransactionStore(),
		Grants:       newMemGrantStore(),
		Replay:       newMemReplayStore(),
		ClientKeys:   &memClientKeySource{clientID: ClientID, manager: clientKeys},
		Keys:         asKeys,
		AccessTokens: jwtAccessTokens,
		Revocation:   server.NoRevocation{},
		Clock:        clock,
		Random:       rand.Reader,
	}
	srv, err := server.New(srvCfg, srvDeps)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	as.srv = srv

	httpClient := as.ts.Client()
	httpClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	fetcher, err := fapihttp.New(httpClient, fapihttp.Config{
		MaxResponseBytes: 1 << 16, RequestTimeout: 5 * time.Second, MaxRedirects: 1,
		AllowLoopbackHTTP: true,
	})
	if err != nil {
		t.Fatalf("fapihttp.New: %v", err)
	}

	discovered, err := client.Discover(context.Background(), fetcher, issuer, fapi.AllowLoopbackHTTP())
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(discovered.IDTokenAlgorithms) != 1 || discovered.IDTokenAlgorithms[0] != fapi.ES256 {
		t.Fatalf("IDTokenAlgorithms = %v, want [ES256]", discovered.IDTokenAlgorithms)
	}

	issuerKeys, err := keys.NewJWKSIssuerKeySource(fetcher, discovered.JWKSURI, time.Minute)
	if err != nil {
		t.Fatalf("NewJWKSIssuerKeySource: %v", err)
	}

	clientCfg := client.Config{
		Issuer: issuer, ClientID: ClientID, RedirectURI: RedirectURI,
		Endpoints: discovered.Endpoints,
		Profile:   client.ProfileFAPISecurity,
		Algorithms: client.Algorithms{
			ClientAuthentication: fapi.ES256,
			DPoP:                 fapi.ES256,
			IDToken:              discovered.IDTokenAlgorithms[0],
		},
		Limits: client.Limits{
			ClientAssertionLifetime: time.Minute, SessionLifetime: 5 * time.Minute,
			MaxIDTokenLifetime: 5 * time.Minute, MaxClockSkew: 5 * time.Second,
			HTTPTimeout: 5 * time.Second, MaxHTTPResponseBytes: 1 << 16,
			MaxJOSECompactBytes: 16 * 1024,
		},
	}
	clientDeps := client.Dependencies{
		Sessions: newMemSessionStore(), Keys: clientKeys, IssuerKeys: issuerKeys,
		HTTP: httpClient, Clock: clock, Random: rand.Reader,
	}
	c, err := client.New(clientCfg, clientDeps)
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}

	h := &Harness{t: t, Client: c, Clock: clock, authServer: as, httpClient: httpClient}
	tokens, err := h.RunAuthorizationCodeFlow(context.Background(), []string{"openid", "accounts"})
	if err != nil {
		t.Fatalf("RunAuthorizationCodeFlow: %v", err)
	}
	if !tokens.HasIDToken || tokens.Subject != Subject {
		t.Fatalf("HasIDToken=%v Subject=%q, want true/%q", tokens.HasIDToken, tokens.Subject, Subject)
	}
}
