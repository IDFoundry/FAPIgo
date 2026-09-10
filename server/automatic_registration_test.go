package server_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/fapihttp"
	"github.com/idfoundry/fapigo/federation"
	"github.com/idfoundry/fapigo/internal/clientassertion"
	intfed "github.com/idfoundry/fapigo/internal/federation"
	"github.com/idfoundry/fapigo/internal/jose"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
)

// automaticRegistrationFixture is a two-level federation (TA -> RP)
// standing in for a Relying Party this server has never statically
// registered — mirrors the fixture federation's own
// automatic_registration_test.go builds, adapted to this package since
// federation_test's own helpers aren't reachable from here.
type automaticRegistrationFixture struct {
	taID, rpID string
	taKey      *ecdsa.PrivateKey
	taJWKS     json.RawMessage
	rpOIDCKey  *ecdsa.PrivateKey
	fetcher    *fapihttp.Client
	now        time.Time
}

func fedJWKS(t *testing.T, kid string, key *ecdsa.PrivateKey) json.RawMessage {
	t.Helper()
	jwk, err := jose.NewJWK(&key.PublicKey, fapi.ES256)
	if err != nil {
		t.Fatalf("jose.NewJWK: %v", err)
	}
	jwkJSON, err := jwk.WithKeyID(kid).MarshalJSON()
	if err != nil {
		t.Fatalf("marshal jwk: %v", err)
	}
	set, err := json.Marshal(map[string][]json.RawMessage{"keys": {jwkJSON}})
	if err != nil {
		t.Fatalf("marshal jwk set: %v", err)
	}
	return set
}

// setupAutomaticRegistrationFixture builds a real TA -> RP federation
// over HTTPS test servers, with RP's own openid_relying_party metadata
// declaring redirectURI/private_key_jwt/rpOIDCKey — the same shape
// federation.AutomaticClientRepository already extensively tests on its
// own; this fixture exists only to prove server.New actually wires that
// mechanism in, not to re-prove the mechanism itself.
func setupAutomaticRegistrationFixture(t *testing.T, redirectURI string) *automaticRegistrationFixture {
	t.Helper()
	now := time.Now()

	taKey, rpFedKey, rpOIDCKey := generateKey(t), generateKey(t), generateKey(t)
	taJWKS := fedJWKS(t, "ta", taKey)

	taMux := http.NewServeMux()
	taServer := httptest.NewTLSServer(taMux)
	t.Cleanup(taServer.Close)
	rpMux := http.NewServeMux()
	rpServer := httptest.NewTLSServer(rpMux)
	t.Cleanup(rpServer.Close)

	taID, rpID := taServer.URL, rpServer.URL

	sign := func(p intfed.CreateParams) string {
		t.Helper()
		token, err := intfed.Create(p)
		if err != nil {
			t.Fatalf("intfed.Create: %v", err)
		}
		return token
	}

	fetchMeta, err := json.Marshal(map[string]string{"federation_fetch_endpoint": taID + "/fetch"})
	if err != nil {
		t.Fatalf("marshal federation_entity metadata: %v", err)
	}
	taConfig := sign(intfed.CreateParams{
		Signer: taKey, Algorithm: fapi.ES256, KeyID: "ta",
		Issuer: taID, Subject: taID, Now: now, Lifetime: time.Hour, JWKS: taJWKS,
		Metadata: map[string]json.RawMessage{"federation_entity": fetchMeta},
	})
	rpFedJWKS := fedJWKS(t, "rp-fed", rpFedKey)
	taAboutRP := sign(intfed.CreateParams{
		Signer: taKey, Algorithm: fapi.ES256, KeyID: "ta",
		Issuer: taID, Subject: rpID, Now: now, Lifetime: time.Hour, JWKS: rpFedJWKS,
	})
	rpMetadataJSON, err := json.Marshal(map[string]any{
		"redirect_uris":                   []string{redirectURI},
		"token_endpoint_auth_method":      "private_key_jwt",
		"token_endpoint_auth_signing_alg": "ES256",
		"jwks":                            json.RawMessage(fedJWKS(t, "rp-oidc", rpOIDCKey)),
	})
	if err != nil {
		t.Fatalf("marshal openid_relying_party metadata: %v", err)
	}
	rpConfig := sign(intfed.CreateParams{
		Signer: rpFedKey, Algorithm: fapi.ES256, KeyID: "rp-fed",
		Issuer: rpID, Subject: rpID, Now: now, Lifetime: time.Hour, JWKS: rpFedJWKS,
		AuthorityHints: []string{taID},
		Metadata:       map[string]json.RawMessage{"openid_relying_party": rpMetadataJSON},
	})

	serveToken := func(token string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/entity-statement+jwt")
			w.Write([]byte(token))
		}
	}
	taMux.HandleFunc("/.well-known/openid-federation", serveToken(taConfig))
	taMux.HandleFunc("/fetch", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("sub") != rpID {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		serveToken(taAboutRP)(w, r)
	})
	rpMux.HandleFunc("/.well-known/openid-federation", serveToken(rpConfig))

	pool := x509.NewCertPool()
	pool.AddCert(taServer.Certificate())
	pool.AddCert(rpServer.Certificate())
	httpClient := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}
	fetcher, err := fapihttp.New(httpClient, fapihttp.Config{
		MaxResponseBytes: 1 << 16, RequestTimeout: 5 * time.Second, MaxRedirects: 1,
		AllowLoopbackHTTP: true,
	})
	if err != nil {
		t.Fatalf("fapihttp.New: %v", err)
	}

	return &automaticRegistrationFixture{
		taID: taID, rpID: rpID, taKey: taKey, taJWKS: taJWKS,
		rpOIDCKey: rpOIDCKey, fetcher: fetcher, now: now,
	}
}

func validAutomaticRegistrationServerConfig(f *automaticRegistrationFixture) server.AutomaticRegistrationConfig {
	return server.AutomaticRegistrationConfig{
		TrustAnchors:         []federation.TrustAnchor{{EntityID: f.taID, JWKS: f.taJWKS}},
		AllowedScopes:        []string{"openid", "accounts"},
		MaxPathLength:        5,
		MaxStatementLifetime: 2 * time.Hour,
		MaxClockSkew:         5 * time.Second,
		MaxCacheAge:          time.Hour,
	}
}

func TestNewAcceptsZeroValueAutomaticRegistrationConfig(t *testing.T) {
	cfg := validConfig(t)
	if len(cfg.AutomaticRegistration.TrustAnchors) != 0 {
		t.Fatalf("validConfig's zero-value AutomaticRegistration.TrustAnchors is non-empty")
	}
	if _, err := server.New(cfg, validDependencies()); err != nil {
		t.Fatalf("New: %v", err)
	}
}

func TestNewRejectsInvalidAutomaticRegistrationConfig(t *testing.T) {
	f := setupAutomaticRegistrationFixture(t, testRedirectURI)

	validCfg := validConfig(t)
	validCfg.AutomaticRegistration = validAutomaticRegistrationServerConfig(f)
	validDeps := validDependencies()
	validDeps.FederationHTTP = f.fetcher
	validDeps.Clock = fixedClock{now: f.now}

	cases := map[string]func(*server.Config, *server.Dependencies){
		"empty allowed scopes": func(c *server.Config, d *server.Dependencies) { c.AutomaticRegistration.AllowedScopes = nil },
		"zero max cache age":   func(c *server.Config, d *server.Dependencies) { c.AutomaticRegistration.MaxCacheAge = 0 },
		"zero max path length": func(c *server.Config, d *server.Dependencies) { c.AutomaticRegistration.MaxPathLength = 0 },
		"nil federation http":  func(c *server.Config, d *server.Dependencies) { d.FederationHTTP = nil },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := validCfg
			deps := validDeps
			mutate(&cfg, &deps)
			if _, err := server.New(cfg, deps); err == nil {
				t.Fatalf("New(%s) = nil error, want error", name)
			}
		})
	}
}

func TestNewRejectsMalformedTrustAnchorEntry(t *testing.T) {
	// TrustAnchors itself is non-empty (so AutomaticRegistration is
	// "on"), but the one entry in it is malformed — validateConfig
	// only checks the fields it owns (AllowedScopes, MaxCacheAge);
	// federation.NewResolver validates TrustAnchors/Limits itself when
	// New actually constructs a Resolver from them.
	f := setupAutomaticRegistrationFixture(t, testRedirectURI)
	cfg := validConfig(t)
	cfg.AutomaticRegistration = validAutomaticRegistrationServerConfig(f)
	cfg.AutomaticRegistration.TrustAnchors = []federation.TrustAnchor{{EntityID: "", JWKS: nil}}
	deps := validDependencies()
	deps.FederationHTTP = f.fetcher
	if _, err := server.New(cfg, deps); err == nil {
		t.Fatalf("New(malformed trust anchor entry) = nil error, want error")
	}
}

// TestNewWiresAutomaticRegistrationIntoPushAuthorizationRequest proves
// server.New actually wraps Dependencies.Clients/ClientKeys when
// AutomaticRegistration is configured: Dependencies.Clients/ClientKeys
// are both deliberately empty (no statically registered client would
// ever resolve), yet PushAuthorizationRequest still succeeds for a
// Relying Party this server has never seen before, authenticated with a
// client assertion signed by the key that RP published in its own
// federation-resolved openid_relying_party metadata.
func TestNewWiresAutomaticRegistrationIntoPushAuthorizationRequest(t *testing.T) {
	f := setupAutomaticRegistrationFixture(t, testRedirectURI)

	issuer, err := fapi.ParseIssuerURL(testIssuer)
	if err != nil {
		t.Fatalf("ParseIssuerURL: %v", err)
	}
	cfg := server.Config{
		Issuer:    issuer,
		Endpoints: testEndpoints(t),
		Profile:   server.ProfileFAPISecurity,
		Algorithms: server.AlgorithmPolicy{
			ClientAssertion: server.AlgorithmSet{fapi.ES256},
			RequestObject:   server.AlgorithmSet{fapi.ES256},
			JARM:            fapi.ES256,
			IDToken:         fapi.ES256,
		},
		Limits: server.Limits{
			PushedRequestLifetime:      90 * time.Second,
			MaxClientAssertionLifetime: time.Minute,
			MaxRequestObjectLifetime:   time.Minute,
			InteractionLifetime:        5 * time.Minute,
			AuthorizationCodeLifetime:  time.Minute,
			JARMResponseLifetime:       time.Minute,
			AccessTokenLifetime:        5 * time.Minute,
			IDTokenLifetime:            5 * time.Minute,
			RefreshTokenLifetime:       5 * time.Minute,
			MaxDPoPProofAge:            time.Minute,
			MaxClockSkew:               5 * time.Second,
		},
		Assurance:             server.AssuranceDevelopment,
		AutomaticRegistration: validAutomaticRegistrationServerConfig(f),
	}
	serverKey := generateKey(t)
	serverKeyManager := &fakeKeyManager{key: serverKey, keyID: "as-key-1"}
	deps := server.Dependencies{
		// Deliberately empty: no statically registered client would
		// ever resolve, so PushAuthorizationRequest's success below can
		// only be explained by AutomaticRegistration having kicked in.
		Clients:        &fakeClientRepository{clients: map[fapi.ClientID]storage.RegisteredClient{}},
		Transactions:   &fakeTransactionStore{},
		Grants:         &fakeGrantStore{},
		Replay:         &fakeReplayStore{},
		ClientKeys:     &fakeClientKeySource{keysByClient: map[fapi.ClientID][]keys.VerificationKey{}},
		Keys:           serverKeyManager,
		AccessTokens:   server.JWTAccessTokens{Keys: serverKeyManager, Algorithm: fapi.ES256},
		Revocation:     &fakeRevocationSink{},
		Audit:          &fakeAuditSink{},
		Clock:          fixedClock{now: f.now},
		Random:         rand.Reader,
		FederationHTTP: f.fetcher,
	}

	srv, err := server.New(cfg, deps)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}

	assertion, err := clientassertion.CreateAssertion(clientassertion.AssertionRequest{
		Signer: f.rpOIDCKey, Algorithm: fapi.ES256, KeyID: "rp-oidc",
		ClientID: f.rpID, Audience: testIssuer,
		Now: f.now, Lifetime: 30 * time.Second,
	})
	if err != nil {
		t.Fatalf("CreateAssertion: %v", err)
	}

	if _, err := srv.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
		HTTP: server.FormRequest{Parameters: plainFormParameters(t, assertion, nil)},
	}); err != nil {
		t.Fatalf("PushAuthorizationRequest (automatically-registered client): %v", err)
	}
}
