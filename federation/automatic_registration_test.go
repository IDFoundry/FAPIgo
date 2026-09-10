package federation_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/fapihttp"
	"github.com/idfoundry/fapigo/federation"
	intfed "github.com/idfoundry/fapigo/internal/federation"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/storage"
)

// automaticRegistrationFixture is a two-level federation (TA -> RP)
// purpose-built for AutomaticClientRepository/AutomaticClientKeySource
// tests — chain-walking itself is already covered by resolver_test.go,
// so this stays as shallow as the feature under test allows. rpFedKey
// signs RP's own Entity Configuration (its federation identity); rpOIDCKey
// is a deliberately different key, published only inside RP's own
// openid_relying_party metadata "jwks" — the two are never the same key
// (federation/doc.go), and AutomaticClientKeySource must resolve the
// latter, not the former.
type automaticRegistrationFixture struct {
	taID, rpID          string
	taKey               *ecdsa.PrivateKey
	taJWKS              json.RawMessage
	rpFedKey, rpOIDCKey *ecdsa.PrivateKey
	fetcher             *fapihttp.Client
	now                 time.Time
	rpConfigCalls       *int32
}

// setupAutomaticRegistrationFixture builds the fixture. metadataFn, if
// non-nil, is called with the RP's own entity ID and its (freshly
// generated) OIDC-level key to build RP's own openid_relying_party
// metadata — a callback rather than a precomputed value, since both
// only exist once setup is already underway. nil means RP publishes no
// openid_relying_party metadata at all.
func setupAutomaticRegistrationFixture(t *testing.T, metadataFn func(rpID string, rpOIDCKey *ecdsa.PrivateKey) json.RawMessage) *automaticRegistrationFixture {
	t.Helper()
	now := time.Now()

	taKey, rpFedKey, rpOIDCKey := generateKey(t), generateKey(t), generateKey(t)
	taJWKS := jwksFor(t, "ta", taKey)

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

	taConfig := sign(intfed.CreateParams{
		Signer: taKey, Algorithm: fapi.ES256, KeyID: "ta",
		Issuer: taID, Subject: taID, Now: now, Lifetime: time.Hour, JWKS: taJWKS,
		Metadata: federationEntityMetadata(t, taID+"/fetch"),
	})
	rpFedJWKS := jwksFor(t, "rp-fed", rpFedKey)
	taAboutRP := sign(intfed.CreateParams{
		Signer: taKey, Algorithm: fapi.ES256, KeyID: "ta",
		Issuer: taID, Subject: rpID, Now: now, Lifetime: time.Hour, JWKS: rpFedJWKS,
	})
	var metadata map[string]json.RawMessage
	if metadataFn != nil {
		metadata = map[string]json.RawMessage{"openid_relying_party": metadataFn(rpID, rpOIDCKey)}
	}
	rpConfig := sign(intfed.CreateParams{
		Signer: rpFedKey, Algorithm: fapi.ES256, KeyID: "rp-fed",
		Issuer: rpID, Subject: rpID, Now: now, Lifetime: time.Hour, JWKS: rpFedJWKS,
		AuthorityHints: []string{taID}, Metadata: metadata,
	})

	taMux.HandleFunc("/.well-known/openid-federation", serveStatement(taConfig))
	taMux.HandleFunc("/fetch", serveFetch(map[string]string{rpID: taAboutRP}))
	var calls int32
	rpMux.HandleFunc("/.well-known/openid-federation", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		serveStatement(rpConfig)(w, r)
	})

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
		rpFedKey: rpFedKey, rpOIDCKey: rpOIDCKey,
		fetcher: fetcher, now: now, rpConfigCalls: &calls,
	}
}

func (f *automaticRegistrationFixture) newResolver(t *testing.T) *federation.Resolver {
	t.Helper()
	r, err := federation.NewResolver(federation.Config{
		TrustAnchors: []federation.TrustAnchor{{EntityID: f.taID, JWKS: f.taJWKS}},
		Limits:       federation.Limits{MaxPathLength: 5, MaxStatementLifetime: 2 * time.Hour, MaxClockSkew: 5 * time.Second},
	}, federation.Dependencies{HTTP: f.fetcher, Clock: fixedClock{now: f.now}})
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	return r
}

// rpMetadataBuilder returns a metadataFn (see setupAutomaticRegistrationFixture)
// building a minimal but complete openid_relying_party metadata object:
// redirect_uris, private_key_jwt authentication with rpOIDCKey (kid
// "rp-oidc") as its published jwks. A closure over t, rather than
// taking t as a direct parameter, so it matches metadataFn's own
// signature exactly and can be passed as a plain function value.
func rpMetadataBuilder(t *testing.T) func(rpID string, rpOIDCKey *ecdsa.PrivateKey) json.RawMessage {
	return func(rpID string, rpOIDCKey *ecdsa.PrivateKey) json.RawMessage {
		t.Helper()
		raw, err := json.Marshal(map[string]any{
			"redirect_uris":                   []string{rpID + "/cb"},
			"token_endpoint_auth_method":      "private_key_jwt",
			"token_endpoint_auth_signing_alg": "ES256",
			"jwks":                            json.RawMessage(jwksFor(t, "rp-oidc", rpOIDCKey)),
		})
		if err != nil {
			t.Fatalf("marshal openid_relying_party metadata: %v", err)
		}
		return raw
	}
}

// alwaysFailsRepository is a storage.ClientRepository that always
// fails — for tests wanting AutomaticClientRepository's federation
// fallback exercised unconditionally.
type alwaysFailsRepository struct{}

func (alwaysFailsRepository) ResolveClient(context.Context, fapi.ClientID) (storage.RegisteredClient, error) {
	return storage.RegisteredClient{}, fmt.Errorf("alwaysFailsRepository: no such client")
}

// alwaysFailsKeySource mirrors alwaysFailsRepository for keys.ClientKeySource.
type alwaysFailsKeySource struct{}

func (alwaysFailsKeySource) ResolveVerificationKeys(context.Context, keys.ClientKeyRequest) (keys.VerificationKeySet, error) {
	return keys.VerificationKeySet{}, fmt.Errorf("alwaysFailsKeySource: no such client")
}

// staticRepository resolves exactly one client ID to a fixed
// storage.RegisteredClient, failing for every other ID — a minimal
// storage.ClientRepository test double representing "statically
// registered" clients.
type staticRepository struct {
	id     fapi.ClientID
	client storage.RegisteredClient
}

func (s staticRepository) ResolveClient(_ context.Context, id fapi.ClientID) (storage.RegisteredClient, error) {
	if id == s.id {
		return s.client, nil
	}
	return storage.RegisteredClient{}, fmt.Errorf("staticRepository: no such client %q", id)
}

// staticKeySource resolves exactly one client ID to a fixed
// keys.VerificationKeySet, failing for every other ID.
type staticKeySource struct {
	id     fapi.ClientID
	keySet keys.VerificationKeySet
}

func (s staticKeySource) ResolveVerificationKeys(_ context.Context, req keys.ClientKeyRequest) (keys.VerificationKeySet, error) {
	if req.ClientID == s.id {
		return s.keySet, nil
	}
	return keys.VerificationKeySet{}, fmt.Errorf("staticKeySource: no such client %q", req.ClientID)
}

func validAutomaticRegistrationConfig() federation.AutomaticRegistrationConfig {
	return federation.AutomaticRegistrationConfig{AllowedScopes: []string{"openid"}, MaxCacheAge: time.Hour}
}

func TestNewAutomaticClientRepositoryRejectsInvalidConfig(t *testing.T) {
	f := setupAutomaticRegistrationFixture(t, nil)
	resolver := f.newResolver(t)

	cases := map[string]func() (storage.ClientRepository, *federation.Resolver, federation.AutomaticRegistrationConfig, federation.Clock){
		"nil underlying": func() (storage.ClientRepository, *federation.Resolver, federation.AutomaticRegistrationConfig, federation.Clock) {
			return nil, resolver, validAutomaticRegistrationConfig(), fixedClock{now: f.now}
		},
		"nil resolver": func() (storage.ClientRepository, *federation.Resolver, federation.AutomaticRegistrationConfig, federation.Clock) {
			return alwaysFailsRepository{}, nil, validAutomaticRegistrationConfig(), fixedClock{now: f.now}
		},
		"empty allowed scopes": func() (storage.ClientRepository, *federation.Resolver, federation.AutomaticRegistrationConfig, federation.Clock) {
			cfg := validAutomaticRegistrationConfig()
			cfg.AllowedScopes = nil
			return alwaysFailsRepository{}, resolver, cfg, fixedClock{now: f.now}
		},
		"zero max cache age": func() (storage.ClientRepository, *federation.Resolver, federation.AutomaticRegistrationConfig, federation.Clock) {
			cfg := validAutomaticRegistrationConfig()
			cfg.MaxCacheAge = 0
			return alwaysFailsRepository{}, resolver, cfg, fixedClock{now: f.now}
		},
		"nil clock": func() (storage.ClientRepository, *federation.Resolver, federation.AutomaticRegistrationConfig, federation.Clock) {
			return alwaysFailsRepository{}, resolver, validAutomaticRegistrationConfig(), nil
		},
	}
	for name, build := range cases {
		t.Run(name, func(t *testing.T) {
			underlying, resolver, cfg, clock := build()
			if _, err := federation.NewAutomaticClientRepository(underlying, resolver, cfg, clock); err == nil {
				t.Fatalf("NewAutomaticClientRepository(%s) = nil error, want error", name)
			}
		})
	}
}

func TestAutomaticClientRepositoryResolveClientPrefersUnderlying(t *testing.T) {
	f := setupAutomaticRegistrationFixture(t, rpMetadataBuilder(t))
	resolver := f.newResolver(t)

	staticClient, err := storage.NewRegisteredClient(storage.RegisteredClientConfig{
		ID: fapi.ClientID(f.rpID), RedirectURIs: []fapi.RegisteredRedirectURI{fapi.RegisteredRedirectURI(f.rpID + "/static-cb")},
		ClientAuthMethod: storage.ClientAuthMethodPrivateKeyJWT, ClientAssertionAlgorithm: fapi.ES256,
		SenderConstrain: storage.SenderConstrainDPoP, AllowedScopes: []string{"openid"},
	})
	if err != nil {
		t.Fatalf("storage.NewRegisteredClient: %v", err)
	}

	repo, err := federation.NewAutomaticClientRepository(
		staticRepository{id: fapi.ClientID(f.rpID), client: staticClient}, resolver,
		validAutomaticRegistrationConfig(), fixedClock{now: f.now})
	if err != nil {
		t.Fatalf("NewAutomaticClientRepository: %v", err)
	}

	got, err := repo.ResolveClient(context.Background(), fapi.ClientID(f.rpID))
	if err != nil {
		t.Fatalf("ResolveClient: %v", err)
	}
	if !got.HasRedirectURI(f.rpID + "/static-cb") {
		t.Errorf("ResolveClient returned a client without the statically registered redirect URI — federation resolution must not have shadowed it")
	}
	if atomic.LoadInt32(f.rpConfigCalls) != 0 {
		t.Errorf("RP's own well-known endpoint was fetched %d times, want 0 — underlying should have short-circuited federation resolution entirely", atomic.LoadInt32(f.rpConfigCalls))
	}
}

func TestAutomaticClientRepositoryResolveClientFallsBackToFederation(t *testing.T) {
	f := setupAutomaticRegistrationFixture(t, rpMetadataBuilder(t))
	resolver := f.newResolver(t)

	repo, err := federation.NewAutomaticClientRepository(alwaysFailsRepository{}, resolver, validAutomaticRegistrationConfig(), fixedClock{now: f.now})
	if err != nil {
		t.Fatalf("NewAutomaticClientRepository: %v", err)
	}

	got, err := repo.ResolveClient(context.Background(), fapi.ClientID(f.rpID))
	if err != nil {
		t.Fatalf("ResolveClient: %v", err)
	}
	if got.ID() != fapi.ClientID(f.rpID) {
		t.Errorf("ID() = %q, want %q", got.ID(), f.rpID)
	}
	if !got.HasRedirectURI(f.rpID + "/cb") {
		t.Errorf("ResolveClient returned a client missing the resolved redirect_uris")
	}
	if got.ClientAuthMethod() != storage.ClientAuthMethodPrivateKeyJWT {
		t.Errorf("ClientAuthMethod() = %v, want ClientAuthMethodPrivateKeyJWT", got.ClientAuthMethod())
	}
	if !got.AllowsScope("openid") {
		t.Errorf("AllowsScope(openid) = false, want true (from AutomaticRegistrationConfig.AllowedScopes)")
	}
}

func TestAutomaticClientRepositoryResolveClientRejectsNonEntityID(t *testing.T) {
	f := setupAutomaticRegistrationFixture(t, nil)
	resolver := f.newResolver(t)
	repo, err := federation.NewAutomaticClientRepository(alwaysFailsRepository{}, resolver, validAutomaticRegistrationConfig(), fixedClock{now: f.now})
	if err != nil {
		t.Fatalf("NewAutomaticClientRepository: %v", err)
	}
	if _, err := repo.ResolveClient(context.Background(), "not-a-url"); err == nil {
		t.Fatalf("ResolveClient(\"not-a-url\") = nil error, want error")
	}
}

func TestAutomaticClientRepositoryResolveClientRejectsMissingRelyingPartyMetadata(t *testing.T) {
	f := setupAutomaticRegistrationFixture(t, nil) // RP publishes no openid_relying_party metadata at all
	resolver := f.newResolver(t)
	repo, err := federation.NewAutomaticClientRepository(alwaysFailsRepository{}, resolver, validAutomaticRegistrationConfig(), fixedClock{now: f.now})
	if err != nil {
		t.Fatalf("NewAutomaticClientRepository: %v", err)
	}
	if _, err := repo.ResolveClient(context.Background(), fapi.ClientID(f.rpID)); err == nil {
		t.Fatalf("ResolveClient(no openid_relying_party metadata) = nil error, want error")
	}
}

func TestAutomaticClientRepositoryCachesAcrossCalls(t *testing.T) {
	f := setupAutomaticRegistrationFixture(t, rpMetadataBuilder(t))
	resolver := f.newResolver(t)
	repo, err := federation.NewAutomaticClientRepository(alwaysFailsRepository{}, resolver, validAutomaticRegistrationConfig(), fixedClock{now: f.now})
	if err != nil {
		t.Fatalf("NewAutomaticClientRepository: %v", err)
	}

	if _, err := repo.ResolveClient(context.Background(), fapi.ClientID(f.rpID)); err != nil {
		t.Fatalf("ResolveClient (1st): %v", err)
	}
	if _, err := repo.ResolveClient(context.Background(), fapi.ClientID(f.rpID)); err != nil {
		t.Fatalf("ResolveClient (2nd): %v", err)
	}
	if calls := atomic.LoadInt32(f.rpConfigCalls); calls != 1 {
		t.Errorf("RP's own well-known endpoint was fetched %d times across two ResolveClient calls within the cache window, want 1", calls)
	}
}

func TestAutomaticClientKeySourceResolvesFromRelyingPartyMetadataJWKS(t *testing.T) {
	f := setupAutomaticRegistrationFixture(t, rpMetadataBuilder(t))
	resolver := f.newResolver(t)
	repo, err := federation.NewAutomaticClientRepository(alwaysFailsRepository{}, resolver, validAutomaticRegistrationConfig(), fixedClock{now: f.now})
	if err != nil {
		t.Fatalf("NewAutomaticClientRepository: %v", err)
	}
	src, err := federation.NewAutomaticClientKeySource(alwaysFailsKeySource{}, repo)
	if err != nil {
		t.Fatalf("NewAutomaticClientKeySource: %v", err)
	}

	set, err := src.ResolveVerificationKeys(context.Background(), keys.ClientKeyRequest{
		ClientID: fapi.ClientID(f.rpID), Purpose: keys.ClientAssertionVerification,
		Algorithm: fapi.ES256, KeyID: "rp-oidc",
	})
	if err != nil {
		t.Fatalf("ResolveVerificationKeys: %v", err)
	}
	if len(set.Keys) != 1 {
		t.Fatalf("ResolveVerificationKeys returned %d keys, want 1", len(set.Keys))
	}
	pub, ok := set.Keys[0].PublicKey.(*ecdsa.PublicKey)
	if !ok || !pub.Equal(&f.rpOIDCKey.PublicKey) {
		t.Errorf("resolved key does not match the RP's own openid_relying_party jwks key (rpOIDCKey) — got a different key, possibly the federation entity key (rpFedKey) by mistake")
	}
}

func TestAutomaticClientKeySourcePrefersUnderlying(t *testing.T) {
	f := setupAutomaticRegistrationFixture(t, rpMetadataBuilder(t))
	resolver := f.newResolver(t)
	repo, err := federation.NewAutomaticClientRepository(alwaysFailsRepository{}, resolver, validAutomaticRegistrationConfig(), fixedClock{now: f.now})
	if err != nil {
		t.Fatalf("NewAutomaticClientRepository: %v", err)
	}

	underlyingKey := generateKey(t)
	underlying := staticKeySource{
		id: fapi.ClientID(f.rpID),
		keySet: keys.VerificationKeySet{Keys: []keys.VerificationKey{
			{KeyID: "static-kid", Algorithm: fapi.ES256, PublicKey: &underlyingKey.PublicKey},
		}},
	}
	src, err := federation.NewAutomaticClientKeySource(underlying, repo)
	if err != nil {
		t.Fatalf("NewAutomaticClientKeySource: %v", err)
	}

	set, err := src.ResolveVerificationKeys(context.Background(), keys.ClientKeyRequest{
		ClientID: fapi.ClientID(f.rpID), Purpose: keys.ClientAssertionVerification, Algorithm: fapi.ES256,
	})
	if err != nil {
		t.Fatalf("ResolveVerificationKeys: %v", err)
	}
	if len(set.Keys) != 1 || set.Keys[0].KeyID != "static-kid" {
		t.Errorf("ResolveVerificationKeys = %+v, want the underlying static key, unshadowed by federation resolution", set)
	}
	if atomic.LoadInt32(f.rpConfigCalls) != 0 {
		t.Errorf("RP's own well-known endpoint was fetched, want underlying to have short-circuited federation resolution entirely")
	}
}

func TestAutomaticClientRepositoryResolveClientRejectsUnreachableFederationEntity(t *testing.T) {
	f := setupAutomaticRegistrationFixture(t, nil)
	resolver := f.newResolver(t)
	repo, err := federation.NewAutomaticClientRepository(alwaysFailsRepository{}, resolver, validAutomaticRegistrationConfig(), fixedClock{now: f.now})
	if err != nil {
		t.Fatalf("NewAutomaticClientRepository: %v", err)
	}
	// A well-formed https Entity Identifier, but not one Resolve can
	// ever reach (unresolvable host) — exercises Resolver.Resolve's own
	// error path, distinct from the "not a valid Entity ID at all" case.
	if _, err := repo.ResolveClient(context.Background(), "https://nonexistent-rp-host.example.invalid"); err == nil {
		t.Fatalf("ResolveClient(unreachable federation entity) = nil error, want error")
	}
}

func TestAutomaticClientRepositoryResolveClientRejectsInvalidRelyingPartyMetadata(t *testing.T) {
	// RP publishes openid_relying_party metadata missing redirect_uris
	// — resolves successfully at the federation layer, but
	// registeredClientConfigFromMetadata itself must reject it.
	f := setupAutomaticRegistrationFixture(t, func(rpID string, rpOIDCKey *ecdsa.PrivateKey) json.RawMessage {
		raw, err := json.Marshal(map[string]any{
			"token_endpoint_auth_method":      "private_key_jwt",
			"token_endpoint_auth_signing_alg": "ES256",
			"jwks":                            json.RawMessage(jwksFor(t, "rp-oidc", rpOIDCKey)),
		})
		if err != nil {
			t.Fatalf("marshal openid_relying_party metadata: %v", err)
		}
		return raw
	})
	resolver := f.newResolver(t)
	repo, err := federation.NewAutomaticClientRepository(alwaysFailsRepository{}, resolver, validAutomaticRegistrationConfig(), fixedClock{now: f.now})
	if err != nil {
		t.Fatalf("NewAutomaticClientRepository: %v", err)
	}
	if _, err := repo.ResolveClient(context.Background(), fapi.ClientID(f.rpID)); err == nil {
		t.Fatalf("ResolveClient(openid_relying_party metadata missing redirect_uris) = nil error, want error")
	}
}

func TestAutomaticClientRepositoryResolveClientRejectsInvalidAllowedScope(t *testing.T) {
	f := setupAutomaticRegistrationFixture(t, rpMetadataBuilder(t))
	resolver := f.newResolver(t)
	cfg := validAutomaticRegistrationConfig()
	cfg.AllowedScopes = []string{""} // passes NewAutomaticClientRepository's own len()>0 check, but storage.NewRegisteredClient rejects an empty scope entry
	repo, err := federation.NewAutomaticClientRepository(alwaysFailsRepository{}, resolver, cfg, fixedClock{now: f.now})
	if err != nil {
		t.Fatalf("NewAutomaticClientRepository: %v", err)
	}
	if _, err := repo.ResolveClient(context.Background(), fapi.ClientID(f.rpID)); err == nil {
		t.Fatalf("ResolveClient(empty allowed scope entry) = nil error, want error")
	}
}

func TestAutomaticClientKeySourceRejectsUnresolvableClient(t *testing.T) {
	f := setupAutomaticRegistrationFixture(t, nil)
	resolver := f.newResolver(t)
	repo, err := federation.NewAutomaticClientRepository(alwaysFailsRepository{}, resolver, validAutomaticRegistrationConfig(), fixedClock{now: f.now})
	if err != nil {
		t.Fatalf("NewAutomaticClientRepository: %v", err)
	}
	src, err := federation.NewAutomaticClientKeySource(alwaysFailsKeySource{}, repo)
	if err != nil {
		t.Fatalf("NewAutomaticClientKeySource: %v", err)
	}
	if _, err := src.ResolveVerificationKeys(context.Background(), keys.ClientKeyRequest{ClientID: "not-a-url", Algorithm: fapi.ES256}); err == nil {
		t.Fatalf("ResolveVerificationKeys(unresolvable client) = nil error, want error")
	}
}

func TestAutomaticClientKeySourceRejectsMalformedResolvedJWKS(t *testing.T) {
	f := setupAutomaticRegistrationFixture(t, func(rpID string, rpOIDCKey *ecdsa.PrivateKey) json.RawMessage {
		raw, err := json.Marshal(map[string]any{
			"redirect_uris":                   []string{rpID + "/cb"},
			"token_endpoint_auth_method":      "private_key_jwt",
			"token_endpoint_auth_signing_alg": "ES256",
			"jwks":                            "not-a-jwk-set-object",
		})
		if err != nil {
			t.Fatalf("marshal openid_relying_party metadata: %v", err)
		}
		return raw
	})
	resolver := f.newResolver(t)
	repo, err := federation.NewAutomaticClientRepository(alwaysFailsRepository{}, resolver, validAutomaticRegistrationConfig(), fixedClock{now: f.now})
	if err != nil {
		t.Fatalf("NewAutomaticClientRepository: %v", err)
	}
	src, err := federation.NewAutomaticClientKeySource(alwaysFailsKeySource{}, repo)
	if err != nil {
		t.Fatalf("NewAutomaticClientKeySource: %v", err)
	}
	if _, err := src.ResolveVerificationKeys(context.Background(), keys.ClientKeyRequest{ClientID: fapi.ClientID(f.rpID), Algorithm: fapi.ES256}); err == nil {
		t.Fatalf("ResolveVerificationKeys(malformed resolved jwks) = nil error, want error")
	}
}

func TestAutomaticClientKeySourceSkipsCandidatesWithWrongAlgorithmOrKeyID(t *testing.T) {
	f := setupAutomaticRegistrationFixture(t, rpMetadataBuilder(t))
	resolver := f.newResolver(t)
	repo, err := federation.NewAutomaticClientRepository(alwaysFailsRepository{}, resolver, validAutomaticRegistrationConfig(), fixedClock{now: f.now})
	if err != nil {
		t.Fatalf("NewAutomaticClientRepository: %v", err)
	}
	src, err := federation.NewAutomaticClientKeySource(alwaysFailsKeySource{}, repo)
	if err != nil {
		t.Fatalf("NewAutomaticClientKeySource: %v", err)
	}

	// Wrong algorithm: the resolved key is ES256, requesting PS256
	// must match nothing.
	set, err := src.ResolveVerificationKeys(context.Background(), keys.ClientKeyRequest{
		ClientID: fapi.ClientID(f.rpID), Algorithm: fapi.PS256,
	})
	if err != nil {
		t.Fatalf("ResolveVerificationKeys(wrong algorithm): %v", err)
	}
	if len(set.Keys) != 0 {
		t.Errorf("ResolveVerificationKeys(wrong algorithm) = %d keys, want 0", len(set.Keys))
	}

	// Wrong kid: the resolved key's kid is "rp-oidc".
	set, err = src.ResolveVerificationKeys(context.Background(), keys.ClientKeyRequest{
		ClientID: fapi.ClientID(f.rpID), Algorithm: fapi.ES256, KeyID: "not-the-real-kid",
	})
	if err != nil {
		t.Fatalf("ResolveVerificationKeys(wrong kid): %v", err)
	}
	if len(set.Keys) != 0 {
		t.Errorf("ResolveVerificationKeys(wrong kid) = %d keys, want 0", len(set.Keys))
	}
}

func TestNewAutomaticClientKeySourceRejectsInvalidArguments(t *testing.T) {
	f := setupAutomaticRegistrationFixture(t, nil)
	resolver := f.newResolver(t)
	repo, err := federation.NewAutomaticClientRepository(alwaysFailsRepository{}, resolver, validAutomaticRegistrationConfig(), fixedClock{now: f.now})
	if err != nil {
		t.Fatalf("NewAutomaticClientRepository: %v", err)
	}
	if _, err := federation.NewAutomaticClientKeySource(nil, repo); err == nil {
		t.Fatalf("NewAutomaticClientKeySource(nil underlying) = nil error, want error")
	}
	if _, err := federation.NewAutomaticClientKeySource(alwaysFailsKeySource{}, nil); err == nil {
		t.Fatalf("NewAutomaticClientKeySource(nil repo) = nil error, want error")
	}
}
