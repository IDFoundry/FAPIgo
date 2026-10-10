package server_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
)

// newServerWithKeyManager builds a fresh server using km as its signing
// key manager, for tests that need a KeyManager behavior newHarness's
// fixed fakeKeyManager doesn't provide.
func newServerWithKeyManager(t *testing.T, profile server.Profile, km keys.KeyManager) *server.Server {
	t.Helper()
	clientKey := generateKey(t)
	client, err := storage.NewRegisteredClient(storage.RegisteredClientConfig{
		ID:                       testClientID,
		RedirectURIs:             []fapi.RegisteredRedirectURI{testRedirectURI},
		ClientAssertionAlgorithm: fapi.ES256,
		RequestObjectAlgorithm:   fapi.ES256,
		AllowedScopes:            []string{"openid", "accounts", "offline_access"},
	})
	if err != nil {
		t.Fatalf("NewRegisteredClient: %v", err)
	}
	issuer, err := fapi.ParseIssuerURL(testIssuer)
	if err != nil {
		t.Fatalf("ParseIssuerURL: %v", err)
	}

	cfg := server.Config{
		Issuer:    issuer,
		Endpoints: testEndpoints(t),
		Profile:   profile,
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
			MaxIDTokenClaimsBytes:      4096,
			RefreshTokenLifetime:       5 * time.Minute,
			MaxDPoPProofAge:            time.Minute,
			MaxClockSkew:               5 * time.Second,
		},
		Assurance: server.AssuranceDevelopment,
	}
	deps := server.Dependencies{
		Clients:      &fakeClientRepository{clients: map[fapi.ClientID]storage.RegisteredClient{testClientID: client}},
		Transactions: &fakeTransactionStore{},
		Grants:       &fakeGrantStore{},
		Replay:       &fakeReplayStore{},
		ClientKeys: &fakeClientKeySource{keysByClient: map[fapi.ClientID][]keys.VerificationKey{
			testClientID: {{Algorithm: fapi.ES256, PublicKey: &clientKey.PublicKey}},
		}},
		Keys:                   km,
		AccessTokens:           server.JWTAccessTokens{Keys: km, Algorithm: fapi.ES256},
		Revocation:             server.NoRevocation{},
		ClientCertificateTrust: server.NoClientCertificateChainTrust{},
		Clock:                  fixedClock{now: time.Now()},
		Random:                 rand.Reader,
	}
	srv, err := server.New(cfg, deps)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	return srv
}

func TestPublicJWKSSecurityProfile(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)

	set, err := h.server.PublicJWKS(context.Background())
	if err != nil {
		t.Fatalf("PublicJWKS: %v", err)
	}
	// fakeKeyManager returns the same key/kid regardless of purpose, so
	// AccessTokenSigning and IDTokenSigning dedupe into one entry.
	if len(set.Keys) != 1 {
		t.Fatalf("len(Keys) = %d, want 1", len(set.Keys))
	}
	if set.Keys[0].KeyID() != "as-key-1" {
		t.Fatalf("KeyID() = %q, want %q", set.Keys[0].KeyID(), "as-key-1")
	}
}

func TestPublicJWKSMessageSigningProfileStillDedupes(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurityWithMessageSigning, true)

	set, err := h.server.PublicJWKS(context.Background())
	if err != nil {
		t.Fatalf("PublicJWKS: %v", err)
	}
	// JARMSigning also resolves to the same fake key, so this profile
	// (which activates three purposes instead of two) still dedupes to
	// a single entry.
	if len(set.Keys) != 1 {
		t.Fatalf("len(Keys) = %d, want 1", len(set.Keys))
	}
}

func TestPublicJWKSMarshalsToValidJWKSJSON(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	set, err := h.server.PublicJWKS(context.Background())
	if err != nil {
		t.Fatalf("PublicJWKS: %v", err)
	}

	data, err := json.Marshal(set)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	var decoded struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if len(decoded.Keys) != 1 {
		t.Fatalf("len(decoded.Keys) = %d, want 1", len(decoded.Keys))
	}
	key := decoded.Keys[0]
	if key["kty"] != "EC" {
		t.Fatalf("kty = %v, want EC", key["kty"])
	}
	if key["crv"] != "P-256" {
		t.Fatalf("crv = %v, want P-256", key["crv"])
	}
	if key["kid"] != "as-key-1" {
		t.Fatalf("kid = %v, want as-key-1", key["kid"])
	}
	if key["x"] == "" || key["y"] == "" {
		t.Fatalf("key missing x/y coordinates: %v", key)
	}
	// A public JWKS must never carry private key material.
	if _, ok := key["d"]; ok {
		t.Fatalf("published JWK contains private key material: %v", key)
	}
}

// multiKeyManager returns a distinct key per SigningPurpose, to exercise
// PublicJWKS's union-across-purposes behavior (as opposed to dedup).
type multiKeyManager struct {
	byPurpose map[keys.SigningPurpose]*fakeKeyManager
}

func (m *multiKeyManager) Sign(ctx context.Context, req keys.SigningRequest) (keys.Signature, error) {
	return m.byPurpose[req.Purpose].Sign(ctx, req)
}

func (m *multiKeyManager) PublicKey(ctx context.Context, purpose keys.SigningPurpose, algorithm fapi.SignatureAlgorithm) (keys.PublicKeyInfo, error) {
	return m.byPurpose[purpose].PublicKey(ctx, purpose, algorithm)
}

func TestPublicJWKSReturnsDistinctKeysPerPurpose(t *testing.T) {
	km := &multiKeyManager{byPurpose: map[keys.SigningPurpose]*fakeKeyManager{
		keys.AccessTokenSigning: {key: generateKey(t), keyID: "access-key"},
		keys.IDTokenSigning:     {key: generateKey(t), keyID: "id-key"},
		keys.JARMSigning:        {key: generateKey(t), keyID: "jarm-key"},
	}}
	srv := newServerWithKeyManager(t, server.ProfileFAPISecurityWithMessageSigning, km)

	set, err := srv.PublicJWKS(context.Background())
	if err != nil {
		t.Fatalf("PublicJWKS: %v", err)
	}
	if len(set.Keys) != 3 {
		t.Fatalf("len(Keys) = %d, want 3", len(set.Keys))
	}
	seen := map[string]bool{}
	for _, k := range set.Keys {
		seen[k.KeyID()] = true
	}
	for _, want := range []string{"access-key", "id-key", "jarm-key"} {
		if !seen[want] {
			t.Fatalf("Keys missing kid %q; got %v", want, seen)
		}
	}
}

// TestPublicJWKSIncludesUserInfoSigningKeyWhenConfigured confirms
// PublicJWKS resolves and publishes a UserInfoSigning key once
// Config.Algorithms.UserInfo is set — using multiKeyManager (distinct
// kid per purpose) so a missing/wrong-purpose lookup would show up as a
// missing kid, not silently dedupe away.
// TestPublicJWKSOAuthOnlyOmitsIDTokenSigningKey confirms PublicJWKS
// never even resolves an IDTokenSigning key under Config.OAuthOnly — km
// has no keys.IDTokenSigning entry at all, so multiKeyManager.PublicKey
// would panic on a nil *fakeKeyManager if PublicJWKS asked for one
// anyway; a real deployment running OAuthOnly has no reason to
// provision that key purpose in its own KeyManager at all.
func TestPublicJWKSOAuthOnlyOmitsIDTokenSigningKey(t *testing.T) {
	km := &multiKeyManager{byPurpose: map[keys.SigningPurpose]*fakeKeyManager{
		keys.AccessTokenSigning: {key: generateKey(t), keyID: "access-key"},
	}}

	clientKey := generateKey(t)
	client, err := storage.NewRegisteredClient(storage.RegisteredClientConfig{
		ID:                       testClientID,
		RedirectURIs:             []fapi.RegisteredRedirectURI{testRedirectURI},
		ClientAssertionAlgorithm: fapi.ES256,
		AllowedScopes:            []string{"accounts", "offline_access"},
	})
	if err != nil {
		t.Fatalf("NewRegisteredClient: %v", err)
	}
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
		},
		Limits: server.Limits{
			PushedRequestLifetime:      90 * time.Second,
			MaxClientAssertionLifetime: time.Minute,
			MaxRequestObjectLifetime:   time.Minute,
			InteractionLifetime:        5 * time.Minute,
			AuthorizationCodeLifetime:  time.Minute,
			AccessTokenLifetime:        5 * time.Minute,
			RefreshTokenLifetime:       5 * time.Minute,
			MaxDPoPProofAge:            time.Minute,
			MaxClockSkew:               5 * time.Second,
		},
		Assurance: server.AssuranceDevelopment,
		OAuthOnly: true,
	}
	deps := server.Dependencies{
		Clients:      &fakeClientRepository{clients: map[fapi.ClientID]storage.RegisteredClient{testClientID: client}},
		Transactions: &fakeTransactionStore{},
		Grants:       &fakeGrantStore{},
		Replay:       &fakeReplayStore{},
		ClientKeys: &fakeClientKeySource{keysByClient: map[fapi.ClientID][]keys.VerificationKey{
			testClientID: {{Algorithm: fapi.ES256, PublicKey: &clientKey.PublicKey}},
		}},
		Keys:                   km,
		AccessTokens:           server.JWTAccessTokens{Keys: km, Algorithm: fapi.ES256},
		Revocation:             server.NoRevocation{},
		ClientCertificateTrust: server.NoClientCertificateChainTrust{},
		Clock:                  fixedClock{now: time.Now()},
		Random:                 rand.Reader,
	}
	srv, err := server.New(cfg, deps)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}

	set, err := srv.PublicJWKS(context.Background())
	if err != nil {
		t.Fatalf("PublicJWKS: %v", err)
	}
	if len(set.Keys) != 1 || set.Keys[0].KeyID() != "access-key" {
		t.Fatalf("Keys = %v, want exactly [access-key]", set.Keys)
	}
}

func TestPublicJWKSIncludesUserInfoSigningKeyWhenConfigured(t *testing.T) {
	km := &multiKeyManager{byPurpose: map[keys.SigningPurpose]*fakeKeyManager{
		keys.AccessTokenSigning: {key: generateKey(t), keyID: "access-key"},
		keys.IDTokenSigning:     {key: generateKey(t), keyID: "id-key"},
		keys.UserInfoSigning:    {key: generateKey(t), keyID: "userinfo-key"},
	}}
	srv := newServerWithKeyManagerAndUserInfo(t, server.ProfileFAPISecurity, km, fapi.ES256)

	set, err := srv.PublicJWKS(context.Background())
	if err != nil {
		t.Fatalf("PublicJWKS: %v", err)
	}
	seen := map[string]bool{}
	for _, k := range set.Keys {
		seen[k.KeyID()] = true
	}
	if !seen["userinfo-key"] {
		t.Fatalf("Keys missing kid %q; got %v", "userinfo-key", seen)
	}
	if !seen["id-key"] {
		t.Fatalf("Keys missing kid %q; got %v", "id-key", seen)
	}
}

// TestPublicJWKSOmitsUserInfoSigningKeyWhenNotConfigured is the negative
// counterpart of TestPublicJWKSIncludesUserInfoSigningKeyWhenConfigured:
// with Algorithms.UserInfo left zero, PublicJWKS must never resolve (or
// publish) a UserInfoSigning key at all.
func TestPublicJWKSOmitsUserInfoSigningKeyWhenNotConfigured(t *testing.T) {
	km := &multiKeyManager{byPurpose: map[keys.SigningPurpose]*fakeKeyManager{
		keys.AccessTokenSigning: {key: generateKey(t), keyID: "access-key"},
		keys.IDTokenSigning:     {key: generateKey(t), keyID: "id-key"},
	}}
	srv := newServerWithKeyManagerAndUserInfo(t, server.ProfileFAPISecurity, km, 0)

	set, err := srv.PublicJWKS(context.Background())
	if err != nil {
		t.Fatalf("PublicJWKS: %v", err)
	}
	for _, k := range set.Keys {
		if k.KeyID() == "userinfo-key" {
			t.Fatalf("PublicJWKS published a userinfo-key with UserInfo signing unconfigured")
		}
	}
}

// newServerWithKeyManagerAndUserInfo mirrors newServerWithKeyManager but
// additionally sets Algorithms.UserInfo, for tests that need
// PublicJWKS's UserInfoSigning branch active.
func newServerWithKeyManagerAndUserInfo(t *testing.T, profile server.Profile, km keys.KeyManager, userInfo fapi.SignatureAlgorithm) *server.Server {
	t.Helper()
	clientKey := generateKey(t)
	client, err := storage.NewRegisteredClient(storage.RegisteredClientConfig{
		ID:                       testClientID,
		RedirectURIs:             []fapi.RegisteredRedirectURI{testRedirectURI},
		ClientAssertionAlgorithm: fapi.ES256,
		RequestObjectAlgorithm:   fapi.ES256,
		AllowedScopes:            []string{"openid", "accounts", "offline_access"},
	})
	if err != nil {
		t.Fatalf("NewRegisteredClient: %v", err)
	}
	issuer, err := fapi.ParseIssuerURL(testIssuer)
	if err != nil {
		t.Fatalf("ParseIssuerURL: %v", err)
	}

	cfg := server.Config{
		Issuer:    issuer,
		Endpoints: testEndpoints(t),
		Profile:   profile,
		Algorithms: server.AlgorithmPolicy{
			ClientAssertion: server.AlgorithmSet{fapi.ES256},
			RequestObject:   server.AlgorithmSet{fapi.ES256},
			JARM:            fapi.ES256,
			IDToken:         fapi.ES256,
			UserInfo:        userInfo,
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
			MaxIDTokenClaimsBytes:      4096,
			RefreshTokenLifetime:       5 * time.Minute,
			MaxDPoPProofAge:            time.Minute,
			MaxClockSkew:               5 * time.Second,
		},
		Assurance: server.AssuranceDevelopment,
	}
	deps := server.Dependencies{
		Clients:      &fakeClientRepository{clients: map[fapi.ClientID]storage.RegisteredClient{testClientID: client}},
		Transactions: &fakeTransactionStore{},
		Grants:       &fakeGrantStore{},
		Replay:       &fakeReplayStore{},
		ClientKeys: &fakeClientKeySource{keysByClient: map[fapi.ClientID][]keys.VerificationKey{
			testClientID: {{Algorithm: fapi.ES256, PublicKey: &clientKey.PublicKey}},
		}},
		Keys:                   km,
		AccessTokens:           server.JWTAccessTokens{Keys: km, Algorithm: fapi.ES256},
		Revocation:             server.NoRevocation{},
		ClientCertificateTrust: server.NoClientCertificateChainTrust{},
		Clock:                  fixedClock{now: time.Now()},
		Random:                 rand.Reader,
	}
	srv, err := server.New(cfg, deps)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	return srv
}

// TestNewRejectsEmptyKeyID: a key published with an empty kid would make
// /jwks fail, so New refuses it, naming the purpose and algorithm.
func TestNewRejectsEmptyKeyID(t *testing.T) {
	deps := validDependencies()
	deps.Keys = &fakeKeyManager{key: generateKey(t), keyID: ""}

	_, err := server.New(validConfig(t), deps)
	if err == nil || !strings.Contains(err.Error(), "keys has no usable id_token_signing key for ES256") || !strings.Contains(err.Error(), "empty kid") {
		t.Fatalf("New(empty kid) = %v, want it refused naming id_token_signing and ES256", err)
	}
}

// mismatchedKeyManager reports one key's public half but signs with
// another: a KMS whose key alias points somewhere else.
type mismatchedKeyManager struct {
	fakeKeyManager
	signingKey *ecdsa.PrivateKey
}

func (m *mismatchedKeyManager) Sign(ctx context.Context, req keys.SigningRequest) (keys.Signature, error) {
	inner := fakeKeyManager{key: m.signingKey, keyID: m.keyID}
	return inner.Sign(ctx, req)
}

// TestNewRejectsKeyThatSignsWithAnotherKey: New signs a probe with each
// key and verifies it, so a manager whose signatures don't match the
// public key it publishes fails at startup, not at every relying party.
func TestNewRejectsKeyThatSignsWithAnotherKey(t *testing.T) {
	deps := validDependencies()
	deps.Keys = &mismatchedKeyManager{fakeKeyManager: fakeKeyManager{key: generateKey(t), keyID: "as-key-1"}, signingKey: generateKey(t)}

	_, err := server.New(validConfig(t), deps)
	if err == nil || !strings.Contains(err.Error(), "keys can't sign with its id_token_signing key for ES256") {
		t.Fatalf("New(mismatched signer) = %v, want it refused naming id_token_signing and ES256", err)
	}
}

// signFailingKeyManager publishes its key but can't sign with it: a
// KMS whose signing permission is missing.
type signFailingKeyManager struct{ fakeKeyManager }

func (m *signFailingKeyManager) Sign(context.Context, keys.SigningRequest) (keys.Signature, error) {
	return keys.Signature{}, errors.New("kms: access denied")
}

// TestNewRejectsKeyManagerThatCannotSign: New's probe signature fails,
// so a key that can be published but not used fails at startup.
func TestNewRejectsKeyManagerThatCannotSign(t *testing.T) {
	deps := validDependencies()
	deps.Keys = &signFailingKeyManager{fakeKeyManager{key: generateKey(t), keyID: "as-key-1"}}

	_, err := server.New(validConfig(t), deps)
	if err == nil || !strings.Contains(err.Error(), "keys can't sign with its id_token_signing key for ES256") || !strings.Contains(err.Error(), "access denied") {
		t.Fatalf("New(signer that fails) = %v, want it refused naming id_token_signing, ES256 and the cause", err)
	}
}

// rotatingKeyManager is a keys.RotatingKeyManager fake: Sign/PublicKey
// always use the newest key (as a real rotation would — new signatures
// never use an outgoing key), but PublicKeys publishes both, proving
// PublicJWKS takes the wider set rather than falling back to the
// single-key path when it's available.
type rotatingKeyManager struct {
	outgoing, newest *fakeKeyManager
}

func (m *rotatingKeyManager) Sign(ctx context.Context, req keys.SigningRequest) (keys.Signature, error) {
	return m.newest.Sign(ctx, req)
}

func (m *rotatingKeyManager) PublicKey(ctx context.Context, purpose keys.SigningPurpose, algorithm fapi.SignatureAlgorithm) (keys.PublicKeyInfo, error) {
	return m.newest.PublicKey(ctx, purpose, algorithm)
}

func (m *rotatingKeyManager) PublicKeys(ctx context.Context, purpose keys.SigningPurpose, algorithm fapi.SignatureAlgorithm) (keys.SigningKeySet, error) {
	outgoing, err := m.outgoing.PublicKey(ctx, purpose, algorithm)
	if err != nil {
		return keys.SigningKeySet{}, err
	}
	newest, err := m.newest.PublicKey(ctx, purpose, algorithm)
	if err != nil {
		return keys.SigningKeySet{}, err
	}
	return keys.SigningKeySet{Keys: []keys.PublicKeyInfo{outgoing, newest}}, nil
}

// TestPublicJWKSPublishesRotatingKeySet confirms PublicJWKS prefers
// RotatingKeyManager.PublicKeys over the single-key PublicKey path when
// the configured manager implements it, so both the outgoing and the
// newest key stay published during a rotation's overlap window.
func TestPublicJWKSPublishesRotatingKeySet(t *testing.T) {
	km := &rotatingKeyManager{
		outgoing: &fakeKeyManager{key: generateKey(t), keyID: "outgoing-key"},
		newest:   &fakeKeyManager{key: generateKey(t), keyID: "newest-key"},
	}
	srv := newServerWithKeyManager(t, server.ProfileFAPISecurity, km)

	set, err := srv.PublicJWKS(context.Background())
	if err != nil {
		t.Fatalf("PublicJWKS: %v", err)
	}
	if len(set.Keys) != 2 {
		t.Fatalf("len(Keys) = %d, want 2 (outgoing + newest)", len(set.Keys))
	}
	seen := map[string]bool{}
	for _, k := range set.Keys {
		seen[k.KeyID()] = true
	}
	for _, want := range []string{"outgoing-key", "newest-key"} {
		if !seen[want] {
			t.Fatalf("Keys missing kid %q; got %v", want, seen)
		}
	}
}

// TestPublicJWKSRotatingKeySetStillDedupes confirms the existing
// dedup-by-kid behavior still applies when a RotatingKeyManager's
// PublicKeys happens to return the same kid across purposes (or the
// outgoing/newest keys happen to collide, though that would be an
// unusual rotation).
func TestPublicJWKSRotatingKeySetStillDedupes(t *testing.T) {
	shared := &fakeKeyManager{key: generateKey(t), keyID: "shared-key"}
	km := &rotatingKeyManager{outgoing: shared, newest: shared}
	srv := newServerWithKeyManager(t, server.ProfileFAPISecurity, km)

	set, err := srv.PublicJWKS(context.Background())
	if err != nil {
		t.Fatalf("PublicJWKS: %v", err)
	}
	if len(set.Keys) != 1 {
		t.Fatalf("len(Keys) = %d, want 1 (outgoing == newest, plus cross-purpose dedup)", len(set.Keys))
	}
}

type erroringKeyManager struct{}

func (erroringKeyManager) Sign(context.Context, keys.SigningRequest) (keys.Signature, error) {
	return keys.Signature{}, errKeyManagerUnavailable
}

func (erroringKeyManager) PublicKey(context.Context, keys.SigningPurpose, fapi.SignatureAlgorithm) (keys.PublicKeyInfo, error) {
	return keys.PublicKeyInfo{}, errKeyManagerUnavailable
}

var errKeyManagerUnavailable = errors.New("key manager unavailable")

func TestNewRejectsErroringKeyManager(t *testing.T) {
	deps := validDependencies()
	deps.Keys = erroringKeyManager{}

	if _, err := server.New(validConfig(t), deps); err == nil {
		t.Fatalf("New(erroring key manager) = nil error, want error")
	}
}

// TestNewChecksSigningKeysAtStartup: a KeyManager missing a purpose the
// configuration needs, or holding a key that doesn't suit the configured
// algorithm, or two managers publishing different keys under one kid,
// is refused by New — each used to surface as a server_error at the
// first token request, or a failing /jwks.
func TestNewChecksSigningKeysAtStartup(t *testing.T) {
	es256, err := keys.NewKeyManagerFromSigners([]keys.SignerSpec{
		{Purpose: keys.AccessTokenSigning, Algorithm: fapi.ES256, Signer: generateKey(t), KeyID: "at-1"},
	})
	if err != nil {
		t.Fatalf("NewKeyManagerFromSigners: %v", err)
	}
	for name, tc := range map[string]struct {
		mutate func(*server.Config, *server.Dependencies)
		want   string
	}{
		"no id token key": {
			func(_ *server.Config, d *server.Dependencies) { d.Keys = es256 },
			"keys has no usable id_token_signing key for ES256",
		},
		"access tokens over a key of another algorithm": {
			func(_ *server.Config, d *server.Dependencies) {
				d.AccessTokens = server.JWTAccessTokens{Keys: newTestKeyManager(), Algorithm: fapi.PS256}
			},
			"access_tokens keys has no usable access_token_signing key for PS256",
		},
		"one kid for two keys across managers": {
			func(_ *server.Config, d *server.Dependencies) {
				d.AccessTokens = server.JWTAccessTokens{Keys: &fakeKeyManager{key: generateKey(t), keyID: "as-key-1"}, Algorithm: fapi.ES256}
			},
			`kid "as-key-1" names two different keys`,
		},
		"jarm under message signing": {
			func(c *server.Config, d *server.Dependencies) {
				c.Profile = server.ProfileFAPISecurityWithMessageSigning
				c.Algorithms.JARM = fapi.PS256
				c.Limits.JARMResponseLifetime = time.Minute
			},
			"keys has no usable jarm_signing key for PS256",
		},
		"userinfo signing": {
			func(c *server.Config, d *server.Dependencies) { c.Algorithms.UserInfo = fapi.EdDSA },
			"keys has no usable userinfo_signing key for EdDSA",
		},
	} {
		t.Run(name, func(t *testing.T) {
			cfg, deps := validConfig(t), validDependencies()
			tc.mutate(&cfg, &deps)
			if _, err := server.New(cfg, deps); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("New = %v, want an error containing %q", err, tc.want)
			}
		})
	}

	t.Run("OAuthOnly needs no id token key", func(t *testing.T) {
		cfg, deps := validConfig(t), validDependencies()
		cfg.OAuthOnly = true
		deps.Keys = es256
		deps.AccessTokens = server.JWTAccessTokens{Keys: es256, Algorithm: fapi.ES256}
		if _, err := server.New(cfg, deps); err != nil {
			t.Fatalf("New(OAuthOnly, no id token key) = %v, want nil", err)
		}
	})
}
