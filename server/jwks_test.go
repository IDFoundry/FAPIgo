package server_test

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
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
		Keys:         km,
		AccessTokens: server.JWTAccessTokens{Keys: km, Algorithm: fapi.ES256},
		Revocation:   server.NoRevocation{},
		Clock:        fixedClock{now: time.Now()},
		Random:       rand.Reader,
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

func TestPublicJWKSRejectsEmptyKeyID(t *testing.T) {
	srv := newServerWithKeyManager(t, server.ProfileFAPISecurity, &fakeKeyManager{key: generateKey(t), keyID: ""})

	if _, err := srv.PublicJWKS(context.Background()); err == nil {
		t.Fatalf("PublicJWKS(empty kid) = nil error, want error")
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

func TestPublicJWKSPropagatesKeyManagerError(t *testing.T) {
	srv := newServerWithKeyManager(t, server.ProfileFAPISecurity, erroringKeyManager{})

	if _, err := srv.PublicJWKS(context.Background()); err == nil {
		t.Fatalf("PublicJWKS(erroring key manager) = nil error, want error")
	}
}
