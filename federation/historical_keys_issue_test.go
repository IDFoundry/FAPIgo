package federation_test

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/federation"
	"github.com/idfoundry/fapigo/internal/jose"
)

func validHistoricalKeysIssueDeps(t *testing.T) federation.HistoricalKeysIssueDependencies {
	t.Helper()
	key := generateKey(t)
	return federation.HistoricalKeysIssueDependencies{
		Signer: key, Algorithm: fapi.ES256, KeyID: "current-key",
		JWKS: jwksFor(t, "current-key", key), Clock: federation.SystemClock{},
	}
}

func TestNewHistoricalKeysIssuerRejectsInvalidConfig(t *testing.T) {
	cases := map[string]func(*federation.HistoricalKeysIssueConfig, *federation.HistoricalKeysIssueDependencies){
		"empty entity ID": func(c *federation.HistoricalKeysIssueConfig, _ *federation.HistoricalKeysIssueDependencies) {
			c.EntityID = ""
		},
		"non-https entity ID": func(c *federation.HistoricalKeysIssueConfig, _ *federation.HistoricalKeysIssueDependencies) {
			c.EntityID = "http://entity.example.org"
		},
		"empty additional reason": func(c *federation.HistoricalKeysIssueConfig, _ *federation.HistoricalKeysIssueDependencies) {
			c.AdditionalRevocationReasons = []federation.KeyRevocationReason{""}
		},
		"nil signer": func(_ *federation.HistoricalKeysIssueConfig, d *federation.HistoricalKeysIssueDependencies) {
			d.Signer = nil
		},
		"empty key id": func(_ *federation.HistoricalKeysIssueConfig, d *federation.HistoricalKeysIssueDependencies) {
			d.KeyID = ""
		},
		"nil clock": func(_ *federation.HistoricalKeysIssueConfig, d *federation.HistoricalKeysIssueDependencies) {
			d.Clock = nil
		},
		"malformed jwks": func(_ *federation.HistoricalKeysIssueConfig, d *federation.HistoricalKeysIssueDependencies) {
			d.JWKS = json.RawMessage(`{"keys":`)
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := federation.HistoricalKeysIssueConfig{EntityID: "https://entity.example.org"}
			deps := validHistoricalKeysIssueDeps(t)
			mutate(&cfg, &deps)
			if _, err := federation.NewHistoricalKeysIssuer(cfg, deps); err == nil {
				t.Fatalf("NewHistoricalKeysIssuer(%s) = nil error, want error", name)
			}
		})
	}
}

func TestHistoricalKeysIssuerResponseRejectsInvalidKeys(t *testing.T) {
	deps := validHistoricalKeysIssueDeps(t)
	currentKey := deps.Signer
	overlapKey := generateKey(t)
	// The entity still publishes overlapKey alongside its signing key, as
	// during a rotation's overlap window.
	deps.JWKS = jwksWith(t, map[string]crypto.PublicKey{"current-key": currentKey.Public(), "overlap-key": &overlapKey.PublicKey})
	issuer, err := federation.NewHistoricalKeysIssuer(federation.HistoricalKeysIssueConfig{
		EntityID:                    "https://entity.example.org",
		AdditionalRevocationReasons: []federation.KeyRevocationReason{"ceremony-aborted"},
	}, deps)
	if err != nil {
		t.Fatalf("NewHistoricalKeysIssuer: %v", err)
	}

	retired := generateKey(t)
	now := time.Now()
	valid := func() federation.HistoricalKeyParams {
		return federation.HistoricalKeyParams{
			KeyID: "old-key", Algorithm: fapi.ES256, PublicKey: &retired.PublicKey,
			IssuedAt: now.Add(-48 * time.Hour), ExpiresAt: now.Add(-time.Hour),
		}
	}
	if _, err := issuer.Response([]federation.HistoricalKeyParams{valid()}); err != nil {
		t.Fatalf("Response(valid) = %v", err)
	}
	federationReason := valid()
	federationReason.Revoked = &federation.KeyRevocation{RevokedAt: now, Reason: "ceremony-aborted"}
	if _, err := issuer.Response([]federation.HistoricalKeyParams{federationReason}); err != nil {
		t.Fatalf("Response(additional revocation reason) = %v", err)
	}

	cases := map[string]func(*federation.HistoricalKeyParams) []federation.HistoricalKeyParams{
		"no kid": func(k *federation.HistoricalKeyParams) []federation.HistoricalKeyParams { k.KeyID = ""; return nil },
		"no public key": func(k *federation.HistoricalKeyParams) []federation.HistoricalKeyParams {
			k.PublicKey = nil
			return nil
		},
		"private key": func(k *federation.HistoricalKeyParams) []federation.HistoricalKeyParams {
			k.PublicKey = retired
			return nil
		},
		"no exp": func(k *federation.HistoricalKeyParams) []federation.HistoricalKeyParams {
			k.ExpiresAt = time.Time{}
			return nil
		},
		"invalid alg": func(k *federation.HistoricalKeyParams) []federation.HistoricalKeyParams { k.Algorithm = 0; return nil },
		"wrong key type": func(k *federation.HistoricalKeyParams) []federation.HistoricalKeyParams {
			k.Algorithm = fapi.PS256
			return nil
		},
		"exp before iat": func(k *federation.HistoricalKeyParams) []federation.HistoricalKeyParams {
			k.ExpiresAt = k.IssuedAt.Add(-time.Second)
			return nil
		},
		"exp before nbf": func(k *federation.HistoricalKeyParams) []federation.HistoricalKeyParams {
			k.IssuedAt, k.NotBefore = time.Time{}, k.ExpiresAt.Add(time.Second)
			return nil
		},
		"revoked without revoked_at": func(k *federation.HistoricalKeyParams) []federation.HistoricalKeyParams {
			k.Revoked = &federation.KeyRevocation{Reason: federation.KeyRevocationReasonCompromised}
			return nil
		},
		"unknown revocation reason": func(k *federation.HistoricalKeyParams) []federation.HistoricalKeyParams {
			k.Revoked = &federation.KeyRevocation{RevokedAt: now, Reason: "Compromised"}
			return nil
		},
		"active signing kid": func(k *federation.HistoricalKeyParams) []federation.HistoricalKeyParams {
			k.KeyID = "current-key"
			return nil
		},
		"active signing key under another kid": func(k *federation.HistoricalKeyParams) []federation.HistoricalKeyParams {
			k.PublicKey = currentKey.Public()
			return nil
		},
		"kid still published in jwks": func(k *federation.HistoricalKeyParams) []federation.HistoricalKeyParams {
			k.KeyID = "overlap-key"
			return nil
		},
		"key still published in jwks": func(k *federation.HistoricalKeyParams) []federation.HistoricalKeyParams {
			k.PublicKey = &overlapKey.PublicKey
			return nil
		},
		"duplicate kid": func(k *federation.HistoricalKeyParams) []federation.HistoricalKeyParams {
			other := generateKey(t)
			dup := *k
			dup.PublicKey = &other.PublicKey
			return []federation.HistoricalKeyParams{*k, dup}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			k := valid()
			keys := mutate(&k)
			if keys == nil {
				keys = []federation.HistoricalKeyParams{k}
			}
			if _, err := issuer.Response(keys); err == nil {
				t.Fatalf("Response(%s) = nil error, want error", name)
			}
		})
	}
}

// TestHistoricalKeysIssuerRefusesSignerKeyWithoutJWKS covers the active
// signing key being refused even when Dependencies.JWKS is unset.
func TestHistoricalKeysIssuerRefusesSignerKeyWithoutJWKS(t *testing.T) {
	deps := validHistoricalKeysIssueDeps(t)
	deps.JWKS = nil
	issuer, err := federation.NewHistoricalKeysIssuer(federation.HistoricalKeysIssueConfig{EntityID: "https://entity.example.org"}, deps)
	if err != nil {
		t.Fatalf("NewHistoricalKeysIssuer: %v", err)
	}
	_, err = issuer.Response([]federation.HistoricalKeyParams{{
		KeyID: "renamed", Algorithm: fapi.ES256, PublicKey: deps.Signer.Public(), ExpiresAt: time.Now(),
	}})
	if err == nil || !strings.Contains(err.Error(), "active signing key") {
		t.Fatalf("Response(signer's key) = %v, want an active signing key error", err)
	}
}

// TestHistoricalKeysIssuerRoundTripsThroughFetchHistoricalKeys serves a
// HistoricalKeysIssuer's response with WriteHistoricalKeys from a
// self-anchored entity and fetches it back with
// Resolver.FetchHistoricalKeys, checking every member a key can carry
// survives, and that the retired key still verifies what it signed.
func TestHistoricalKeysIssuerRoundTripsThroughFetchHistoricalKeys(t *testing.T) {
	currentKey := generateKey(t)
	jwks := jwksFor(t, "current-key", currentKey)
	expiredKey := generateKey(t)
	_, compromisedKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	oldStatement, err := jose.Sign(compromisedKey, jose.Header{Algorithm: fapi.EdDSA, KeyID: "compromised-key"}, []byte(`{}`))
	if err != nil {
		t.Fatalf("jose.Sign: %v", err)
	}

	mux := http.NewServeMux()
	ts := httptest.NewTLSServer(mux)
	t.Cleanup(ts.Close)
	entityID := ts.URL
	now := time.Now().Truncate(time.Second)

	self, err := federation.NewSelfIssuer(federation.SelfIssueConfig{EntityID: entityID, Lifetime: time.Hour}, federation.SelfIssueDependencies{
		Signer: currentKey, Algorithm: fapi.ES256, KeyID: "current-key", JWKS: jwks, Clock: federation.SystemClock{},
	})
	if err != nil {
		t.Fatalf("NewSelfIssuer: %v", err)
	}
	metadata := map[string]json.RawMessage{
		"federation_entity": json.RawMessage(`{"federation_historical_keys_endpoint":"` + entityID + `/historical-keys"}`),
	}
	ecToken, err := self.EntityConfiguration(metadata)
	if err != nil {
		t.Fatalf("EntityConfiguration: %v", err)
	}
	mux.HandleFunc(federation.WellKnownPath, func(w http.ResponseWriter, _ *http.Request) {
		federation.WriteEntityStatement(w, ecToken)
	})

	issuer, err := federation.NewHistoricalKeysIssuer(federation.HistoricalKeysIssueConfig{EntityID: entityID}, federation.HistoricalKeysIssueDependencies{
		Signer: currentKey, Algorithm: fapi.ES256, KeyID: "current-key", JWKS: jwks, Clock: fixedClock{now},
	})
	if err != nil {
		t.Fatalf("NewHistoricalKeysIssuer: %v", err)
	}
	token, err := issuer.Response([]federation.HistoricalKeyParams{
		{KeyID: "expired-key", Algorithm: fapi.ES256, PublicKey: &expiredKey.PublicKey, IssuedAt: now.Add(-48 * time.Hour), ExpiresAt: now.Add(-time.Hour)},
		{
			KeyID: "compromised-key", Algorithm: fapi.EdDSA, PublicKey: compromisedKey.Public(),
			ExpiresAt: now.Add(24 * time.Hour), NotBefore: now.Add(-72 * time.Hour),
			Revoked: &federation.KeyRevocation{RevokedAt: now.Add(-30 * time.Minute), Reason: federation.KeyRevocationReasonCompromised},
		},
	})
	if err != nil {
		t.Fatalf("Response: %v", err)
	}
	mux.HandleFunc("/historical-keys", func(w http.ResponseWriter, _ *http.Request) {
		federation.WriteHistoricalKeys(w, token)
	})

	resolver, err := federation.NewResolver(federation.Config{
		TrustAnchors: []federation.TrustAnchor{{EntityID: entityID, JWKS: jwks}},
		Limits:       federation.Limits{MaxPathLength: 5, MaxAuthorityHints: 5, MaxStatementLifetime: 2 * time.Hour, MaxClockSkew: 5 * time.Second},
	}, federation.Dependencies{HTTP: fetcherFor(t, ts), Clock: federation.SystemClock{}})
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	resolved, err := resolver.Resolve(context.Background(), entityID)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	var fedEntity struct {
		Endpoint string `json:"federation_historical_keys_endpoint"`
	}
	if err := json.Unmarshal(resolved.Metadata["federation_entity"], &fedEntity); err != nil {
		t.Fatalf("federation_entity metadata: %v", err)
	}

	claims, err := resolver.FetchHistoricalKeys(context.Background(), fedEntity.Endpoint, entityID)
	if err != nil {
		t.Fatalf("FetchHistoricalKeys: %v", err)
	}
	if claims.Issuer != entityID || !claims.IssuedAt.Equal(now) {
		t.Errorf("iss, iat = %q, %v; want %q, %v", claims.Issuer, claims.IssuedAt, entityID, now)
	}
	if len(claims.Keys) != 2 {
		t.Fatalf("len(Keys) = %d, want 2", len(claims.Keys))
	}
	checkExpiredHistoricalKey(t, claims.Keys[0], &expiredKey.PublicKey, now)
	checkCompromisedHistoricalKey(t, claims.Keys[1], oldStatement, now)
}

func checkExpiredHistoricalKey(t *testing.T, got federation.HistoricalKey, pub crypto.PublicKey, now time.Time) {
	t.Helper()
	if got.KeyID != "expired-key" || got.Algorithm != fapi.ES256 || !got.IssuedAt.Equal(now.Add(-48*time.Hour)) ||
		!got.ExpiresAt.Equal(now.Add(-time.Hour)) || got.Revoked != nil || !samePublic(pub, got.PublicKey) {
		t.Errorf("expired key = %+v", got)
	}
}

// checkCompromisedHistoricalKey also checks oldStatement, signed by the
// compromised key before it was retired, still verifies against the
// published entry.
func checkCompromisedHistoricalKey(t *testing.T, got federation.HistoricalKey, oldStatement string, now time.Time) {
	t.Helper()
	if got.KeyID != "compromised-key" || got.Algorithm != fapi.EdDSA || !got.NotBefore.Equal(now.Add(-72*time.Hour)) {
		t.Errorf("compromised key = %+v", got)
	}
	if got.Revoked == nil || got.Revoked.Reason != federation.KeyRevocationReasonCompromised || !got.Revoked.RevokedAt.Equal(now.Add(-30*time.Minute)) {
		t.Errorf("compromised key revoked = %+v", got.Revoked)
	}
	parsed, err := jose.ParseCompact(oldStatement)
	if err != nil {
		t.Fatalf("ParseCompact: %v", err)
	}
	if err := parsed.Verify(got.PublicKey, got.Algorithm); err != nil {
		t.Errorf("old statement doesn't verify against its published historical key: %v", err)
	}
}

func samePublic(a, b crypto.PublicKey) bool {
	eq, ok := a.(interface{ Equal(crypto.PublicKey) bool })
	return ok && eq.Equal(b)
}

func TestWriteHistoricalKeys(t *testing.T) {
	rec := httptest.NewRecorder()
	federation.WriteHistoricalKeys(rec, "a.b.c")
	if got := rec.Header().Get("Content-Type"); got != federation.HistoricalKeysContentType {
		t.Errorf("Content-Type = %q, want %q", got, federation.HistoricalKeysContentType)
	}
	if rec.Code != http.StatusOK || rec.Body.String() != "a.b.c" {
		t.Errorf("response = %d %q", rec.Code, rec.Body.String())
	}
}

// jwksWith builds a JWK Set JSON object of ES256 keys, one per kid.
func jwksWith(t *testing.T, keys map[string]crypto.PublicKey) json.RawMessage {
	t.Helper()
	entries := make([]json.RawMessage, 0, len(keys))
	for kid, pub := range keys {
		jwk, err := jose.NewJWK(pub, fapi.ES256)
		if err != nil {
			t.Fatalf("NewJWK: %v", err)
		}
		raw, err := jwk.WithKeyID(kid).MarshalJSON()
		if err != nil {
			t.Fatalf("MarshalJSON: %v", err)
		}
		entries = append(entries, raw)
	}
	out, err := json.Marshal(map[string][]json.RawMessage{"keys": entries})
	if err != nil {
		t.Fatalf("marshal jwks: %v", err)
	}
	return out
}
