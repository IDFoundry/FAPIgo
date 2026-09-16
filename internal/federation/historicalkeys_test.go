package federation

import (
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/jose"
)

func createHistoricalKeysToken(t *testing.T, key *ecdsa.PrivateKey, kid, typ string, claims map[string]any) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	token, err := jose.Sign(key, jose.Header{Algorithm: fapi.ES256, Type: typ, KeyID: kid}, payload)
	if err != nil {
		t.Fatalf("jose.Sign: %v", err)
	}
	return token
}

func historicalKeyJWKMap(t *testing.T, kid string, pub *ecdsa.PublicKey, extra map[string]any) map[string]any {
	t.Helper()
	jwk, err := jose.NewJWK(pub, fapi.ES256)
	if err != nil {
		t.Fatalf("jose.NewJWK: %v", err)
	}
	raw, err := jwk.WithKeyID(kid).MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal jwk: %v", err)
	}
	for k, v := range extra {
		m[k] = v
	}
	return m
}

func validHistoricalKeysClaims(t *testing.T, now time.Time, historicalKey *ecdsa.PrivateKey) map[string]any {
	return map[string]any{
		"iss": "https://entity.example.org",
		"iat": now.Unix(),
		"keys": []map[string]any{
			historicalKeyJWKMap(t, "old-key", &historicalKey.PublicKey, map[string]any{
				"exp": now.Add(-time.Hour).Unix(),
			}),
		},
	}
}

func historicalKeysVerifyPolicy(now time.Time) HistoricalKeysVerifyPolicy {
	return HistoricalKeysVerifyPolicy{
		ExpectedIssuer: "https://entity.example.org", Algorithm: fapi.ES256, Now: now,
	}
}

func TestParseHistoricalKeysResponseAndVerifyRoundTrip(t *testing.T) {
	signingKey := generateKey(t)
	historicalKey := generateKey(t)
	now := time.Now()
	token := createHistoricalKeysToken(t, signingKey, "current-key", historicalKeysJWTType, validHistoricalKeysClaims(t, now, historicalKey))

	r, err := ParseHistoricalKeysResponse(token)
	if err != nil {
		t.Fatalf("ParseHistoricalKeysResponse: %v", err)
	}
	if r.ClaimedIssuer() != "https://entity.example.org" {
		t.Errorf("ClaimedIssuer() = %q", r.ClaimedIssuer())
	}
	if r.KeyID() != "current-key" {
		t.Errorf("KeyID() = %q", r.KeyID())
	}
	if r.Algorithm() != fapi.ES256 {
		t.Errorf("Algorithm() = %v", r.Algorithm())
	}

	claims, err := r.Verify(&signingKey.PublicKey, historicalKeysVerifyPolicy(now.Add(time.Second)))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if len(claims.Keys) != 1 {
		t.Fatalf("len(Keys) = %d, want 1", len(claims.Keys))
	}
	got := claims.Keys[0]
	if got.KeyID != "old-key" {
		t.Errorf("Keys[0].KeyID = %q", got.KeyID)
	}
	if got.Algorithm != fapi.ES256 {
		t.Errorf("Keys[0].Algorithm = %v", got.Algorithm)
	}
	if got.ExpiresAt.IsZero() || got.ExpiresAt.After(now) {
		t.Errorf("Keys[0].ExpiresAt = %v, want in the past", got.ExpiresAt)
	}
	if got.Revoked != nil {
		t.Errorf("Keys[0].Revoked = %+v, want nil", got.Revoked)
	}
}

func TestParseHistoricalKeysResponseParsesRevokedKey(t *testing.T) {
	signingKey := generateKey(t)
	historicalKey := generateKey(t)
	now := time.Now()
	claims := map[string]any{
		"iss": "https://entity.example.org",
		"iat": now.Unix(),
		"keys": []map[string]any{
			historicalKeyJWKMap(t, "compromised-key", &historicalKey.PublicKey, map[string]any{
				"iat": now.Add(-48 * time.Hour).Unix(),
				"exp": now.Add(-24 * time.Hour).Unix(),
				"revoked": map[string]any{
					"revoked_at": now.Add(-36 * time.Hour).Unix(),
					"reason":     "compromised",
				},
			}),
		},
	}
	token := createHistoricalKeysToken(t, signingKey, "current-key", historicalKeysJWTType, claims)

	r, err := ParseHistoricalKeysResponse(token)
	if err != nil {
		t.Fatalf("ParseHistoricalKeysResponse: %v", err)
	}
	got, err := r.Verify(&signingKey.PublicKey, historicalKeysVerifyPolicy(now.Add(time.Second)))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if len(got.Keys) != 1 {
		t.Fatalf("len(Keys) = %d, want 1", len(got.Keys))
	}
	key := got.Keys[0]
	if key.IssuedAt.IsZero() {
		t.Errorf("IssuedAt is zero, want set")
	}
	if key.Revoked == nil {
		t.Fatalf("Revoked is nil, want set")
	}
	if key.Revoked.Reason != KeyRevocationReasonCompromised {
		t.Errorf("Revoked.Reason = %q, want compromised", key.Revoked.Reason)
	}
	if key.Revoked.RevokedAt.IsZero() {
		t.Errorf("Revoked.RevokedAt is zero, want set")
	}
}

func TestParseHistoricalKeysResponseSkipsEntryMissingExp(t *testing.T) {
	signingKey := generateKey(t)
	goodKey := generateKey(t)
	badKey := generateKey(t)
	now := time.Now()
	claims := map[string]any{
		"iss": "https://entity.example.org",
		"iat": now.Unix(),
		"keys": []map[string]any{
			historicalKeyJWKMap(t, "no-exp", &badKey.PublicKey, nil),
			historicalKeyJWKMap(t, "good", &goodKey.PublicKey, map[string]any{"exp": now.Add(-time.Hour).Unix()}),
		},
	}
	token := createHistoricalKeysToken(t, signingKey, "current-key", historicalKeysJWTType, claims)

	r, err := ParseHistoricalKeysResponse(token)
	if err != nil {
		t.Fatalf("ParseHistoricalKeysResponse: %v", err)
	}
	got, err := r.Verify(&signingKey.PublicKey, historicalKeysVerifyPolicy(now.Add(time.Second)))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if len(got.Keys) != 1 || got.Keys[0].KeyID != "good" {
		t.Fatalf("Keys = %+v, want only the entry with exp set", got.Keys)
	}
}

func TestParseHistoricalKeysResponseSkipsUnsupportedJWKEntry(t *testing.T) {
	signingKey := generateKey(t)
	goodKey := generateKey(t)
	now := time.Now()
	claims := map[string]any{
		"iss": "https://entity.example.org",
		"iat": now.Unix(),
		"keys": []map[string]any{
			{"kty": "unsupported-key-type", "kid": "bad", "exp": now.Add(-time.Hour).Unix()},
			historicalKeyJWKMap(t, "good", &goodKey.PublicKey, map[string]any{"exp": now.Add(-time.Hour).Unix()}),
		},
	}
	token := createHistoricalKeysToken(t, signingKey, "current-key", historicalKeysJWTType, claims)

	r, err := ParseHistoricalKeysResponse(token)
	if err != nil {
		t.Fatalf("ParseHistoricalKeysResponse: %v", err)
	}
	got, err := r.Verify(&signingKey.PublicKey, historicalKeysVerifyPolicy(now.Add(time.Second)))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if len(got.Keys) != 1 || got.Keys[0].KeyID != "good" {
		t.Fatalf("Keys = %+v, want only the supported entry", got.Keys)
	}
}

func TestParseHistoricalKeysResponseRejectsWrongType(t *testing.T) {
	signingKey := generateKey(t)
	historicalKey := generateKey(t)
	now := time.Now()
	token := createHistoricalKeysToken(t, signingKey, "current-key", "some-other+jwt", validHistoricalKeysClaims(t, now, historicalKey))
	if _, err := ParseHistoricalKeysResponse(token); !errors.Is(err, ErrHistoricalKeysWrongType) {
		t.Fatalf("ParseHistoricalKeysResponse(wrong typ) = %v, want ErrHistoricalKeysWrongType", err)
	}
}

func TestParseHistoricalKeysResponseRejectsMalformedCompact(t *testing.T) {
	if _, err := ParseHistoricalKeysResponse("not-a-jws-at-all"); err == nil {
		t.Fatalf("ParseHistoricalKeysResponse(garbage) = nil error, want error")
	}
}

func TestParseHistoricalKeysResponseRejectsNonJSONPayload(t *testing.T) {
	key := generateKey(t)
	token, err := jose.Sign(key, jose.Header{Algorithm: fapi.ES256, Type: historicalKeysJWTType}, []byte("not json"))
	if err != nil {
		t.Fatalf("jose.Sign: %v", err)
	}
	if _, err := ParseHistoricalKeysResponse(token); !errors.Is(err, ErrMalformedClaims) {
		t.Fatalf("ParseHistoricalKeysResponse(non-JSON payload) = %v, want ErrMalformedClaims", err)
	}
}

func TestParseHistoricalKeysResponseRejectsMissingRequiredClaims(t *testing.T) {
	signingKey := generateKey(t)
	historicalKey := generateKey(t)
	now := time.Now()
	for _, field := range []string{"iss", "iat", "keys"} {
		t.Run(field, func(t *testing.T) {
			claims := validHistoricalKeysClaims(t, now, historicalKey)
			delete(claims, field)
			token := createHistoricalKeysToken(t, signingKey, "current-key", historicalKeysJWTType, claims)
			if _, err := ParseHistoricalKeysResponse(token); !errors.Is(err, ErrMalformedClaims) {
				t.Fatalf("ParseHistoricalKeysResponse(missing %s) = %v, want ErrMalformedClaims", field, err)
			}
		})
	}
}

func TestHistoricalKeysVerifyRejectsWrongKey(t *testing.T) {
	signingKey := generateKey(t)
	otherKey := generateKey(t)
	historicalKey := generateKey(t)
	now := time.Now()
	token := createHistoricalKeysToken(t, signingKey, "current-key", historicalKeysJWTType, validHistoricalKeysClaims(t, now, historicalKey))
	r, err := ParseHistoricalKeysResponse(token)
	if err != nil {
		t.Fatalf("ParseHistoricalKeysResponse: %v", err)
	}
	if _, err := r.Verify(&otherKey.PublicKey, historicalKeysVerifyPolicy(now.Add(time.Second))); err == nil {
		t.Fatal("Verify(wrong key) = nil error, want error")
	}
}

func TestHistoricalKeysVerifyRejectsMissingPolicyFields(t *testing.T) {
	signingKey := generateKey(t)
	historicalKey := generateKey(t)
	now := time.Now()
	token := createHistoricalKeysToken(t, signingKey, "current-key", historicalKeysJWTType, validHistoricalKeysClaims(t, now, historicalKey))
	r, err := ParseHistoricalKeysResponse(token)
	if err != nil {
		t.Fatalf("ParseHistoricalKeysResponse: %v", err)
	}
	cases := map[string]func(*HistoricalKeysVerifyPolicy){
		"no expected issuer": func(p *HistoricalKeysVerifyPolicy) { p.ExpectedIssuer = "" },
		"zero now":           func(p *HistoricalKeysVerifyPolicy) { p.Now = time.Time{} },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			policy := historicalKeysVerifyPolicy(now.Add(time.Second))
			mutate(&policy)
			if _, err := r.Verify(&signingKey.PublicKey, policy); err == nil {
				t.Fatalf("Verify(%s) = nil error, want error", name)
			}
		})
	}
}

func TestHistoricalKeysVerifyRejectsIssuerMismatch(t *testing.T) {
	signingKey := generateKey(t)
	historicalKey := generateKey(t)
	now := time.Now()
	token := createHistoricalKeysToken(t, signingKey, "current-key", historicalKeysJWTType, validHistoricalKeysClaims(t, now, historicalKey))
	r, err := ParseHistoricalKeysResponse(token)
	if err != nil {
		t.Fatalf("ParseHistoricalKeysResponse: %v", err)
	}
	policy := historicalKeysVerifyPolicy(now.Add(time.Second))
	policy.ExpectedIssuer = "https://someone-else.example.org"
	if _, err := r.Verify(&signingKey.PublicKey, policy); !errors.Is(err, ErrHistoricalKeysIssuerMismatch) {
		t.Fatalf("Verify(issuer mismatch) = %v, want ErrHistoricalKeysIssuerMismatch", err)
	}
}

func TestHistoricalKeysVerifyRejectsNotYetValid(t *testing.T) {
	signingKey := generateKey(t)
	historicalKey := generateKey(t)
	now := time.Now()
	token := createHistoricalKeysToken(t, signingKey, "current-key", historicalKeysJWTType, validHistoricalKeysClaims(t, now.Add(time.Hour), historicalKey))
	r, err := ParseHistoricalKeysResponse(token)
	if err != nil {
		t.Fatalf("ParseHistoricalKeysResponse: %v", err)
	}
	if _, err := r.Verify(&signingKey.PublicKey, historicalKeysVerifyPolicy(now)); !errors.Is(err, ErrHistoricalKeysNotYetValid) {
		t.Fatalf("Verify(not yet valid) = %v, want ErrHistoricalKeysNotYetValid", err)
	}
}

func TestCreateHistoricalKeysResponseRoundTrip(t *testing.T) {
	signingKey := generateKey(t)
	historicalKey := generateKey(t)
	now := time.Now()
	token, err := CreateHistoricalKeysResponse(CreateHistoricalKeysResponseParams{
		Signer: signingKey, Algorithm: fapi.ES256, KeyID: "current-key",
		Issuer: "https://entity.example.org", Now: now,
		Keys: []HistoricalKeyParams{
			{
				KeyID: "old-key", Algorithm: fapi.ES256, PublicKey: &historicalKey.PublicKey,
				IssuedAt: now.Add(-48 * time.Hour), ExpiresAt: now.Add(-time.Hour), NotBefore: now.Add(-48 * time.Hour),
				Revoked: &KeyRevocation{RevokedAt: now.Add(-2 * time.Hour), Reason: KeyRevocationReasonSuperseded},
			},
		},
	})
	if err != nil {
		t.Fatalf("CreateHistoricalKeysResponse: %v", err)
	}

	r, err := ParseHistoricalKeysResponse(token)
	if err != nil {
		t.Fatalf("ParseHistoricalKeysResponse: %v", err)
	}
	claims, err := r.Verify(&signingKey.PublicKey, historicalKeysVerifyPolicy(now.Add(time.Second)))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if len(claims.Keys) != 1 {
		t.Fatalf("len(Keys) = %d, want 1", len(claims.Keys))
	}
	key := claims.Keys[0]
	if key.KeyID != "old-key" {
		t.Errorf("KeyID = %q", key.KeyID)
	}
	if key.IssuedAt.IsZero() || key.NotBefore.IsZero() {
		t.Errorf("IssuedAt/NotBefore not round-tripped: %+v", key)
	}
	if key.Revoked == nil || key.Revoked.Reason != KeyRevocationReasonSuperseded {
		t.Errorf("Revoked = %+v, want superseded", key.Revoked)
	}
}

func TestCreateHistoricalKeysResponseRejectsMissingFields(t *testing.T) {
	signingKey := generateKey(t)
	historicalKey := generateKey(t)
	now := time.Now()
	validKey := func() HistoricalKeyParams {
		return HistoricalKeyParams{KeyID: "old-key", Algorithm: fapi.ES256, PublicKey: &historicalKey.PublicKey, ExpiresAt: now.Add(-time.Hour)}
	}
	base := func() CreateHistoricalKeysResponseParams {
		return CreateHistoricalKeysResponseParams{
			Signer: signingKey, Algorithm: fapi.ES256, KeyID: "current-key",
			Issuer: "https://entity.example.org", Now: now, Keys: []HistoricalKeyParams{validKey()},
		}
	}
	cases := map[string]func(*CreateHistoricalKeysResponseParams){
		"no signer":   func(p *CreateHistoricalKeysResponseParams) { p.Signer = nil },
		"invalid alg": func(p *CreateHistoricalKeysResponseParams) { p.Algorithm = 0 },
		"no key id":   func(p *CreateHistoricalKeysResponseParams) { p.KeyID = "" },
		"no issuer":   func(p *CreateHistoricalKeysResponseParams) { p.Issuer = "" },
		"zero now":    func(p *CreateHistoricalKeysResponseParams) { p.Now = time.Time{} },
		"no keys":     func(p *CreateHistoricalKeysResponseParams) { p.Keys = nil },
		"key: no key id": func(p *CreateHistoricalKeysResponseParams) {
			k := validKey()
			k.KeyID = ""
			p.Keys = []HistoricalKeyParams{k}
		},
		"key: invalid alg": func(p *CreateHistoricalKeysResponseParams) {
			k := validKey()
			k.Algorithm = 0
			p.Keys = []HistoricalKeyParams{k}
		},
		"key: no public key": func(p *CreateHistoricalKeysResponseParams) {
			k := validKey()
			k.PublicKey = nil
			p.Keys = []HistoricalKeyParams{k}
		},
		"key: zero exp": func(p *CreateHistoricalKeysResponseParams) {
			k := validKey()
			k.ExpiresAt = time.Time{}
			p.Keys = []HistoricalKeyParams{k}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			p := base()
			mutate(&p)
			if _, err := CreateHistoricalKeysResponse(p); err == nil {
				t.Fatalf("CreateHistoricalKeysResponse(%s) = nil error, want error", name)
			}
		})
	}
}
