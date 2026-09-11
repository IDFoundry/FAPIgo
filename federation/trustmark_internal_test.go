package federation

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	intfed "github.com/idfoundry/fapigo/internal/federation"
	"github.com/idfoundry/fapigo/internal/jose"
)

func generateTestKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return key
}

func testKeyJWKS(t *testing.T, kid string, key *ecdsa.PrivateKey, alg fapi.SignatureAlgorithm) json.RawMessage {
	t.Helper()
	jwk, err := jose.NewJWK(&key.PublicKey, alg)
	if err != nil {
		t.Fatalf("jose.NewJWK: %v", err)
	}
	jwkJSON, err := jwk.WithKeyID(kid).MarshalJSON()
	if err != nil {
		t.Fatalf("marshal jwk: %v", err)
	}
	return jwkJSON
}

func testRSAJWKS(t *testing.T, kid string) json.RawMessage {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	jwk, err := jose.NewJWK(&key.PublicKey, fapi.PS256)
	if err != nil {
		t.Fatalf("jose.NewJWK: %v", err)
	}
	jwkJSON, err := jwk.WithKeyID(kid).MarshalJSON()
	if err != nil {
		t.Fatalf("marshal jwk: %v", err)
	}
	return jwkJSON
}

func jwkSetOf(t *testing.T, jwks ...json.RawMessage) json.RawMessage {
	t.Helper()
	set, err := json.Marshal(map[string][]json.RawMessage{"keys": jwks})
	if err != nil {
		t.Fatalf("marshal jwk set: %v", err)
	}
	return set
}

func signTestTrustMark(t *testing.T, key *ecdsa.PrivateKey, kid string, claims map[string]any) intfed.TrustMark {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	token, err := jose.Sign(key, jose.Header{Algorithm: fapi.ES256, Type: "trust-mark+jwt", KeyID: kid}, payload)
	if err != nil {
		t.Fatalf("jose.Sign: %v", err)
	}
	tm, err := intfed.ParseTrustMark(token)
	if err != nil {
		t.Fatalf("intfed.ParseTrustMark: %v", err)
	}
	return tm
}

type fixedTestClock struct{ now time.Time }

func (c fixedTestClock) Now() time.Time { return c.now }

func testResolver() *Resolver {
	return &Resolver{
		cfg:  Config{Limits: Limits{MaxClockSkew: 5 * time.Second}},
		deps: Dependencies{Clock: fixedTestClock{now: time.Now()}},
	}
}

func signTestTrustMarkDelegation(t *testing.T, key *ecdsa.PrivateKey, kid string, claims map[string]any) intfed.TrustMarkDelegation {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	token, err := jose.Sign(key, jose.Header{Algorithm: fapi.ES256, Type: "trust-mark-delegation+jwt", KeyID: kid}, payload)
	if err != nil {
		t.Fatalf("jose.Sign: %v", err)
	}
	d, err := intfed.ParseTrustMarkDelegation(token)
	if err != nil {
		t.Fatalf("intfed.ParseTrustMarkDelegation: %v", err)
	}
	return d
}

func TestVerifyTrustMarkAgainstJWKSRejectsMalformedJWKS(t *testing.T) {
	key := generateTestKey(t)
	tm := signTestTrustMark(t, key, "issuer-kid", map[string]any{
		"iss": "https://issuer.example.org", "sub": "https://rp.example.org",
		"trust_mark_type": "https://federation.example.org/marks/certified",
		"iat":             time.Now().Unix(),
	})
	if _, err := testResolver().verifyTrustMarkAgainstJWKS(tm, json.RawMessage(`not json`), "https://rp.example.org", "https://federation.example.org/marks/certified", fapi.ES256, time.Now()); err == nil {
		t.Fatalf("verifyTrustMarkAgainstJWKS(malformed jwks) = nil error, want error")
	}
}

func TestVerifyTrustMarkAgainstJWKSSkipsWrongAlgorithm(t *testing.T) {
	rsaJWKS := testRSAJWKS(t, "rsa-kid")
	esKey := generateTestKey(t)
	esJWKS := testKeyJWKS(t, "es-kid", esKey, fapi.ES256)
	jwks := jwkSetOf(t, rsaJWKS, esJWKS)

	now := time.Now()
	tm := signTestTrustMark(t, esKey, "es-kid", map[string]any{
		"iss": "https://issuer.example.org", "sub": "https://rp.example.org",
		"trust_mark_type": "https://federation.example.org/marks/certified",
		"iat":             now.Unix(),
	})

	claims, err := testResolver().verifyTrustMarkAgainstJWKS(tm, jwks, "https://rp.example.org", "https://federation.example.org/marks/certified", fapi.ES256, now)
	if err != nil {
		t.Fatalf("verifyTrustMarkAgainstJWKS: %v", err)
	}
	if claims.Issuer != "https://issuer.example.org" {
		t.Errorf("claims.Issuer = %q", claims.Issuer)
	}
}

func TestVerifyTrustMarkAgainstJWKSSkipsWrongKeyID(t *testing.T) {
	otherKey := generateTestKey(t)
	otherJWKS := testKeyJWKS(t, "other-kid", otherKey, fapi.ES256)
	key := generateTestKey(t)
	matchingJWKS := testKeyJWKS(t, "issuer-kid", key, fapi.ES256)
	jwks := jwkSetOf(t, otherJWKS, matchingJWKS)

	now := time.Now()
	tm := signTestTrustMark(t, key, "issuer-kid", map[string]any{
		"iss": "https://issuer.example.org", "sub": "https://rp.example.org",
		"trust_mark_type": "https://federation.example.org/marks/certified",
		"iat":             now.Unix(),
	})

	claims, err := testResolver().verifyTrustMarkAgainstJWKS(tm, jwks, "https://rp.example.org", "https://federation.example.org/marks/certified", fapi.ES256, now)
	if err != nil {
		t.Fatalf("verifyTrustMarkAgainstJWKS: %v", err)
	}
	if claims.Subject != "https://rp.example.org" {
		t.Errorf("claims.Subject = %q", claims.Subject)
	}
}

func TestVerifyTrustMarkAgainstJWKSRejectsNoMatchingCandidate(t *testing.T) {
	otherKey := generateTestKey(t)
	otherJWKS := testKeyJWKS(t, "other-kid", otherKey, fapi.ES256)
	jwks := jwkSetOf(t, otherJWKS)

	key := generateTestKey(t)
	now := time.Now()
	tm := signTestTrustMark(t, key, "issuer-kid", map[string]any{
		"iss": "https://issuer.example.org", "sub": "https://rp.example.org",
		"trust_mark_type": "https://federation.example.org/marks/certified",
		"iat":             now.Unix(),
	})

	if _, err := testResolver().verifyTrustMarkAgainstJWKS(tm, jwks, "https://rp.example.org", "https://federation.example.org/marks/certified", fapi.ES256, now); err == nil {
		t.Fatalf("verifyTrustMarkAgainstJWKS(no matching kid) = nil error, want error")
	}
}

func TestCheckTrustMarkDelegationRejectsUnresolvableTrustAnchor(t *testing.T) {
	tm := signTestTrustMark(t, generateTestKey(t), "issuer-kid", map[string]any{
		"iss": "https://issuer.example.org", "sub": "https://rp.example.org",
		"trust_mark_type": "https://federation.example.org/marks/certified",
		"iat":             time.Now().Unix(),
	})
	claims := intfed.TrustMarkClaims{TrustMarkType: "https://federation.example.org/marks/certified"}
	if err := testResolver().checkTrustMarkDelegation(context.Background(), "not-a-valid-entity-id", tm, claims); err == nil {
		t.Fatalf("checkTrustMarkDelegation(unresolvable trust anchor) = nil error, want error")
	}
}

func TestVerifyTrustMarkDelegationAgainstJWKSRejectsMalformedJWKS(t *testing.T) {
	key := generateTestKey(t)
	d := signTestTrustMarkDelegation(t, key, "owner-kid", map[string]any{
		"iss": "https://owner.example.org", "sub": "https://issuer.example.org",
		"trust_mark_type": "https://federation.example.org/marks/certified",
		"iat":             time.Now().Unix(),
	})
	if _, err := testResolver().verifyTrustMarkDelegationAgainstJWKS(d, json.RawMessage(`not json`), "https://owner.example.org", "https://issuer.example.org", "https://federation.example.org/marks/certified", fapi.ES256, time.Now()); err == nil {
		t.Fatalf("verifyTrustMarkDelegationAgainstJWKS(malformed jwks) = nil error, want error")
	}
}

func TestVerifyTrustMarkDelegationAgainstJWKSSkipsWrongAlgorithm(t *testing.T) {
	rsaJWKS := testRSAJWKS(t, "rsa-kid")
	esKey := generateTestKey(t)
	esJWKS := testKeyJWKS(t, "es-kid", esKey, fapi.ES256)
	jwks := jwkSetOf(t, rsaJWKS, esJWKS)

	now := time.Now()
	d := signTestTrustMarkDelegation(t, esKey, "es-kid", map[string]any{
		"iss": "https://owner.example.org", "sub": "https://issuer.example.org",
		"trust_mark_type": "https://federation.example.org/marks/certified",
		"iat":             now.Unix(),
	})

	claims, err := testResolver().verifyTrustMarkDelegationAgainstJWKS(d, jwks, "https://owner.example.org", "https://issuer.example.org", "https://federation.example.org/marks/certified", fapi.ES256, now)
	if err != nil {
		t.Fatalf("verifyTrustMarkDelegationAgainstJWKS: %v", err)
	}
	if claims.Issuer != "https://owner.example.org" {
		t.Errorf("claims.Issuer = %q", claims.Issuer)
	}
}

func TestVerifyTrustMarkDelegationAgainstJWKSSkipsWrongKeyID(t *testing.T) {
	otherKey := generateTestKey(t)
	otherJWKS := testKeyJWKS(t, "other-kid", otherKey, fapi.ES256)
	key := generateTestKey(t)
	matchingJWKS := testKeyJWKS(t, "owner-kid", key, fapi.ES256)
	jwks := jwkSetOf(t, otherJWKS, matchingJWKS)

	now := time.Now()
	d := signTestTrustMarkDelegation(t, key, "owner-kid", map[string]any{
		"iss": "https://owner.example.org", "sub": "https://issuer.example.org",
		"trust_mark_type": "https://federation.example.org/marks/certified",
		"iat":             now.Unix(),
	})

	claims, err := testResolver().verifyTrustMarkDelegationAgainstJWKS(d, jwks, "https://owner.example.org", "https://issuer.example.org", "https://federation.example.org/marks/certified", fapi.ES256, now)
	if err != nil {
		t.Fatalf("verifyTrustMarkDelegationAgainstJWKS: %v", err)
	}
	if claims.Subject != "https://issuer.example.org" {
		t.Errorf("claims.Subject = %q", claims.Subject)
	}
}

func TestVerifyTrustMarkDelegationAgainstJWKSRejectsNoMatchingCandidate(t *testing.T) {
	otherKey := generateTestKey(t)
	otherJWKS := testKeyJWKS(t, "other-kid", otherKey, fapi.ES256)
	jwks := jwkSetOf(t, otherJWKS)

	key := generateTestKey(t)
	now := time.Now()
	d := signTestTrustMarkDelegation(t, key, "owner-kid", map[string]any{
		"iss": "https://owner.example.org", "sub": "https://issuer.example.org",
		"trust_mark_type": "https://federation.example.org/marks/certified",
		"iat":             now.Unix(),
	})

	if _, err := testResolver().verifyTrustMarkDelegationAgainstJWKS(d, jwks, "https://owner.example.org", "https://issuer.example.org", "https://federation.example.org/marks/certified", fapi.ES256, now); err == nil {
		t.Fatalf("verifyTrustMarkDelegationAgainstJWKS(no matching kid) = nil error, want error")
	}
}
