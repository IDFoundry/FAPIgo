package clientattestation

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/jose"
)

func generateKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return key
}

func confirmationJWK(t *testing.T, pub *ecdsa.PublicKey) []byte {
	t.Helper()
	jwk, err := jose.NewJWK(pub, fapi.ES256)
	if err != nil {
		t.Fatalf("NewJWK: %v", err)
	}
	raw, err := jwk.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}
	return raw
}

type attestationClaimsInput struct {
	Issuer    string
	Subject   string
	ExpiresAt int64
	IssuedAt  int64
	NotBefore int64
	CNFJWK    []byte
}

func createTestAttestation(t *testing.T, signer *ecdsa.PrivateKey, in attestationClaimsInput) string {
	t.Helper()
	payload := map[string]any{
		"iss": in.Issuer,
		"sub": in.Subject,
		"exp": in.ExpiresAt,
	}
	if in.IssuedAt != 0 {
		payload["iat"] = in.IssuedAt
	}
	if in.NotBefore != 0 {
		payload["nbf"] = in.NotBefore
	}
	var jwk json.RawMessage = in.CNFJWK
	payload["cnf"] = map[string]any{"jwk": jwk}

	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	compact, err := jose.Sign(signer, jose.Header{Algorithm: fapi.ES256, Type: TypHeader}, raw)
	if err != nil {
		t.Fatalf("jose.Sign: %v", err)
	}
	return compact
}

type popClaimsInput struct {
	Issuer    string
	Audience  string
	JTI       string
	IssuedAt  int64
	Challenge string
	NotBefore int64
}

func createTestPoP(t *testing.T, signer *ecdsa.PrivateKey, in popClaimsInput) string {
	t.Helper()
	payload := map[string]any{
		"iss": in.Issuer,
		"aud": in.Audience,
		"jti": in.JTI,
		"iat": in.IssuedAt,
	}
	if in.Challenge != "" {
		payload["challenge"] = in.Challenge
	}
	if in.NotBefore != 0 {
		payload["nbf"] = in.NotBefore
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	compact, err := jose.Sign(signer, jose.Header{Algorithm: fapi.ES256, Type: PoPTypHeader}, raw)
	if err != nil {
		t.Fatalf("jose.Sign: %v", err)
	}
	return compact
}

// TestParseAttestation_Draft07Example reproduces draft-07 §5.1's own
// worked example claims set (not the signature, which the draft's
// illustrative example doesn't make independently verifiable — see
// clientattestation_test.go's package comment) to confirm this
// package's claims parsing matches the spec's own field values exactly.
func TestParseAttestation_Draft07Example(t *testing.T) {
	key := generateKey(t)
	jwk := confirmationJWK(t, &key.PublicKey)
	attestation := createTestAttestation(t, key, attestationClaimsInput{
		Issuer:    "https://attester.example.com",
		Subject:   "https://client.example.com",
		NotBefore: 1300815780,
		ExpiresAt: 1300819380,
		CNFJWK:    jwk,
	})

	parsed, err := Parse(attestation)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if parsed.ClaimedIssuer() != "https://attester.example.com" {
		t.Errorf("ClaimedIssuer = %q", parsed.ClaimedIssuer())
	}
	if parsed.ClaimedSubject() != "https://client.example.com" {
		t.Errorf("ClaimedSubject = %q", parsed.ClaimedSubject())
	}
	if parsed.Algorithm() != fapi.ES256 {
		t.Errorf("Algorithm = %v", parsed.Algorithm())
	}
}

func TestAttestation_KeyID(t *testing.T) {
	key := generateKey(t)
	payload, err := json.Marshal(map[string]any{
		"iss": "https://attester.example.com", "sub": "https://client.example.com",
		"exp": time.Now().Add(time.Hour).Unix(),
		"cnf": map[string]any{"jwk": json.RawMessage(confirmationJWK(t, &key.PublicKey))},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	compact, err := jose.Sign(key, jose.Header{Algorithm: fapi.ES256, Type: TypHeader, KeyID: "attester-key-1"}, payload)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	parsed, err := Parse(compact)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if parsed.KeyID() != "attester-key-1" {
		t.Errorf("KeyID() = %q, want %q", parsed.KeyID(), "attester-key-1")
	}
}

func TestPoP_Accessors(t *testing.T) {
	clientKey := generateKey(t)
	pop := createTestPoP(t, clientKey, popClaimsInput{
		Issuer: "https://client.example.com", Audience: "https://as.example.com",
		JTI: "jti-1", IssuedAt: time.Now().Unix(),
	})
	parsed, err := ParsePoP(pop)
	if err != nil {
		t.Fatalf("ParsePoP: %v", err)
	}
	if parsed.Algorithm() != fapi.ES256 {
		t.Errorf("Algorithm() = %v, want ES256", parsed.Algorithm())
	}
	if parsed.ClaimedIssuer() != "https://client.example.com" {
		t.Errorf("ClaimedIssuer() = %q, want %q", parsed.ClaimedIssuer(), "https://client.example.com")
	}
}

func basePolicy(now time.Time) VerifyPolicy {
	return VerifyPolicy{
		ExpectedIssuer:  "https://attester.example.com",
		ExpectedSubject: "https://client.example.com",
		Algorithm:       fapi.ES256,
		Now:             now,
		MaxLifetime:     10 * time.Minute,
	}
}

func TestAttestation_VerifyRoundTrip(t *testing.T) {
	attesterKey := generateKey(t)
	clientKey := generateKey(t)
	now := time.Unix(1300816000, 0)

	attestation := createTestAttestation(t, attesterKey, attestationClaimsInput{
		Issuer:    "https://attester.example.com",
		Subject:   "https://client.example.com",
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(5 * time.Minute).Unix(),
		CNFJWK:    confirmationJWK(t, &clientKey.PublicKey),
	})

	parsed, err := Parse(attestation)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	verified, err := parsed.Verify(&attesterKey.PublicKey, basePolicy(now))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if verified.ClientID != "https://client.example.com" {
		t.Errorf("ClientID = %q", verified.ClientID)
	}

	var gotJWK, wantJWK map[string]any
	if err := json.Unmarshal(verified.ConfirmationJWK, &gotJWK); err != nil {
		t.Fatalf("unmarshal ConfirmationJWK: %v", err)
	}
	if err := json.Unmarshal(confirmationJWK(t, &clientKey.PublicKey), &wantJWK); err != nil {
		t.Fatalf("unmarshal expected JWK: %v", err)
	}
	if gotJWK["x"] != wantJWK["x"] || gotJWK["y"] != wantJWK["y"] {
		t.Errorf("ConfirmationJWK = %v, want %v", gotJWK, wantJWK)
	}
}

func TestAttestation_Verify_RejectsWrongAttesterKey(t *testing.T) {
	attesterKey := generateKey(t)
	otherKey := generateKey(t)
	clientKey := generateKey(t)
	now := time.Unix(1300816000, 0)

	attestation := createTestAttestation(t, attesterKey, attestationClaimsInput{
		Issuer: "https://attester.example.com", Subject: "https://client.example.com",
		ExpiresAt: now.Add(5 * time.Minute).Unix(), CNFJWK: confirmationJWK(t, &clientKey.PublicKey),
	})
	parsed, err := Parse(attestation)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if _, err := parsed.Verify(&otherKey.PublicKey, basePolicy(now)); err == nil {
		t.Errorf("Verify accepted a signature under the wrong Attester key")
	}
}

func TestAttestation_Verify_RejectsIssuerMismatch(t *testing.T) {
	attesterKey := generateKey(t)
	clientKey := generateKey(t)
	now := time.Unix(1300816000, 0)

	attestation := createTestAttestation(t, attesterKey, attestationClaimsInput{
		Issuer: "https://wrong-attester.example.com", Subject: "https://client.example.com",
		ExpiresAt: now.Add(5 * time.Minute).Unix(), CNFJWK: confirmationJWK(t, &clientKey.PublicKey),
	})
	parsed, err := Parse(attestation)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if _, err := parsed.Verify(&attesterKey.PublicKey, basePolicy(now)); err != ErrIssuerMismatch {
		t.Errorf("Verify error = %v, want ErrIssuerMismatch", err)
	}
}

func TestAttestation_Verify_RejectsSubjectMismatch(t *testing.T) {
	attesterKey := generateKey(t)
	clientKey := generateKey(t)
	now := time.Unix(1300816000, 0)

	attestation := createTestAttestation(t, attesterKey, attestationClaimsInput{
		Issuer: "https://attester.example.com", Subject: "https://someone-else.example.com",
		ExpiresAt: now.Add(5 * time.Minute).Unix(), CNFJWK: confirmationJWK(t, &clientKey.PublicKey),
	})
	parsed, err := Parse(attestation)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if _, err := parsed.Verify(&attesterKey.PublicKey, basePolicy(now)); err != ErrSubjectMismatch {
		t.Errorf("Verify error = %v, want ErrSubjectMismatch", err)
	}
}

func TestAttestation_Verify_RejectsExpired(t *testing.T) {
	attesterKey := generateKey(t)
	clientKey := generateKey(t)
	now := time.Unix(1300816000, 0)

	attestation := createTestAttestation(t, attesterKey, attestationClaimsInput{
		Issuer: "https://attester.example.com", Subject: "https://client.example.com",
		ExpiresAt: now.Add(-time.Minute).Unix(), CNFJWK: confirmationJWK(t, &clientKey.PublicKey),
	})
	parsed, err := Parse(attestation)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if _, err := parsed.Verify(&attesterKey.PublicKey, basePolicy(now)); err != ErrExpired {
		t.Errorf("Verify error = %v, want ErrExpired", err)
	}
}

func TestAttestation_Verify_RejectsLifetimeExceeded(t *testing.T) {
	attesterKey := generateKey(t)
	clientKey := generateKey(t)
	now := time.Unix(1300816000, 0)

	attestation := createTestAttestation(t, attesterKey, attestationClaimsInput{
		Issuer: "https://attester.example.com", Subject: "https://client.example.com",
		ExpiresAt: now.Add(time.Hour).Unix(), CNFJWK: confirmationJWK(t, &clientKey.PublicKey),
	})
	parsed, err := Parse(attestation)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	policy := basePolicy(now)
	policy.MaxLifetime = 10 * time.Minute
	if _, err := parsed.Verify(&attesterKey.PublicKey, policy); err != ErrLifetimeExceeded {
		t.Errorf("Verify error = %v, want ErrLifetimeExceeded", err)
	}
}

func TestParse_RejectsMalformedInput(t *testing.T) {
	if _, err := Parse("not-a-jwt"); err == nil {
		t.Errorf("Parse accepted a malformed compact JWS")
	}
}

func TestAttestation_Verify_RejectsIncompletePolicy(t *testing.T) {
	attesterKey := generateKey(t)
	clientKey := generateKey(t)
	now := time.Unix(1300816000, 0)
	attestation := createTestAttestation(t, attesterKey, attestationClaimsInput{
		Issuer: "https://attester.example.com", Subject: "https://client.example.com",
		ExpiresAt: now.Add(5 * time.Minute).Unix(), CNFJWK: confirmationJWK(t, &clientKey.PublicKey),
	})
	parsed, err := Parse(attestation)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	cases := []struct {
		name   string
		mutate func(VerifyPolicy) VerifyPolicy
	}{
		{"empty ExpectedIssuer", func(p VerifyPolicy) VerifyPolicy { p.ExpectedIssuer = ""; return p }},
		{"empty ExpectedSubject", func(p VerifyPolicy) VerifyPolicy { p.ExpectedSubject = ""; return p }},
		{"zero Now", func(p VerifyPolicy) VerifyPolicy { p.Now = time.Time{}; return p }},
		{"zero MaxLifetime", func(p VerifyPolicy) VerifyPolicy { p.MaxLifetime = 0; return p }},
	}
	for _, c := range cases {
		policy := c.mutate(basePolicy(now))
		if _, err := parsed.Verify(&attesterKey.PublicKey, policy); err == nil {
			t.Errorf("%s: Verify accepted an incomplete policy", c.name)
		}
	}
}

func TestAttestation_Verify_RejectsNotYetValid(t *testing.T) {
	attesterKey := generateKey(t)
	clientKey := generateKey(t)
	now := time.Unix(1300816000, 0)
	attestation := createTestAttestation(t, attesterKey, attestationClaimsInput{
		Issuer: "https://attester.example.com", Subject: "https://client.example.com",
		NotBefore: now.Add(time.Hour).Unix(), ExpiresAt: now.Add(2 * time.Hour).Unix(),
		CNFJWK: confirmationJWK(t, &clientKey.PublicKey),
	})
	parsed, err := Parse(attestation)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	// A generous MaxLifetime here so the nbf check, not the exp/lifetime
	// check earlier in Verify, is what actually rejects this attestation.
	policy := basePolicy(now)
	policy.MaxLifetime = 3 * time.Hour
	if _, err := parsed.Verify(&attesterKey.PublicKey, policy); err != ErrNotYetValid {
		t.Errorf("Verify error = %v, want ErrNotYetValid", err)
	}
}

func TestAttestation_Verify_RejectsTypMismatch(t *testing.T) {
	attesterKey := generateKey(t)
	clientKey := generateKey(t)
	now := time.Unix(1300816000, 0)

	payload, err := json.Marshal(map[string]any{
		"iss": "https://attester.example.com", "sub": "https://client.example.com",
		"exp": now.Add(5 * time.Minute).Unix(),
		"cnf": map[string]any{"jwk": json.RawMessage(confirmationJWK(t, &clientKey.PublicKey))},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	wrongTyp, err := jose.Sign(attesterKey, jose.Header{Algorithm: fapi.ES256, Type: "not-the-right-typ"}, payload)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	parsed, err := Parse(wrongTyp)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if _, err := parsed.Verify(&attesterKey.PublicKey, basePolicy(now)); !errors.Is(err, ErrTypMismatch) {
		t.Errorf("Verify error = %v, want ErrTypMismatch", err)
	}
}

func basePoPPolicy(now time.Time) PoPVerifyPolicy {
	return PoPVerifyPolicy{
		ExpectedIssuer:   "https://client.example.com",
		ExpectedAudience: "https://as.example.com",
		Now:              now,
		MaxAge:           2 * time.Minute,
	}
}

func TestPoP_VerifyRoundTrip(t *testing.T) {
	clientKey := generateKey(t)
	now := time.Unix(1300816000, 0)
	jwk := confirmationJWK(t, &clientKey.PublicKey)

	pop := createTestPoP(t, clientKey, popClaimsInput{
		Issuer: "https://client.example.com", Audience: "https://as.example.com",
		JTI: "jti-1", IssuedAt: now.Unix(),
	})
	parsed, err := ParsePoP(pop)
	if err != nil {
		t.Fatalf("ParsePoP: %v", err)
	}
	verified, err := parsed.Verify(context.Background(), jwk, basePoPPolicy(now))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if verified.ClientID != "https://client.example.com" {
		t.Errorf("ClientID = %q", verified.ClientID)
	}
}

func TestParsePoP_RejectsMalformedInput(t *testing.T) {
	if _, err := ParsePoP("not-a-jwt"); err == nil {
		t.Errorf("ParsePoP accepted a malformed compact JWS")
	}
}

func TestPoP_Verify_RejectsIncompletePolicy(t *testing.T) {
	clientKey := generateKey(t)
	now := time.Unix(1300816000, 0)
	jwk := confirmationJWK(t, &clientKey.PublicKey)
	pop := createTestPoP(t, clientKey, popClaimsInput{
		Issuer: "https://client.example.com", Audience: "https://as.example.com",
		JTI: "jti-1", IssuedAt: now.Unix(),
	})
	parsed, err := ParsePoP(pop)
	if err != nil {
		t.Fatalf("ParsePoP: %v", err)
	}

	cases := []struct {
		name   string
		mutate func(PoPVerifyPolicy) PoPVerifyPolicy
	}{
		{"empty ExpectedIssuer", func(p PoPVerifyPolicy) PoPVerifyPolicy { p.ExpectedIssuer = ""; return p }},
		{"empty ExpectedAudience", func(p PoPVerifyPolicy) PoPVerifyPolicy { p.ExpectedAudience = ""; return p }},
		{"zero Now", func(p PoPVerifyPolicy) PoPVerifyPolicy { p.Now = time.Time{}; return p }},
		{"zero MaxAge", func(p PoPVerifyPolicy) PoPVerifyPolicy { p.MaxAge = 0; return p }},
	}
	for _, c := range cases {
		policy := c.mutate(basePoPPolicy(now))
		if _, err := parsed.Verify(context.Background(), jwk, policy); err == nil {
			t.Errorf("%s: Verify accepted an incomplete policy", c.name)
		}
	}
}

func TestPoP_Verify_RejectsNotYetValid(t *testing.T) {
	clientKey := generateKey(t)
	now := time.Unix(1300816000, 0)
	jwk := confirmationJWK(t, &clientKey.PublicKey)
	pop := createTestPoP(t, clientKey, popClaimsInput{
		Issuer: "https://client.example.com", Audience: "https://as.example.com",
		JTI: "jti-1", IssuedAt: now.Unix(), NotBefore: now.Add(time.Hour).Unix(),
	})
	parsed, err := ParsePoP(pop)
	if err != nil {
		t.Fatalf("ParsePoP: %v", err)
	}
	if _, err := parsed.Verify(context.Background(), jwk, basePoPPolicy(now)); err != ErrNotYetValid {
		t.Errorf("Verify error = %v, want ErrNotYetValid", err)
	}
}

func TestPoP_Verify_RejectsFutureIat(t *testing.T) {
	clientKey := generateKey(t)
	now := time.Unix(1300816000, 0)
	jwk := confirmationJWK(t, &clientKey.PublicKey)
	pop := createTestPoP(t, clientKey, popClaimsInput{
		Issuer: "https://client.example.com", Audience: "https://as.example.com",
		JTI: "jti-1", IssuedAt: now.Add(time.Hour).Unix(),
	})
	parsed, err := ParsePoP(pop)
	if err != nil {
		t.Fatalf("ParsePoP: %v", err)
	}
	if _, err := parsed.Verify(context.Background(), jwk, basePoPPolicy(now)); err != ErrNotYetValid {
		t.Errorf("Verify error = %v, want ErrNotYetValid", err)
	}
}

func TestPoP_Verify_RejectsTypMismatch(t *testing.T) {
	clientKey := generateKey(t)
	now := time.Unix(1300816000, 0)
	jwk := confirmationJWK(t, &clientKey.PublicKey)
	payload, err := json.Marshal(map[string]any{
		"iss": "https://client.example.com", "aud": "https://as.example.com",
		"jti": "jti-1", "iat": now.Unix(),
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	wrongTyp, err := jose.Sign(clientKey, jose.Header{Algorithm: fapi.ES256, Type: "not-the-right-typ"}, payload)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	parsed, err := ParsePoP(wrongTyp)
	if err != nil {
		t.Fatalf("ParsePoP: %v", err)
	}
	if _, err := parsed.Verify(context.Background(), jwk, basePoPPolicy(now)); !errors.Is(err, ErrTypMismatch) {
		t.Errorf("Verify error = %v, want ErrTypMismatch", err)
	}
}

func TestPoP_Verify_RejectsMalformedConfirmationKey(t *testing.T) {
	clientKey := generateKey(t)
	now := time.Unix(1300816000, 0)
	pop := createTestPoP(t, clientKey, popClaimsInput{
		Issuer: "https://client.example.com", Audience: "https://as.example.com",
		JTI: "jti-1", IssuedAt: now.Unix(),
	})
	parsed, err := ParsePoP(pop)
	if err != nil {
		t.Fatalf("ParsePoP: %v", err)
	}
	if _, err := parsed.Verify(context.Background(), []byte("not a jwk"), basePoPPolicy(now)); err == nil {
		t.Errorf("Verify accepted a malformed confirmation key")
	}
}

func TestParse_RejectsInvalidClaims(t *testing.T) {
	key := generateKey(t)
	// Well-formed JWS, but a payload missing every required attestation claim.
	compact, err := jose.Sign(key, jose.Header{Algorithm: fapi.ES256, Type: TypHeader}, []byte(`{}`))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if _, err := Parse(compact); err == nil {
		t.Errorf("Parse accepted a well-formed JWS with invalid claims")
	}
}

func TestParsePoP_RejectsInvalidClaims(t *testing.T) {
	key := generateKey(t)
	compact, err := jose.Sign(key, jose.Header{Algorithm: fapi.ES256, Type: PoPTypHeader}, []byte(`{}`))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if _, err := ParsePoP(compact); err == nil {
		t.Errorf("ParsePoP accepted a well-formed JWS with invalid claims")
	}
}

func TestPoP_Verify_RejectsWrongInstanceKey(t *testing.T) {
	clientKey := generateKey(t)
	otherKey := generateKey(t)
	now := time.Unix(1300816000, 0)

	pop := createTestPoP(t, clientKey, popClaimsInput{
		Issuer: "https://client.example.com", Audience: "https://as.example.com",
		JTI: "jti-1", IssuedAt: now.Unix(),
	})
	parsed, err := ParsePoP(pop)
	if err != nil {
		t.Fatalf("ParsePoP: %v", err)
	}
	wrongJWK := confirmationJWK(t, &otherKey.PublicKey)
	if _, err := parsed.Verify(context.Background(), wrongJWK, basePoPPolicy(now)); err == nil {
		t.Errorf("Verify accepted a signature that doesn't match the confirmation key")
	}
}

func TestPoP_Verify_RejectsIssuerMismatch(t *testing.T) {
	clientKey := generateKey(t)
	now := time.Unix(1300816000, 0)
	jwk := confirmationJWK(t, &clientKey.PublicKey)

	pop := createTestPoP(t, clientKey, popClaimsInput{
		Issuer: "https://someone-else.example.com", Audience: "https://as.example.com",
		JTI: "jti-1", IssuedAt: now.Unix(),
	})
	parsed, err := ParsePoP(pop)
	if err != nil {
		t.Fatalf("ParsePoP: %v", err)
	}
	if _, err := parsed.Verify(context.Background(), jwk, basePoPPolicy(now)); err != ErrIssuerMismatch {
		t.Errorf("Verify error = %v, want ErrIssuerMismatch", err)
	}
}

func TestPoP_Verify_RejectsAudienceMismatch(t *testing.T) {
	clientKey := generateKey(t)
	now := time.Unix(1300816000, 0)
	jwk := confirmationJWK(t, &clientKey.PublicKey)

	pop := createTestPoP(t, clientKey, popClaimsInput{
		Issuer: "https://client.example.com", Audience: "https://wrong-as.example.com",
		JTI: "jti-1", IssuedAt: now.Unix(),
	})
	parsed, err := ParsePoP(pop)
	if err != nil {
		t.Fatalf("ParsePoP: %v", err)
	}
	if _, err := parsed.Verify(context.Background(), jwk, basePoPPolicy(now)); err != ErrAudienceMismatch {
		t.Errorf("Verify error = %v, want ErrAudienceMismatch", err)
	}
}

func TestPoP_Verify_Challenge(t *testing.T) {
	clientKey := generateKey(t)
	now := time.Unix(1300816000, 0)
	jwk := confirmationJWK(t, &clientKey.PublicKey)

	pop := createTestPoP(t, clientKey, popClaimsInput{
		Issuer: "https://client.example.com", Audience: "https://as.example.com",
		JTI: "jti-1", IssuedAt: now.Unix(), Challenge: "the-challenge",
	})
	parsed, err := ParsePoP(pop)
	if err != nil {
		t.Fatalf("ParsePoP: %v", err)
	}

	policy := basePoPPolicy(now)
	policy.ExpectedChallenge = "the-challenge"
	if _, err := parsed.Verify(context.Background(), jwk, policy); err != nil {
		t.Errorf("Verify with matching challenge: %v", err)
	}

	policy.ExpectedChallenge = "a-different-challenge"
	if _, err := parsed.Verify(context.Background(), jwk, policy); err != ErrChallengeMismatch {
		t.Errorf("Verify error = %v, want ErrChallengeMismatch", err)
	}
}

func TestPoP_Verify_RejectsStale(t *testing.T) {
	clientKey := generateKey(t)
	now := time.Unix(1300816000, 0)
	jwk := confirmationJWK(t, &clientKey.PublicKey)

	pop := createTestPoP(t, clientKey, popClaimsInput{
		Issuer: "https://client.example.com", Audience: "https://as.example.com",
		JTI: "jti-1", IssuedAt: now.Add(-time.Hour).Unix(),
	})
	parsed, err := ParsePoP(pop)
	if err != nil {
		t.Fatalf("ParsePoP: %v", err)
	}
	if _, err := parsed.Verify(context.Background(), jwk, basePoPPolicy(now)); err != ErrExpired {
		t.Errorf("Verify error = %v, want ErrExpired", err)
	}
}

func TestPoP_Verify_RejectsReplay(t *testing.T) {
	clientKey := generateKey(t)
	now := time.Unix(1300816000, 0)
	jwk := confirmationJWK(t, &clientKey.PublicKey)

	pop := createTestPoP(t, clientKey, popClaimsInput{
		Issuer: "https://client.example.com", Audience: "https://as.example.com",
		JTI: "jti-1", IssuedAt: now.Unix(),
	})

	replay := newMemoryReplayChecker()
	policy := basePoPPolicy(now)
	policy.Replay = replay

	parsed, err := ParsePoP(pop)
	if err != nil {
		t.Fatalf("ParsePoP: %v", err)
	}
	if _, err := parsed.Verify(context.Background(), jwk, policy); err != nil {
		t.Fatalf("first Verify: %v", err)
	}

	parsed2, err := ParsePoP(pop)
	if err != nil {
		t.Fatalf("ParsePoP: %v", err)
	}
	if _, err := parsed2.Verify(context.Background(), jwk, policy); err == nil {
		t.Errorf("Verify accepted a replayed jti")
	}
}

type memoryReplayChecker struct {
	seen map[string]bool
}

func newMemoryReplayChecker() *memoryReplayChecker {
	return &memoryReplayChecker{seen: make(map[string]bool)}
}

func (m *memoryReplayChecker) UseOnce(_ context.Context, jti string, _ time.Time) error {
	if m.seen[jti] {
		return errReplayed
	}
	m.seen[jti] = true
	return nil
}

type fakeErr string

func (e fakeErr) Error() string { return string(e) }

const errReplayed = fakeErr("jti already used")
