package jarm

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"

	fapi "github.com/osanderson/go-fapi"
)

func generateKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return key
}

func jsonRaw(t *testing.T, v any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

func successParameters(t *testing.T) map[string]json.RawMessage {
	t.Helper()
	return map[string]json.RawMessage{
		"code":  jsonRaw(t, "auth-code-value"),
		"state": jsonRaw(t, "opaque-state"),
	}
}

func errorParameters(t *testing.T) map[string]json.RawMessage {
	t.Helper()
	return map[string]json.RawMessage{
		"error":             jsonRaw(t, "access_denied"),
		"error_description": jsonRaw(t, "the user denied the request"),
		"state":             jsonRaw(t, "opaque-state"),
	}
}

func createTestResponse(t *testing.T, key *ecdsa.PrivateKey, now time.Time, lifetime time.Duration, params map[string]json.RawMessage) string {
	t.Helper()
	token, err := Create(CreateParams{
		Signer:     key,
		Algorithm:  fapi.ES256,
		Issuer:     "https://as.example",
		Audience:   "client-123",
		Now:        now,
		Lifetime:   lifetime,
		Parameters: params,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	return token
}

func basePolicy(now time.Time) VerifyPolicy {
	return VerifyPolicy{
		ExpectedIssuer:   "https://as.example",
		ExpectedAudience: "client-123",
		Algorithm:        fapi.ES256,
		Now:              now,
		MaxLifetime:      2 * time.Minute,
	}
}

func TestCreateVerifyRoundTripSuccess(t *testing.T) {
	key := generateKey(t)
	now := time.Now()
	token := createTestResponse(t, key, now, time.Minute, successParameters(t))

	resp, err := Parse(token)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if resp.ClaimedIssuer() != "https://as.example" {
		t.Fatalf("ClaimedIssuer() = %q, want %q", resp.ClaimedIssuer(), "https://as.example")
	}
	raw, ok := resp.Parameter("code")
	if !ok {
		t.Fatalf("Parameter(code) not found")
	}
	var code string
	if err := json.Unmarshal(raw, &code); err != nil || code != "auth-code-value" {
		t.Fatalf("Parameter(code) = %q, want %q", code, "auth-code-value")
	}

	verified, err := resp.Verify(&key.PublicKey, basePolicy(now.Add(time.Second)))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if verified.Issuer != "https://as.example" {
		t.Fatalf("Issuer = %q, want %q", verified.Issuer, "https://as.example")
	}
	var state string
	if err := json.Unmarshal(verified.Parameters["state"], &state); err != nil || state != "opaque-state" {
		t.Fatalf("Parameters[state] = %q, want %q", state, "opaque-state")
	}
}

func TestCreateVerifyRoundTripError(t *testing.T) {
	key := generateKey(t)
	now := time.Now()
	token := createTestResponse(t, key, now, time.Minute, errorParameters(t))

	resp, err := Parse(token)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	verified, err := resp.Verify(&key.PublicKey, basePolicy(now))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	var errCode string
	if err := json.Unmarshal(verified.Parameters["error"], &errCode); err != nil || errCode != "access_denied" {
		t.Fatalf("Parameters[error] = %q, want %q", errCode, "access_denied")
	}
}

func TestVerifyWithKeyID(t *testing.T) {
	key := generateKey(t)
	now := time.Now()
	token, err := Create(CreateParams{
		Signer: key, Algorithm: fapi.ES256, KeyID: "key-1",
		Issuer: "https://as.example", Audience: "client-123",
		Now: now, Lifetime: time.Minute, Parameters: successParameters(t),
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	resp, err := Parse(token)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if resp.KeyID() != "key-1" {
		t.Fatalf("KeyID() = %q, want %q", resp.KeyID(), "key-1")
	}
}

func TestCreateRejectsReservedClaimName(t *testing.T) {
	key := generateKey(t)
	params := successParameters(t)
	params["exp"] = jsonRaw(t, 12345)
	_, err := Create(CreateParams{
		Signer: key, Algorithm: fapi.ES256, Issuer: "https://as.example",
		Audience: "client-123", Now: time.Now(), Lifetime: time.Minute, Parameters: params,
	})
	if err == nil {
		t.Fatalf("Create with reserved claim in Parameters = nil error, want error")
	}
}

func TestVerifyRejectsWrongKey(t *testing.T) {
	key := generateKey(t)
	other := generateKey(t)
	now := time.Now()
	token := createTestResponse(t, key, now, time.Minute, successParameters(t))

	resp, err := Parse(token)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if _, err := resp.Verify(&other.PublicKey, basePolicy(now)); err == nil {
		t.Fatalf("Verify(wrong key) = nil error, want error")
	}
}

func TestVerifyRejectsAlgorithmConfusion(t *testing.T) {
	key := generateKey(t)
	now := time.Now()
	token := createTestResponse(t, key, now, time.Minute, successParameters(t))

	resp, err := Parse(token)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	policy := basePolicy(now)
	policy.Algorithm = fapi.PS256
	if _, err := resp.Verify(&key.PublicKey, policy); err == nil {
		t.Fatalf("Verify(policy alg PS256, header alg ES256) = nil error, want error")
	}
}

func TestVerifyRejectsIssuerMismatch(t *testing.T) {
	key := generateKey(t)
	now := time.Now()
	token := createTestResponse(t, key, now, time.Minute, successParameters(t))

	resp, err := Parse(token)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	policy := basePolicy(now)
	policy.ExpectedIssuer = "https://other-as.example"
	if _, err := resp.Verify(&key.PublicKey, policy); !errors.Is(err, ErrIssuerMismatch) {
		t.Fatalf("Verify(wrong issuer) = %v, want ErrIssuerMismatch", err)
	}
}

func TestVerifyRejectsAudienceMismatch(t *testing.T) {
	key := generateKey(t)
	now := time.Now()
	token := createTestResponse(t, key, now, time.Minute, successParameters(t))

	resp, err := Parse(token)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	policy := basePolicy(now)
	policy.ExpectedAudience = "different-client"
	if _, err := resp.Verify(&key.PublicKey, policy); !errors.Is(err, ErrAudienceMismatch) {
		t.Fatalf("Verify(wrong audience) = %v, want ErrAudienceMismatch", err)
	}
}

func TestVerifyRejectsExpiredResponse(t *testing.T) {
	key := generateKey(t)
	now := time.Now()
	token := createTestResponse(t, key, now, time.Minute, successParameters(t))

	resp, err := Parse(token)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	policy := basePolicy(now.Add(2 * time.Minute))
	if _, err := resp.Verify(&key.PublicKey, policy); !errors.Is(err, ErrExpired) {
		t.Fatalf("Verify(expired) = %v, want ErrExpired", err)
	}
}

func TestVerifyRejectsLifetimeExceeded(t *testing.T) {
	key := generateKey(t)
	now := time.Now()
	token := createTestResponse(t, key, now, 10*time.Minute, successParameters(t))

	resp, err := Parse(token)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if _, err := resp.Verify(&key.PublicKey, basePolicy(now)); !errors.Is(err, ErrLifetimeExceeded) {
		t.Fatalf("Verify(exceeds max lifetime) = %v, want ErrLifetimeExceeded", err)
	}
}

func TestParseRejectsMissingRequiredClaims(t *testing.T) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256"}`))
	cases := []string{
		`{"aud":"client-123","exp":9999999999}`,           // missing iss
		`{"iss":"https://as.example","exp":9999999999}`,   // missing aud
		`{"iss":"https://as.example","aud":"client-123"}`, // missing exp
	}
	for _, payloadJSON := range cases {
		payload := base64.RawURLEncoding.EncodeToString([]byte(payloadJSON))
		token := header + "." + payload + "." + base64.RawURLEncoding.EncodeToString(make([]byte, 64))
		if _, err := Parse(token); !errors.Is(err, ErrMalformedClaims) {
			t.Fatalf("Parse(%s) = %v, want ErrMalformedClaims", payloadJSON, err)
		}
	}
}

func TestVerifyRequiresMaxLifetime(t *testing.T) {
	key := generateKey(t)
	now := time.Now()
	token := createTestResponse(t, key, now, time.Minute, successParameters(t))

	resp, err := Parse(token)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	policy := basePolicy(now)
	policy.MaxLifetime = 0
	if _, err := resp.Verify(&key.PublicKey, policy); err == nil {
		t.Fatalf("Verify with zero MaxLifetime = nil error, want error")
	}
}
