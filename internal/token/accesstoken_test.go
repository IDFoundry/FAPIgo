package token

import (
	"crypto"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/jose"
)

func baseAccessTokenParams(key crypto.Signer, now time.Time, lifetime time.Duration) AccessTokenParams {
	return AccessTokenParams{
		Signer: key, Algorithm: fapi.ES256,
		Issuer: "https://as.example", Subject: "user-1", Audience: "https://rs.example",
		ClientID: "client-123", Scope: "openid accounts", Now: now, Lifetime: lifetime,
	}
}

func baseAccessTokenPolicy(now time.Time) AccessTokenValidatePolicy {
	return AccessTokenValidatePolicy{
		ExpectedIssuer: "https://as.example", ExpectedAudience: "https://rs.example",
		Algorithm: fapi.ES256, Now: now, MaxLifetime: 2 * time.Minute,
	}
}

func TestAccessTokenRoundTrip(t *testing.T) {
	key := generateKey(t)
	now := time.Now()
	p := baseAccessTokenParams(key, now, time.Minute)
	p.Parameters = map[string]json.RawMessage{
		"authorization_details": jsonRaw(t, []map[string]string{{"type": "payment_initiation"}}),
	}
	tok, err := IssueAccessToken(p)
	if err != nil {
		t.Fatalf("IssueAccessToken: %v", err)
	}

	parsed, err := ParseAccessToken(tok)
	if err != nil {
		t.Fatalf("ParseAccessToken: %v", err)
	}
	if parsed.ClaimedIssuer() != "https://as.example" {
		t.Fatalf("ClaimedIssuer() = %q, want %q", parsed.ClaimedIssuer(), "https://as.example")
	}

	validated, err := parsed.Validate(&key.PublicKey, baseAccessTokenPolicy(now.Add(time.Second)))
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if validated.Subject != "user-1" {
		t.Fatalf("Subject = %q, want %q", validated.Subject, "user-1")
	}
	if validated.ClientID != "client-123" {
		t.Fatalf("ClientID = %q, want %q", validated.ClientID, "client-123")
	}
	if validated.Scope != "openid accounts" {
		t.Fatalf("Scope = %q, want %q", validated.Scope, "openid accounts")
	}
	if _, ok := validated.Parameters["authorization_details"]; !ok {
		t.Fatalf("Parameters missing authorization_details")
	}
}

func TestAccessTokenWithKeyID(t *testing.T) {
	key := generateKey(t)
	now := time.Now()
	p := baseAccessTokenParams(key, now, time.Minute)
	p.KeyID = "key-1"
	tok, err := IssueAccessToken(p)
	if err != nil {
		t.Fatalf("IssueAccessToken: %v", err)
	}
	parsed, err := ParseAccessToken(tok)
	if err != nil {
		t.Fatalf("ParseAccessToken: %v", err)
	}
	if parsed.KeyID() != "key-1" {
		t.Fatalf("KeyID() = %q, want %q", parsed.KeyID(), "key-1")
	}
}

func TestAccessTokenConfirmationBinding(t *testing.T) {
	key := generateKey(t)
	dpopKey := generateKey(t)
	dpopJWK, err := jose.NewJWK(&dpopKey.PublicKey, fapi.ES256)
	if err != nil {
		t.Fatalf("NewJWK: %v", err)
	}
	thumbprint, err := dpopJWK.Thumbprint()
	if err != nil {
		t.Fatalf("Thumbprint: %v", err)
	}

	now := time.Now()
	p := baseAccessTokenParams(key, now, time.Minute)
	p.Confirmation = &Confirmation{JKT: thumbprint.String()}
	tok, err := IssueAccessToken(p)
	if err != nil {
		t.Fatalf("IssueAccessToken: %v", err)
	}

	parsed, err := ParseAccessToken(tok)
	if err != nil {
		t.Fatalf("ParseAccessToken: %v", err)
	}

	policy := baseAccessTokenPolicy(now)
	policy.ExpectedThumbprint = &thumbprint
	if _, err := parsed.Validate(&key.PublicKey, policy); err != nil {
		t.Fatalf("Validate(matching thumbprint): %v", err)
	}

	otherKey := generateKey(t)
	otherJWK, err := jose.NewJWK(&otherKey.PublicKey, fapi.ES256)
	if err != nil {
		t.Fatalf("NewJWK: %v", err)
	}
	otherThumbprint, err := otherJWK.Thumbprint()
	if err != nil {
		t.Fatalf("Thumbprint: %v", err)
	}
	wrongPolicy := baseAccessTokenPolicy(now)
	wrongPolicy.ExpectedThumbprint = &otherThumbprint
	if _, err := parsed.Validate(&key.PublicKey, wrongPolicy); !errors.Is(err, ErrConfirmationMismatch) {
		t.Fatalf("Validate(wrong thumbprint) = %v, want ErrConfirmationMismatch", err)
	}
}

func TestAccessTokenMissingConfirmationWhenRequired(t *testing.T) {
	key := generateKey(t)
	now := time.Now()
	tok, err := IssueAccessToken(baseAccessTokenParams(key, now, time.Minute))
	if err != nil {
		t.Fatalf("IssueAccessToken: %v", err)
	}
	parsed, err := ParseAccessToken(tok)
	if err != nil {
		t.Fatalf("ParseAccessToken: %v", err)
	}

	dpopKey := generateKey(t)
	dpopJWK, err := jose.NewJWK(&dpopKey.PublicKey, fapi.ES256)
	if err != nil {
		t.Fatalf("NewJWK: %v", err)
	}
	thumbprint, err := dpopJWK.Thumbprint()
	if err != nil {
		t.Fatalf("Thumbprint: %v", err)
	}
	policy := baseAccessTokenPolicy(now)
	policy.ExpectedThumbprint = &thumbprint
	if _, err := parsed.Validate(&key.PublicKey, policy); !errors.Is(err, ErrMissingConfirmation) {
		t.Fatalf("Validate(no cnf, required) = %v, want ErrMissingConfirmation", err)
	}
}

func TestIssueAccessTokenRejectsReservedClaimName(t *testing.T) {
	key := generateKey(t)
	p := baseAccessTokenParams(key, time.Now(), time.Minute)
	p.Parameters = map[string]json.RawMessage{"jti": jsonRaw(t, "custom")}
	if _, err := IssueAccessToken(p); err == nil {
		t.Fatalf("IssueAccessToken with reserved claim = nil error, want error")
	}
}

func TestAccessTokenValidateRejectsWrongKey(t *testing.T) {
	key := generateKey(t)
	other := generateKey(t)
	now := time.Now()
	tok, err := IssueAccessToken(baseAccessTokenParams(key, now, time.Minute))
	if err != nil {
		t.Fatalf("IssueAccessToken: %v", err)
	}
	parsed, err := ParseAccessToken(tok)
	if err != nil {
		t.Fatalf("ParseAccessToken: %v", err)
	}
	if _, err := parsed.Validate(&other.PublicKey, baseAccessTokenPolicy(now)); err == nil {
		t.Fatalf("Validate(wrong key) = nil error, want error")
	}
}

func TestAccessTokenValidateRejectsAlgorithmConfusion(t *testing.T) {
	key := generateKey(t)
	now := time.Now()
	tok, err := IssueAccessToken(baseAccessTokenParams(key, now, time.Minute))
	if err != nil {
		t.Fatalf("IssueAccessToken: %v", err)
	}
	parsed, err := ParseAccessToken(tok)
	if err != nil {
		t.Fatalf("ParseAccessToken: %v", err)
	}
	policy := baseAccessTokenPolicy(now)
	policy.Algorithm = fapi.PS256
	if _, err := parsed.Validate(&key.PublicKey, policy); err == nil {
		t.Fatalf("Validate(alg confusion) = nil error, want error")
	}
}

func TestAccessTokenValidateRejectsIssuerAndAudienceMismatch(t *testing.T) {
	key := generateKey(t)
	now := time.Now()
	tok, err := IssueAccessToken(baseAccessTokenParams(key, now, time.Minute))
	if err != nil {
		t.Fatalf("IssueAccessToken: %v", err)
	}
	parsed, err := ParseAccessToken(tok)
	if err != nil {
		t.Fatalf("ParseAccessToken: %v", err)
	}

	issuerPolicy := baseAccessTokenPolicy(now)
	issuerPolicy.ExpectedIssuer = "https://other-as.example"
	if _, err := parsed.Validate(&key.PublicKey, issuerPolicy); !errors.Is(err, ErrIssuerMismatch) {
		t.Fatalf("Validate(wrong issuer) = %v, want ErrIssuerMismatch", err)
	}

	audPolicy := baseAccessTokenPolicy(now)
	audPolicy.ExpectedAudience = "https://other-rs.example"
	if _, err := parsed.Validate(&key.PublicKey, audPolicy); !errors.Is(err, ErrAudienceMismatch) {
		t.Fatalf("Validate(wrong audience) = %v, want ErrAudienceMismatch", err)
	}
}

func TestAccessTokenValidateRejectsExpiredAndExceededLifetime(t *testing.T) {
	key := generateKey(t)
	now := time.Now()

	expiredTok, err := IssueAccessToken(baseAccessTokenParams(key, now, time.Minute))
	if err != nil {
		t.Fatalf("IssueAccessToken: %v", err)
	}
	expiredParsed, err := ParseAccessToken(expiredTok)
	if err != nil {
		t.Fatalf("ParseAccessToken: %v", err)
	}
	expiredPolicy := baseAccessTokenPolicy(now.Add(2 * time.Minute))
	if _, err := expiredParsed.Validate(&key.PublicKey, expiredPolicy); !errors.Is(err, ErrExpired) {
		t.Fatalf("Validate(expired) = %v, want ErrExpired", err)
	}

	longTok, err := IssueAccessToken(baseAccessTokenParams(key, now, 10*time.Minute))
	if err != nil {
		t.Fatalf("IssueAccessToken: %v", err)
	}
	longParsed, err := ParseAccessToken(longTok)
	if err != nil {
		t.Fatalf("ParseAccessToken: %v", err)
	}
	if _, err := longParsed.Validate(&key.PublicKey, baseAccessTokenPolicy(now)); !errors.Is(err, ErrLifetimeExceeded) {
		t.Fatalf("Validate(exceeds max lifetime) = %v, want ErrLifetimeExceeded", err)
	}
}

func TestParseAccessTokenRejectsWrongType(t *testing.T) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(
		`{"iss":"https://as.example","sub":"user-1","aud":"https://rs.example","client_id":"client-123","exp":9999999999,"iat":1,"jti":"x"}`,
	))
	tok := header + "." + payload + "." + base64.RawURLEncoding.EncodeToString(make([]byte, 64))
	if _, err := ParseAccessToken(tok); !errors.Is(err, ErrWrongType) {
		t.Fatalf("ParseAccessToken(wrong typ) = %v, want ErrWrongType", err)
	}
}

func TestParseAccessTokenRejectsMissingRequiredClaims(t *testing.T) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","typ":"at+jwt"}`))
	cases := []string{
		`{"sub":"user-1","aud":"https://rs.example","client_id":"client-123","exp":9999999999,"iat":1,"jti":"x"}`,
		`{"iss":"https://as.example","aud":"https://rs.example","client_id":"client-123","exp":9999999999,"iat":1,"jti":"x"}`,
		`{"iss":"https://as.example","sub":"user-1","client_id":"client-123","exp":9999999999,"iat":1,"jti":"x"}`,
		`{"iss":"https://as.example","sub":"user-1","aud":"https://rs.example","exp":9999999999,"iat":1,"jti":"x"}`,
		`{"iss":"https://as.example","sub":"user-1","aud":"https://rs.example","client_id":"client-123","iat":1,"jti":"x"}`,
		`{"iss":"https://as.example","sub":"user-1","aud":"https://rs.example","client_id":"client-123","exp":9999999999,"jti":"x"}`,
		`{"iss":"https://as.example","sub":"user-1","aud":"https://rs.example","client_id":"client-123","exp":9999999999,"iat":1}`,
	}
	for _, payloadJSON := range cases {
		payload := base64.RawURLEncoding.EncodeToString([]byte(payloadJSON))
		tok := header + "." + payload + "." + base64.RawURLEncoding.EncodeToString(make([]byte, 64))
		if _, err := ParseAccessToken(tok); !errors.Is(err, ErrMalformedClaims) {
			t.Fatalf("ParseAccessToken(%s) = %v, want ErrMalformedClaims", payloadJSON, err)
		}
	}
}
