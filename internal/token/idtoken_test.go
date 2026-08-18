package token

import (
	"crypto"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
)

func baseIDTokenParams(key crypto.Signer, now time.Time, lifetime time.Duration) IDTokenParams {
	return IDTokenParams{
		Signer: key, Algorithm: fapi.ES256,
		Issuer: "https://as.example", Subject: "user-1", Audience: "client-123",
		Now: now, Lifetime: lifetime,
	}
}

func baseIDTokenPolicy(now time.Time) IDTokenValidatePolicy {
	return IDTokenValidatePolicy{
		ExpectedIssuer: "https://as.example", ExpectedAudience: "client-123",
		Algorithm: fapi.ES256, Now: now, MaxLifetime: 2 * time.Minute,
	}
}

func TestIDTokenRoundTrip(t *testing.T) {
	key := generateKey(t)
	now := time.Now()
	p := baseIDTokenParams(key, now, time.Minute)
	p.Nonce = "opaque-nonce"
	p.AuthTime = now.Add(-30 * time.Second)
	p.ACR = "urn:mace:incommon:iap:silver"
	p.AMR = []string{"pwd", "otp"}
	p.Parameters = map[string]json.RawMessage{"custom_claim": jsonRaw(t, "value")}

	tok, err := IssueIDToken(p)
	if err != nil {
		t.Fatalf("IssueIDToken: %v", err)
	}

	parsed, err := ParseIDToken(tok)
	if err != nil {
		t.Fatalf("ParseIDToken: %v", err)
	}
	if parsed.ClaimedIssuer() != "https://as.example" {
		t.Fatalf("ClaimedIssuer() = %q, want %q", parsed.ClaimedIssuer(), "https://as.example")
	}

	policy := baseIDTokenPolicy(now.Add(time.Second))
	policy.ExpectedNonce = "opaque-nonce"
	validated, err := parsed.Validate(&key.PublicKey, policy)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if validated.Subject != "user-1" {
		t.Fatalf("Subject = %q, want %q", validated.Subject, "user-1")
	}
	if validated.ACR != "urn:mace:incommon:iap:silver" {
		t.Fatalf("ACR = %q, want %q", validated.ACR, "urn:mace:incommon:iap:silver")
	}
	if len(validated.AMR) != 2 || validated.AMR[0] != "pwd" || validated.AMR[1] != "otp" {
		t.Fatalf("AMR = %v, want [pwd otp]", validated.AMR)
	}
	if validated.AuthTime.Unix() != now.Add(-30*time.Second).Unix() {
		t.Fatalf("AuthTime = %v, want %v", validated.AuthTime, now.Add(-30*time.Second))
	}
	if _, ok := validated.Parameters["custom_claim"]; !ok {
		t.Fatalf("Parameters missing custom_claim")
	}
}

func TestIDTokenWithoutNonceWhenNotExpected(t *testing.T) {
	key := generateKey(t)
	now := time.Now()
	tok, err := IssueIDToken(baseIDTokenParams(key, now, time.Minute))
	if err != nil {
		t.Fatalf("IssueIDToken: %v", err)
	}
	parsed, err := ParseIDToken(tok)
	if err != nil {
		t.Fatalf("ParseIDToken: %v", err)
	}
	if _, err := parsed.Validate(&key.PublicKey, baseIDTokenPolicy(now)); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestIDTokenValidateRejectsNonceMismatch(t *testing.T) {
	key := generateKey(t)
	now := time.Now()
	p := baseIDTokenParams(key, now, time.Minute)
	p.Nonce = "actual-nonce"
	tok, err := IssueIDToken(p)
	if err != nil {
		t.Fatalf("IssueIDToken: %v", err)
	}
	parsed, err := ParseIDToken(tok)
	if err != nil {
		t.Fatalf("ParseIDToken: %v", err)
	}
	policy := baseIDTokenPolicy(now)
	policy.ExpectedNonce = "different-nonce"
	if _, err := parsed.Validate(&key.PublicKey, policy); !errors.Is(err, ErrNonceMismatch) {
		t.Fatalf("Validate(wrong nonce) = %v, want ErrNonceMismatch", err)
	}
}

func TestIDTokenValidateRejectsMissingNonceWhenExpected(t *testing.T) {
	key := generateKey(t)
	now := time.Now()
	tok, err := IssueIDToken(baseIDTokenParams(key, now, time.Minute))
	if err != nil {
		t.Fatalf("IssueIDToken: %v", err)
	}
	parsed, err := ParseIDToken(tok)
	if err != nil {
		t.Fatalf("ParseIDToken: %v", err)
	}
	policy := baseIDTokenPolicy(now)
	policy.ExpectedNonce = "expected-nonce"
	if _, err := parsed.Validate(&key.PublicKey, policy); !errors.Is(err, ErrNonceMismatch) {
		t.Fatalf("Validate(missing nonce, expected one) = %v, want ErrNonceMismatch", err)
	}
}

func TestIssueIDTokenRejectsReservedClaimName(t *testing.T) {
	key := generateKey(t)
	p := baseIDTokenParams(key, time.Now(), time.Minute)
	p.Parameters = map[string]json.RawMessage{"acr": jsonRaw(t, "custom")}
	if _, err := IssueIDToken(p); err == nil {
		t.Fatalf("IssueIDToken with reserved claim = nil error, want error")
	}
}

func TestIDTokenValidateRejectsWrongKey(t *testing.T) {
	key := generateKey(t)
	other := generateKey(t)
	now := time.Now()
	tok, err := IssueIDToken(baseIDTokenParams(key, now, time.Minute))
	if err != nil {
		t.Fatalf("IssueIDToken: %v", err)
	}
	parsed, err := ParseIDToken(tok)
	if err != nil {
		t.Fatalf("ParseIDToken: %v", err)
	}
	if _, err := parsed.Validate(&other.PublicKey, baseIDTokenPolicy(now)); err == nil {
		t.Fatalf("Validate(wrong key) = nil error, want error")
	}
}

func TestIDTokenValidateRejectsIssuerAndAudienceMismatch(t *testing.T) {
	key := generateKey(t)
	now := time.Now()
	tok, err := IssueIDToken(baseIDTokenParams(key, now, time.Minute))
	if err != nil {
		t.Fatalf("IssueIDToken: %v", err)
	}
	parsed, err := ParseIDToken(tok)
	if err != nil {
		t.Fatalf("ParseIDToken: %v", err)
	}

	issuerPolicy := baseIDTokenPolicy(now)
	issuerPolicy.ExpectedIssuer = "https://other-as.example"
	if _, err := parsed.Validate(&key.PublicKey, issuerPolicy); !errors.Is(err, ErrIssuerMismatch) {
		t.Fatalf("Validate(wrong issuer) = %v, want ErrIssuerMismatch", err)
	}

	audPolicy := baseIDTokenPolicy(now)
	audPolicy.ExpectedAudience = "different-client"
	if _, err := parsed.Validate(&key.PublicKey, audPolicy); !errors.Is(err, ErrAudienceMismatch) {
		t.Fatalf("Validate(wrong audience) = %v, want ErrAudienceMismatch", err)
	}
}

// OIDC Core §2 documents "aud" as possibly array-valued for an ID token
// ("In the general case, the aud value is an array of case sensitive
// strings") - a single-element array naming just this client's own ID
// must validate exactly like a bare string would. Confirmed against the
// OIDF conformance suite's own
// fapi2-security-profile-final-client-test-valid-aud-as-array module
// (which, per its own summary and AddAudValueAsArrayToIdToken source,
// specifically wraps the single value in an array — not a genuine
// multi-audience token), not just the spec text.
func TestIDTokenValidateAcceptsSingleElementAudienceArray(t *testing.T) {
	key := generateKey(t)
	now := time.Now()

	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256"}`))
	payloadJSON, err := json.Marshal(map[string]any{
		"iss": "https://as.example",
		"sub": "user-1",
		"aud": []string{"client-123"},
		"exp": now.Add(time.Minute).Unix(),
		"iat": now.Unix(),
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	signingInput := header + "." + base64.RawURLEncoding.EncodeToString(payloadJSON)
	tok := signingInput + "." + signRaw(t, key, signingInput)

	parsed, err := ParseIDToken(tok)
	if err != nil {
		t.Fatalf("ParseIDToken: %v", err)
	}
	if _, err := parsed.Validate(&key.PublicKey, baseIDTokenPolicy(now)); err != nil {
		t.Fatalf("Validate(single-element aud array) = %v, want nil error", err)
	}
}

// OIDC Core §3.1.3.7 step 3: "The ID Token MUST be rejected if the ID
// Token does not list the Client as a valid audience, or if it contains
// additional audiences not trusted by the Client." This package has no
// mechanism for a caller to name any audience as trusted besides
// itself, so a second, untrusted audience value must be rejected even
// though the client's own ID is genuinely present too. Confirmed
// against the OIDF conformance suite's own
// fapi2-security-profile-final-client-test-invalid-secondary-aud
// module and its AddUntrustedSecondAudValueToIdToken source.
func TestIDTokenValidateRejectsUntrustedSecondAudience(t *testing.T) {
	key := generateKey(t)
	now := time.Now()

	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256"}`))
	payloadJSON, err := json.Marshal(map[string]any{
		"iss": "https://as.example",
		"sub": "user-1",
		"aud": []string{"client-123", "client-1231"},
		"exp": now.Add(time.Minute).Unix(),
		"iat": now.Unix(),
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	signingInput := header + "." + base64.RawURLEncoding.EncodeToString(payloadJSON)
	tok := signingInput + "." + signRaw(t, key, signingInput)

	parsed, err := ParseIDToken(tok)
	if err != nil {
		t.Fatalf("ParseIDToken: %v", err)
	}
	if _, err := parsed.Validate(&key.PublicKey, baseIDTokenPolicy(now)); !errors.Is(err, ErrAudienceMismatch) {
		t.Fatalf("Validate(untrusted second aud) = %v, want ErrAudienceMismatch", err)
	}
}

func TestIDTokenValidateRejectsExpiredAndExceededLifetime(t *testing.T) {
	key := generateKey(t)
	now := time.Now()

	expiredTok, err := IssueIDToken(baseIDTokenParams(key, now, time.Minute))
	if err != nil {
		t.Fatalf("IssueIDToken: %v", err)
	}
	expiredParsed, err := ParseIDToken(expiredTok)
	if err != nil {
		t.Fatalf("ParseIDToken: %v", err)
	}
	expiredPolicy := baseIDTokenPolicy(now.Add(2 * time.Minute))
	if _, err := expiredParsed.Validate(&key.PublicKey, expiredPolicy); !errors.Is(err, ErrExpired) {
		t.Fatalf("Validate(expired) = %v, want ErrExpired", err)
	}

	longTok, err := IssueIDToken(baseIDTokenParams(key, now, 10*time.Minute))
	if err != nil {
		t.Fatalf("IssueIDToken: %v", err)
	}
	longParsed, err := ParseIDToken(longTok)
	if err != nil {
		t.Fatalf("ParseIDToken: %v", err)
	}
	if _, err := longParsed.Validate(&key.PublicKey, baseIDTokenPolicy(now)); !errors.Is(err, ErrLifetimeExceeded) {
		t.Fatalf("Validate(exceeds max lifetime) = %v, want ErrLifetimeExceeded", err)
	}
}

func TestParseIDTokenRejectsMissingRequiredClaims(t *testing.T) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256"}`))
	cases := []string{
		`{"sub":"user-1","aud":"client-123","exp":9999999999,"iat":1}`,
		`{"iss":"https://as.example","aud":"client-123","exp":9999999999,"iat":1}`,
		`{"iss":"https://as.example","sub":"user-1","exp":9999999999,"iat":1}`,
		`{"iss":"https://as.example","sub":"user-1","aud":"client-123","iat":1}`,
		`{"iss":"https://as.example","sub":"user-1","aud":"client-123","exp":9999999999}`,
	}
	for _, payloadJSON := range cases {
		payload := base64.RawURLEncoding.EncodeToString([]byte(payloadJSON))
		tok := header + "." + payload + "." + base64.RawURLEncoding.EncodeToString(make([]byte, 64))
		if _, err := ParseIDToken(tok); !errors.Is(err, ErrMalformedClaims) {
			t.Fatalf("ParseIDToken(%s) = %v, want ErrMalformedClaims", payloadJSON, err)
		}
	}
}
