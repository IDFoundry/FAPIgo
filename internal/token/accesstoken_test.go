package token

import (
	"crypto"
	"crypto/ecdsa"
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
	tok, jti, err := IssueAccessToken(p)
	if err != nil {
		t.Fatalf("IssueAccessToken: %v", err)
	}
	if jti == "" {
		t.Fatal("IssueAccessToken returned an empty jti")
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
	if validated.JTI != jti {
		t.Fatalf("validated.JTI = %q, want %q (the jti IssueAccessToken returned)", validated.JTI, jti)
	}
	if validated.JKT != "" {
		t.Fatalf("validated.JKT = %q, want \"\" (no Confirmation was set)", validated.JKT)
	}
}

func TestAccessTokenWithKeyID(t *testing.T) {
	key := generateKey(t)
	now := time.Now()
	p := baseAccessTokenParams(key, now, time.Minute)
	p.KeyID = "key-1"
	tok, _, err := IssueAccessToken(p)
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

// TestAccessTokenConfirmationBinding confirms Validate exposes a
// token's cnf.jkt claim, trusted, via ValidatedAccessToken.JKT — it no
// longer checks that claim against an expected value itself (that
// moved to resource.Verify(), see JKT's own doc comment).
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
	thumbprintStr := thumbprint.String()

	now := time.Now()
	p := baseAccessTokenParams(key, now, time.Minute)
	p.Confirmation = &Confirmation{JKT: thumbprintStr}
	tok, _, err := IssueAccessToken(p)
	if err != nil {
		t.Fatalf("IssueAccessToken: %v", err)
	}

	parsed, err := ParseAccessToken(tok)
	if err != nil {
		t.Fatalf("ParseAccessToken: %v", err)
	}

	validated, err := parsed.Validate(&key.PublicKey, baseAccessTokenPolicy(now))
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if validated.JKT != thumbprintStr {
		t.Fatalf("validated.JKT = %q, want %q", validated.JKT, thumbprintStr)
	}
}

func TestIssueAccessTokenRejectsReservedClaimName(t *testing.T) {
	key := generateKey(t)
	p := baseAccessTokenParams(key, time.Now(), time.Minute)
	p.Parameters = map[string]json.RawMessage{"jti": jsonRaw(t, "custom")}
	if _, _, err := IssueAccessToken(p); err == nil {
		t.Fatalf("IssueAccessToken with reserved claim = nil error, want error")
	}
}

func TestAccessTokenValidateRejectsWrongKey(t *testing.T) {
	key := generateKey(t)
	other := generateKey(t)
	now := time.Now()
	tok, _, err := IssueAccessToken(baseAccessTokenParams(key, now, time.Minute))
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
	tok, _, err := IssueAccessToken(baseAccessTokenParams(key, now, time.Minute))
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
	tok, _, err := IssueAccessToken(baseAccessTokenParams(key, now, time.Minute))
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

// buildRawAccessTokenWithClaims hand-crafts a validly signed, "at+jwt"
// typed ES256 access token from claims, for tests that need shapes
// IssueAccessToken's public API can't produce (a multi-element "aud"
// array — AccessTokenParams.Audience always sends a single string, but
// RFC 9068 §3 doesn't narrow RFC 7519 §4.1.3's general "aud").
func buildRawAccessTokenWithClaims(t *testing.T, key crypto.Signer, claims map[string]any) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","typ":"at+jwt"}`))
	payloadJSON, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	signingInput := header + "." + base64.RawURLEncoding.EncodeToString(payloadJSON)
	ecKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("buildRawAccessTokenWithClaims: key is %T, want *ecdsa.PrivateKey", key)
	}
	return signingInput + "." + signRaw(t, ecKey, signingInput)
}

// RFC 9068 §3 doesn't narrow RFC 7519 §4.1.3's general "aud" definition
// — an access token scoped to more than one resource server must
// validate as long as ExpectedAudience is among them, not only when it
// is the sole entry.
func TestAccessTokenValidateAcceptsMultiValuedAudience(t *testing.T) {
	key := generateKey(t)
	now := time.Now()

	tok := buildRawAccessTokenWithClaims(t, key, map[string]any{
		"iss":       "https://as.example",
		"sub":       "user-1",
		"aud":       []string{"https://rs.example", "https://other-rs.example"},
		"client_id": "client-123",
		"exp":       now.Add(time.Minute).Unix(),
		"iat":       now.Unix(),
		"jti":       "jti-1",
	})

	parsed, err := ParseAccessToken(tok)
	if err != nil {
		t.Fatalf("ParseAccessToken: %v", err)
	}
	if _, err := parsed.Validate(&key.PublicKey, baseAccessTokenPolicy(now)); err != nil {
		t.Fatalf("Validate(multi-valued aud) = %v, want nil error", err)
	}
}

// The containment relaxation in TestAccessTokenValidateAcceptsMultiValuedAudience
// must not become "any element matches" — ExpectedAudience must
// actually be named among the entries.
func TestAccessTokenValidateRejectsMultiValuedAudienceWithoutExpected(t *testing.T) {
	key := generateKey(t)
	now := time.Now()

	tok := buildRawAccessTokenWithClaims(t, key, map[string]any{
		"iss":       "https://as.example",
		"sub":       "user-1",
		"aud":       []string{"https://other-rs.example", "https://yet-another-rs.example"},
		"client_id": "client-123",
		"exp":       now.Add(time.Minute).Unix(),
		"iat":       now.Unix(),
		"jti":       "jti-1",
	})

	parsed, err := ParseAccessToken(tok)
	if err != nil {
		t.Fatalf("ParseAccessToken: %v", err)
	}
	if _, err := parsed.Validate(&key.PublicKey, baseAccessTokenPolicy(now)); !errors.Is(err, ErrAudienceMismatch) {
		t.Fatalf("Validate(multi-valued aud, expected absent) = %v, want ErrAudienceMismatch", err)
	}
}

// TestAccessTokenValidateRejectsExceededLifetime covers the one
// expiry-adjacent check that stays in this package: a defense against
// a forged/over-long exp claim, independent of whether the token has
// actually expired yet as of now. Ordinary "is it expired as of now"
// is no longer checked here at all — see AccessToken.Validate's own
// comment — so there is no equivalent "expired" half of this test
// anymore; that coverage lives in resource/verify_test.go instead,
// exercised through Verify() the same way every caller actually hits
// it.
func TestAccessTokenValidateRejectsExceededLifetime(t *testing.T) {
	key := generateKey(t)
	now := time.Now()

	longTok, _, err := IssueAccessToken(baseAccessTokenParams(key, now, 10*time.Minute))
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
