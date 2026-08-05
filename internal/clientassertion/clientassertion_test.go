package clientassertion

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	fapi "github.com/osanderson/go-fapi"
)

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

func generateKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return key
}

func basePolicy(now time.Time) VerifyPolicy {
	return VerifyPolicy{
		ExpectedClientID: "client-123",
		ExpectedAudience: "https://as.example/token",
		Algorithm:        fapi.ES256,
		Now:              now,
		MaxLifetime:      2 * time.Minute,
	}
}

func createTestAssertion(t *testing.T, key *ecdsa.PrivateKey, now time.Time, lifetime time.Duration) string {
	t.Helper()
	assertion, err := CreateAssertion(AssertionRequest{
		Signer:    key,
		Algorithm: fapi.ES256,
		ClientID:  "client-123",
		Audience:  "https://as.example/token",
		Now:       now,
		Lifetime:  lifetime,
	})
	if err != nil {
		t.Fatalf("CreateAssertion: %v", err)
	}
	return assertion
}

func TestCreateVerifyRoundTrip(t *testing.T) {
	key := generateKey(t)
	now := time.Now()
	assertion := createTestAssertion(t, key, now, time.Minute)

	parsed, err := Parse(assertion)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if parsed.ClaimedIssuer() != "client-123" {
		t.Fatalf("ClaimedIssuer() = %q, want %q", parsed.ClaimedIssuer(), "client-123")
	}
	if parsed.Algorithm() != fapi.ES256 {
		t.Fatalf("Algorithm() = %v, want ES256", parsed.Algorithm())
	}

	verified, err := parsed.Verify(context.Background(), &key.PublicKey, basePolicy(now.Add(time.Second)))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if verified.ClientID != "client-123" {
		t.Fatalf("ClientID = %q, want %q", verified.ClientID, "client-123")
	}
}

func TestVerifyWithKeyID(t *testing.T) {
	key := generateKey(t)
	now := time.Now()
	assertion, err := CreateAssertion(AssertionRequest{
		Signer: key, Algorithm: fapi.ES256, KeyID: "key-1",
		ClientID: "client-123", Audience: "https://as.example/token", Now: now, Lifetime: time.Minute,
	})
	if err != nil {
		t.Fatalf("CreateAssertion: %v", err)
	}

	parsed, err := Parse(assertion)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if parsed.KeyID() != "key-1" {
		t.Fatalf("KeyID() = %q, want %q", parsed.KeyID(), "key-1")
	}
}

func TestVerifyRejectsWrongKey(t *testing.T) {
	key := generateKey(t)
	other := generateKey(t)
	now := time.Now()
	assertion := createTestAssertion(t, key, now, time.Minute)

	parsed, err := Parse(assertion)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if _, err := parsed.Verify(context.Background(), &other.PublicKey, basePolicy(now)); err == nil {
		t.Fatalf("Verify(wrong key) = nil error, want error")
	}
}

func TestVerifyRejectsAlgorithmConfusion(t *testing.T) {
	key := generateKey(t)
	now := time.Now()
	assertion := createTestAssertion(t, key, now, time.Minute)

	parsed, err := Parse(assertion)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	policy := basePolicy(now)
	policy.Algorithm = fapi.PS256
	if _, err := parsed.Verify(context.Background(), &key.PublicKey, policy); err == nil {
		t.Fatalf("Verify(policy alg PS256, header alg ES256) = nil error, want error")
	}
}

func TestVerifyRejectsIssuerSubjectMismatch(t *testing.T) {
	key := generateKey(t)
	now := time.Now()
	assertion := createTestAssertion(t, key, now, time.Minute)

	parsed, err := Parse(assertion)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	policy := basePolicy(now)
	policy.ExpectedClientID = "different-client"
	if _, err := parsed.Verify(context.Background(), &key.PublicKey, policy); !errors.Is(err, ErrIssuerSubjectMismatch) {
		t.Fatalf("Verify(wrong client id) = %v, want ErrIssuerSubjectMismatch", err)
	}
}

func TestVerifyRejectsAudienceMismatch(t *testing.T) {
	key := generateKey(t)
	now := time.Now()
	assertion := createTestAssertion(t, key, now, time.Minute)

	parsed, err := Parse(assertion)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	policy := basePolicy(now)
	policy.ExpectedAudience = "https://as.example/par"
	if _, err := parsed.Verify(context.Background(), &key.PublicKey, policy); !errors.Is(err, ErrAudienceMismatch) {
		t.Fatalf("Verify(wrong audience) = %v, want ErrAudienceMismatch", err)
	}
}

func TestVerifyRejectsExpiredAssertion(t *testing.T) {
	key := generateKey(t)
	now := time.Now()
	assertion := createTestAssertion(t, key, now, time.Minute)

	parsed, err := Parse(assertion)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	policy := basePolicy(now.Add(2 * time.Minute))
	if _, err := parsed.Verify(context.Background(), &key.PublicKey, policy); !errors.Is(err, ErrExpired) {
		t.Fatalf("Verify(expired) = %v, want ErrExpired", err)
	}
}

func TestVerifyRejectsLifetimeExceeded(t *testing.T) {
	key := generateKey(t)
	now := time.Now()
	// exp is 10 minutes out, but policy only allows a 2-minute lifetime.
	assertion := createTestAssertion(t, key, now, 10*time.Minute)

	parsed, err := Parse(assertion)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if _, err := parsed.Verify(context.Background(), &key.PublicKey, basePolicy(now)); !errors.Is(err, ErrLifetimeExceeded) {
		t.Fatalf("Verify(exceeds max lifetime) = %v, want ErrLifetimeExceeded", err)
	}
}

func TestVerifyDetectsReplay(t *testing.T) {
	key := generateKey(t)
	now := time.Now()
	assertion := createTestAssertion(t, key, now, time.Minute)

	replay := newMemoryReplayChecker()
	policy := basePolicy(now)
	policy.Replay = replay

	parsed, err := Parse(assertion)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if _, err := parsed.Verify(context.Background(), &key.PublicKey, policy); err != nil {
		t.Fatalf("first Verify: %v", err)
	}

	parsed2, err := Parse(assertion)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if _, err := parsed2.Verify(context.Background(), &key.PublicKey, policy); err == nil {
		t.Fatalf("second Verify (replay) = nil error, want error")
	}
}

func TestParseRejectsAudienceArray(t *testing.T) {
	// Hand-build an assertion whose "aud" claim is a JSON array rather
	// than a single string, to confirm it's rejected rather than
	// silently accepted as "one of several intended audiences".
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(
		`{"iss":"client-123","sub":"client-123","aud":["https://as.example/token"],"jti":"abc","exp":9999999999}`,
	))
	token := header + "." + payload + "." + base64.RawURLEncoding.EncodeToString(make([]byte, 64))

	if _, err := Parse(token); !errors.Is(err, ErrMalformedClaims) {
		t.Fatalf("Parse(array aud) = %v, want ErrMalformedClaims", err)
	}
}

func TestParseRejectsUnknownClaim(t *testing.T) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(
		`{"iss":"client-123","sub":"client-123","aud":"https://as.example/token","jti":"abc","exp":9999999999,"unexpected":"x"}`,
	))
	token := header + "." + payload + "." + base64.RawURLEncoding.EncodeToString(make([]byte, 64))

	if _, err := Parse(token); !errors.Is(err, ErrMalformedClaims) {
		t.Fatalf("Parse(unknown claim) = %v, want ErrMalformedClaims", err)
	}
}

func TestParseRejectsMissingRequiredClaims(t *testing.T) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256"}`))
	cases := []string{
		`{"sub":"client-123","aud":"https://as.example/token","jti":"abc","exp":9999999999}`,        // missing iss
		`{"iss":"client-123","aud":"https://as.example/token","jti":"abc","exp":9999999999}`,        // missing sub
		`{"iss":"client-123","sub":"client-123","jti":"abc","exp":9999999999}`,                      // missing aud
		`{"iss":"client-123","sub":"client-123","aud":"https://as.example/token","exp":9999999999}`, // missing jti
		`{"iss":"client-123","sub":"client-123","aud":"https://as.example/token","jti":"abc"}`,      // missing exp
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
	assertion := createTestAssertion(t, key, now, time.Minute)

	parsed, err := Parse(assertion)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	policy := basePolicy(now)
	policy.MaxLifetime = 0
	if _, err := parsed.Verify(context.Background(), &key.PublicKey, policy); err == nil {
		t.Fatalf("Verify with zero MaxLifetime = nil error, want error")
	}
}
