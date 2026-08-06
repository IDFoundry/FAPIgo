package clientassertion

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
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

func TestCreateAssertionRejectsInvalidInput(t *testing.T) {
	key := generateKey(t)
	now := time.Now()
	validReq := func() AssertionRequest {
		return AssertionRequest{
			Signer: key, Algorithm: fapi.ES256,
			ClientID: "client-123", Audience: "https://as.example/token",
			Now: now, Lifetime: time.Minute,
		}
	}
	cases := map[string]func(*AssertionRequest){
		"nil signer":        func(r *AssertionRequest) { r.Signer = nil },
		"invalid algorithm": func(r *AssertionRequest) { r.Algorithm = 0 },
		"empty client id":   func(r *AssertionRequest) { r.ClientID = "" },
		"empty audience":    func(r *AssertionRequest) { r.Audience = "" },
		"zero now":          func(r *AssertionRequest) { r.Now = time.Time{} },
		"zero lifetime":     func(r *AssertionRequest) { r.Lifetime = 0 },
		"negative lifetime": func(r *AssertionRequest) { r.Lifetime = -time.Second },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			req := validReq()
			mutate(&req)
			if _, err := CreateAssertion(req); err == nil {
				t.Fatalf("CreateAssertion(%s) = nil error, want error", name)
			}
		})
	}
}

func TestVerifyRejectsInvalidPolicy(t *testing.T) {
	key := generateKey(t)
	now := time.Now()
	assertion := createTestAssertion(t, key, now, time.Minute)
	parsed, err := Parse(assertion)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	cases := map[string]func(*VerifyPolicy){
		"empty expected client id": func(p *VerifyPolicy) { p.ExpectedClientID = "" },
		"empty expected audience":  func(p *VerifyPolicy) { p.ExpectedAudience = "" },
		"zero now":                 func(p *VerifyPolicy) { p.Now = time.Time{} },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			policy := basePolicy(now)
			mutate(&policy)
			if _, err := parsed.Verify(context.Background(), &key.PublicKey, policy); err == nil {
				t.Fatalf("Verify(%s) = nil error, want error", name)
			}
		})
	}
}

func TestVerifyRejectsNotYetValidAssertion(t *testing.T) {
	key := generateKey(t)
	now := time.Now()

	// Hand-build an assertion with an "nbf" claim in the future — CreateAssertion
	// never sets nbf itself, so this exercises the check directly rather
	// than via a fixture CreateAssertion could produce.
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256"}`))
	nbf := now.Add(time.Hour).Unix()
	exp := now.Add(2 * time.Hour).Unix()
	payloadJSON := fmt.Sprintf(
		`{"iss":"client-123","sub":"client-123","aud":"https://as.example/token","jti":"abc","exp":%d,"nbf":%d}`,
		exp, nbf,
	)
	payload := base64.RawURLEncoding.EncodeToString([]byte(payloadJSON))
	signingInput := header + "." + payload
	hash := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, key, hash[:])
	if err != nil {
		t.Fatalf("ecdsa.Sign: %v", err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	token := signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)

	parsed, err := Parse(token)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	policy := basePolicy(now)
	policy.MaxLifetime = 3 * time.Hour
	if _, err := parsed.Verify(context.Background(), &key.PublicKey, policy); !errors.Is(err, ErrNotYetValid) {
		t.Fatalf("Verify(nbf in future) = %v, want ErrNotYetValid", err)
	}
}

func TestClaimedSubject(t *testing.T) {
	key := generateKey(t)
	now := time.Now()
	assertion := createTestAssertion(t, key, now, time.Minute)
	parsed, err := Parse(assertion)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if parsed.ClaimedSubject() != "client-123" {
		t.Fatalf("ClaimedSubject() = %q, want %q", parsed.ClaimedSubject(), "client-123")
	}
}

// failingReader always returns an error, for exercising CreateAssertion's
// jti-generation failure path.
type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, fmt.Errorf("simulated read failure") }

func TestCreateAssertionPropagatesRandomSourceError(t *testing.T) {
	key := generateKey(t)
	_, err := CreateAssertion(AssertionRequest{
		Signer: key, Algorithm: fapi.ES256,
		ClientID: "client-123", Audience: "https://as.example/token",
		Now: time.Now(), Lifetime: time.Minute, Random: failingReader{},
	})
	if err == nil {
		t.Fatalf("CreateAssertion(failing random source) = nil error, want error")
	}
}
