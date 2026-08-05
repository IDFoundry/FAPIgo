package dpop

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/url"
	"testing"
	"time"

	fapi "github.com/osanderson/go-fapi"
)

// memoryReplayChecker is a minimal in-memory ReplayChecker for tests.
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

var errReplayed = fakeErr("jti already used")

type fakeErr string

func (e fakeErr) Error() string { return string(e) }

func generateKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return key
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("url.Parse(%q): %v", raw, err)
	}
	return u
}

func TestCreateVerifyRoundTrip(t *testing.T) {
	key := generateKey(t)
	now := time.Now()
	target := mustURL(t, "https://as.example/token?ignored=1")

	proof, err := CreateProof(ProofRequest{
		Signer:    key,
		Algorithm: fapi.ES256,
		Method:    "post",
		URL:       target,
		Now:       now,
	})
	if err != nil {
		t.Fatalf("CreateProof: %v", err)
	}

	verified, err := Verify(context.Background(), VerifyRequest{
		Proof:       proof,
		Method:      "POST",
		URL:         target,
		Now:         now.Add(time.Second),
		MaxProofAge: time.Minute,
		Replay:      newMemoryReplayChecker(),
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if verified.IssuedAt.Unix() != now.Unix() {
		t.Fatalf("IssuedAt = %v, want %v", verified.IssuedAt, now)
	}
}

func TestVerifyDetectsReplay(t *testing.T) {
	key := generateKey(t)
	now := time.Now()
	target := mustURL(t, "https://as.example/token")

	proof, err := CreateProof(ProofRequest{
		Signer: key, Algorithm: fapi.ES256, Method: "POST", URL: target, Now: now,
	})
	if err != nil {
		t.Fatalf("CreateProof: %v", err)
	}

	replay := newMemoryReplayChecker()
	req := VerifyRequest{Proof: proof, Method: "POST", URL: target, Now: now, MaxProofAge: time.Minute, Replay: replay}

	if _, err := Verify(context.Background(), req); err != nil {
		t.Fatalf("first Verify: %v", err)
	}
	if _, err := Verify(context.Background(), req); err == nil {
		t.Fatalf("second Verify (replay) = nil error, want error")
	}
}

func TestVerifyRejectsMethodMismatch(t *testing.T) {
	key := generateKey(t)
	now := time.Now()
	target := mustURL(t, "https://as.example/token")
	proof, err := CreateProof(ProofRequest{Signer: key, Algorithm: fapi.ES256, Method: "POST", URL: target, Now: now})
	if err != nil {
		t.Fatalf("CreateProof: %v", err)
	}

	_, err = Verify(context.Background(), VerifyRequest{
		Proof: proof, Method: "GET", URL: target, Now: now, MaxProofAge: time.Minute,
	})
	if err == nil {
		t.Fatalf("Verify(method mismatch) = nil error, want ErrMethodMismatch")
	}
}

func TestVerifyRejectsURIMismatch(t *testing.T) {
	key := generateKey(t)
	now := time.Now()
	proof, err := CreateProof(ProofRequest{
		Signer: key, Algorithm: fapi.ES256, Method: "POST", URL: mustURL(t, "https://as.example/token"), Now: now,
	})
	if err != nil {
		t.Fatalf("CreateProof: %v", err)
	}

	_, err = Verify(context.Background(), VerifyRequest{
		Proof: proof, Method: "POST", URL: mustURL(t, "https://as.example/other"), Now: now, MaxProofAge: time.Minute,
	})
	if err == nil {
		t.Fatalf("Verify(uri mismatch) = nil error, want ErrURIMismatch")
	}
}

func TestVerifyRejectsExpiredProof(t *testing.T) {
	key := generateKey(t)
	now := time.Now()
	target := mustURL(t, "https://as.example/token")
	proof, err := CreateProof(ProofRequest{Signer: key, Algorithm: fapi.ES256, Method: "POST", URL: target, Now: now})
	if err != nil {
		t.Fatalf("CreateProof: %v", err)
	}

	_, err = Verify(context.Background(), VerifyRequest{
		Proof: proof, Method: "POST", URL: target, Now: now.Add(2 * time.Minute), MaxProofAge: time.Minute,
	})
	if err == nil {
		t.Fatalf("Verify(expired) = nil error, want ErrExpired")
	}
}

func TestVerifyRejectsFutureDatedProof(t *testing.T) {
	key := generateKey(t)
	now := time.Now()
	target := mustURL(t, "https://as.example/token")
	proof, err := CreateProof(ProofRequest{
		Signer: key, Algorithm: fapi.ES256, Method: "POST", URL: target, Now: now.Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("CreateProof: %v", err)
	}

	_, err = Verify(context.Background(), VerifyRequest{
		Proof: proof, Method: "POST", URL: target, Now: now, MaxProofAge: time.Minute, MaxClockSkew: time.Second,
	})
	if err == nil {
		t.Fatalf("Verify(future-dated) = nil error, want ErrIssuedInFuture")
	}
}

func TestVerifyAccessTokenHashBinding(t *testing.T) {
	key := generateKey(t)
	now := time.Now()
	target := mustURL(t, "https://rs.example/accounts")

	proof, err := CreateProof(ProofRequest{
		Signer: key, Algorithm: fapi.ES256, Method: "GET", URL: target, Now: now, AccessToken: "at-value",
	})
	if err != nil {
		t.Fatalf("CreateProof: %v", err)
	}

	if _, err := Verify(context.Background(), VerifyRequest{
		Proof: proof, Method: "GET", URL: target, Now: now, MaxProofAge: time.Minute, AccessToken: "at-value",
	}); err != nil {
		t.Fatalf("Verify(correct access token): %v", err)
	}

	if _, err := Verify(context.Background(), VerifyRequest{
		Proof: proof, Method: "GET", URL: target, Now: now, MaxProofAge: time.Minute, AccessToken: "wrong-value",
	}); err == nil {
		t.Fatalf("Verify(wrong access token) = nil error, want ErrAccessTokenHashMismatch")
	}

	if _, err := Verify(context.Background(), VerifyRequest{
		Proof: proof, Method: "GET", URL: target, Now: now, MaxProofAge: time.Minute,
	}); err == nil {
		t.Fatalf("Verify(no access token, but proof has ath) = nil error, want error")
	}
}

func TestVerifyRejectsUnexpectedAccessTokenHash(t *testing.T) {
	key := generateKey(t)
	now := time.Now()
	target := mustURL(t, "https://as.example/token")

	// A proof created for a token request has no access token yet.
	proof, err := CreateProof(ProofRequest{Signer: key, Algorithm: fapi.ES256, Method: "POST", URL: target, Now: now})
	if err != nil {
		t.Fatalf("CreateProof: %v", err)
	}

	_, err = Verify(context.Background(), VerifyRequest{
		Proof: proof, Method: "POST", URL: target, Now: now, MaxProofAge: time.Minute, AccessToken: "unexpected",
	})
	if err == nil {
		t.Fatalf("Verify(access token supplied but proof has no ath) = nil error, want error")
	}
}

func TestVerifyNonceBinding(t *testing.T) {
	key := generateKey(t)
	now := time.Now()
	target := mustURL(t, "https://as.example/token")

	proof, err := CreateProof(ProofRequest{
		Signer: key, Algorithm: fapi.ES256, Method: "POST", URL: target, Now: now, Nonce: "server-nonce",
	})
	if err != nil {
		t.Fatalf("CreateProof: %v", err)
	}

	if _, err := Verify(context.Background(), VerifyRequest{
		Proof: proof, Method: "POST", URL: target, Now: now, MaxProofAge: time.Minute, RequiredNonce: "server-nonce",
	}); err != nil {
		t.Fatalf("Verify(correct nonce): %v", err)
	}

	if _, err := Verify(context.Background(), VerifyRequest{
		Proof: proof, Method: "POST", URL: target, Now: now, MaxProofAge: time.Minute, RequiredNonce: "different-nonce",
	}); err == nil {
		t.Fatalf("Verify(wrong nonce) = nil error, want ErrNonceMismatch")
	}
}

func TestVerifyRequiresMaxProofAge(t *testing.T) {
	key := generateKey(t)
	now := time.Now()
	target := mustURL(t, "https://as.example/token")
	proof, err := CreateProof(ProofRequest{Signer: key, Algorithm: fapi.ES256, Method: "POST", URL: target, Now: now})
	if err != nil {
		t.Fatalf("CreateProof: %v", err)
	}

	_, err = Verify(context.Background(), VerifyRequest{Proof: proof, Method: "POST", URL: target, Now: now})
	if err == nil {
		t.Fatalf("Verify with zero MaxProofAge = nil error, want error")
	}
}
