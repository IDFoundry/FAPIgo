package dpop

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"net/url"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/canonical"
	"github.com/idfoundry/fapigo/internal/jose"
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

// RFC 9449 §4.3: "the query and fragment parts of the htu... are
// ignored", and RFC 3986 makes scheme/host case-insensitive. A proof
// whose htu differs from the request URL only in those respects must
// still verify.
func TestVerifyToleratesHTUQueryFragmentAndCase(t *testing.T) {
	key := generateKey(t)
	now := time.Now()
	jwk, err := jose.NewJWK(&key.PublicKey, fapi.ES256)
	if err != nil {
		t.Fatalf("NewJWK: %v", err)
	}
	payload := fmt.Sprintf(`{"jti":"x","htm":"POST","htu":"HTTPS://AS.EXAMPLE/token?dummy1=lorem#frag","iat":%d}`, now.Unix())
	proof, err := jose.Sign(key, jose.Header{Algorithm: fapi.ES256, Type: "dpop+jwt", JWK: &jwk}, []byte(payload))
	if err != nil {
		t.Fatalf("jose.Sign: %v", err)
	}

	if _, err := Verify(context.Background(), VerifyRequest{
		Proof: proof, Method: "POST", URL: mustURL(t, "https://as.example/token"), Now: now, MaxProofAge: time.Minute,
		Replay: newMemoryReplayChecker(),
	}); err != nil {
		t.Fatalf("Verify(htu differs only in query/fragment/case) = %v, want nil", err)
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

// TestVerifyReturnsProofNonce confirms VerifiedProof.Nonce surfaces the
// proof's own "nonce" claim unconditionally — even with no RequiredNonce
// set — since a caller implementing single-use, issued-per-challenge
// nonces (unlike RequiredNonce's compare-to-one-known-value check) needs
// the presented value itself to look up, not just a pass/fail verdict.
func TestVerifyReturnsProofNonce(t *testing.T) {
	key := generateKey(t)
	now := time.Now()
	target := mustURL(t, "https://as.example/token")

	withNonce, err := CreateProof(ProofRequest{
		Signer: key, Algorithm: fapi.ES256, Method: "POST", URL: target, Now: now, Nonce: "presented-nonce",
	})
	if err != nil {
		t.Fatalf("CreateProof: %v", err)
	}
	verified, err := Verify(context.Background(), VerifyRequest{
		Proof: withNonce, Method: "POST", URL: target, Now: now, MaxProofAge: time.Minute,
	})
	if err != nil {
		t.Fatalf("Verify(with nonce): %v", err)
	}
	if verified.Nonce != "presented-nonce" {
		t.Fatalf("VerifiedProof.Nonce = %q, want %q", verified.Nonce, "presented-nonce")
	}

	withoutNonce, err := CreateProof(ProofRequest{Signer: key, Algorithm: fapi.ES256, Method: "POST", URL: target, Now: now})
	if err != nil {
		t.Fatalf("CreateProof: %v", err)
	}
	verified, err = Verify(context.Background(), VerifyRequest{
		Proof: withoutNonce, Method: "POST", URL: target, Now: now, MaxProofAge: time.Minute,
	})
	if err != nil {
		t.Fatalf("Verify(without nonce): %v", err)
	}
	if verified.Nonce != "" {
		t.Fatalf("VerifiedProof.Nonce = %q, want empty", verified.Nonce)
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

func TestCreateProofRejectsInvalidInput(t *testing.T) {
	key := generateKey(t)
	now := time.Now()
	target := mustURL(t, "https://as.example/token")
	validReq := func() ProofRequest {
		return ProofRequest{Signer: key, Algorithm: fapi.ES256, Method: "POST", URL: target, Now: now}
	}
	cases := map[string]func(*ProofRequest){
		"nil signer":        func(r *ProofRequest) { r.Signer = nil },
		"invalid algorithm": func(r *ProofRequest) { r.Algorithm = 0 },
		"empty method":      func(r *ProofRequest) { r.Method = "" },
		"nil url":           func(r *ProofRequest) { r.URL = nil },
		"zero now":          func(r *ProofRequest) { r.Now = time.Time{} },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			req := validReq()
			mutate(&req)
			if _, err := CreateProof(req); err == nil {
				t.Fatalf("CreateProof(%s) = nil error, want error", name)
			}
		})
	}
}

func TestVerifyRejectsInvalidRequest(t *testing.T) {
	key := generateKey(t)
	now := time.Now()
	target := mustURL(t, "https://as.example/token")
	proof, err := CreateProof(ProofRequest{Signer: key, Algorithm: fapi.ES256, Method: "POST", URL: target, Now: now})
	if err != nil {
		t.Fatalf("CreateProof: %v", err)
	}
	validReq := func() VerifyRequest {
		return VerifyRequest{Proof: proof, Method: "POST", URL: target, Now: now, MaxProofAge: time.Minute}
	}
	cases := map[string]func(*VerifyRequest){
		"empty method": func(r *VerifyRequest) { r.Method = "" },
		"nil url":      func(r *VerifyRequest) { r.URL = nil },
		"zero now":     func(r *VerifyRequest) { r.Now = time.Time{} },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			req := validReq()
			mutate(&req)
			if _, err := Verify(context.Background(), req); err == nil {
				t.Fatalf("Verify(%s) = nil error, want error", name)
			}
		})
	}
}

func TestVerifyRejectsWrongJWSType(t *testing.T) {
	// A proof-shaped JWS whose "typ" header is not "dpop+jwt" — e.g. a
	// request object or client assertion accidentally presented as a
	// DPoP proof — must be rejected by type, not merely by claim shape.
	key := generateKey(t)
	now := time.Now()
	target := mustURL(t, "https://as.example/token")

	otherJWT, err := jose.Sign(key, jose.Header{Algorithm: fapi.ES256, Type: "not-dpop+jwt"},
		[]byte(fmt.Sprintf(`{"jti":"x","htm":"POST","htu":%q,"iat":%d}`, canonical.URI(target), now.Unix())))
	if err != nil {
		t.Fatalf("jose.Sign: %v", err)
	}

	_, err = Verify(context.Background(), VerifyRequest{
		Proof: otherJWT, Method: "POST", URL: target, Now: now, MaxProofAge: time.Minute,
	})
	if !errors.Is(err, ErrWrongType) {
		t.Fatalf("Verify(wrong typ) = %v, want ErrWrongType", err)
	}
}

func TestVerifyRejectsMissingEmbeddedJWK(t *testing.T) {
	// A proof whose header carries no embedded "jwk" at all can't be
	// verified against anything — RFC 9449 requires it.
	key := generateKey(t)
	now := time.Now()
	target := mustURL(t, "https://as.example/token")

	noJWKProof, err := jose.Sign(key, jose.Header{Algorithm: fapi.ES256, Type: "dpop+jwt"},
		[]byte(fmt.Sprintf(`{"jti":"x","htm":"POST","htu":%q,"iat":%d}`, canonical.URI(target), now.Unix())))
	if err != nil {
		t.Fatalf("jose.Sign: %v", err)
	}

	_, err = Verify(context.Background(), VerifyRequest{
		Proof: noJWKProof, Method: "POST", URL: target, Now: now, MaxProofAge: time.Minute,
	})
	if !errors.Is(err, ErrMissingJWK) {
		t.Fatalf("Verify(no embedded jwk) = %v, want ErrMissingJWK", err)
	}
}

func TestParseClaimsRejectsMissingRequiredMembers(t *testing.T) {
	key := generateKey(t)
	now := time.Now()
	target := mustURL(t, "https://as.example/token")
	jwk, err := jose.NewJWK(&key.PublicKey, fapi.ES256)
	if err != nil {
		t.Fatalf("NewJWK: %v", err)
	}

	cases := map[string]string{
		"missing jti": fmt.Sprintf(`{"htm":"POST","htu":%q,"iat":%d}`, canonical.URI(target), now.Unix()),
		"missing htm": fmt.Sprintf(`{"jti":"x","htu":%q,"iat":%d}`, canonical.URI(target), now.Unix()),
		"missing htu": fmt.Sprintf(`{"jti":"x","htm":"POST","iat":%d}`, now.Unix()),
	}
	for name, payload := range cases {
		t.Run(name, func(t *testing.T) {
			proof, err := jose.Sign(key, jose.Header{Algorithm: fapi.ES256, Type: "dpop+jwt", JWK: &jwk}, []byte(payload))
			if err != nil {
				t.Fatalf("jose.Sign: %v", err)
			}
			_, err = Verify(context.Background(), VerifyRequest{
				Proof: proof, Method: "POST", URL: target, Now: now, MaxProofAge: time.Minute,
			})
			if !errors.Is(err, ErrMalformedClaims) {
				t.Fatalf("Verify(%s) = %v, want ErrMalformedClaims", name, err)
			}
		})
	}
}

// FAPI2SPFinalCheckDpopProofNbfExp in the OIDF conformance suite sends a
// DPoP proof carrying "nbf" and "exp" alongside the required claims —
// RFC 9449 doesn't define them, but doesn't forbid them either (a DPoP
// proof is a JWT; RFC 7519 §4 permits registered claims generally), so
// a conformant server must not reject the proof merely for their
// presence.
func TestParseClaimsAcceptsNbfAndExp(t *testing.T) {
	key := generateKey(t)
	now := time.Now()
	target := mustURL(t, "https://as.example/token")
	jwk, err := jose.NewJWK(&key.PublicKey, fapi.ES256)
	if err != nil {
		t.Fatalf("NewJWK: %v", err)
	}
	payload := fmt.Sprintf(`{"jti":"x","htm":"POST","htu":%q,"iat":%d,"nbf":%d,"exp":%d}`,
		canonical.URI(target), now.Unix(), now.Unix(), now.Add(5*time.Minute).Unix())
	proof, err := jose.Sign(key, jose.Header{Algorithm: fapi.ES256, Type: "dpop+jwt", JWK: &jwk}, []byte(payload))
	if err != nil {
		t.Fatalf("jose.Sign: %v", err)
	}
	if _, err := Verify(context.Background(), VerifyRequest{
		Proof: proof, Method: "POST", URL: target, Now: now, MaxProofAge: time.Minute,
		Replay: newMemoryReplayChecker(),
	}); err != nil {
		t.Fatalf("Verify(nbf and exp present) = %v, want nil", err)
	}
}

// FAPI2SPFinalCheckDpopProofUnknownClaim in the OIDF conformance suite
// sends a DPoP proof carrying an arbitrary private claim
// ("tx_id_key") the server has no opinion on — RFC 7519 §4 JWT claim
// extensibility means a conformant server must tolerate it rather than
// rejecting the proof outright.
func TestParseClaimsToleratesArbitraryUnrecognizedMember(t *testing.T) {
	key := generateKey(t)
	now := time.Now()
	target := mustURL(t, "https://as.example/token")
	jwk, err := jose.NewJWK(&key.PublicKey, fapi.ES256)
	if err != nil {
		t.Fatalf("NewJWK: %v", err)
	}
	payload := fmt.Sprintf(`{"jti":"x","htm":"POST","htu":%q,"iat":%d,"tx_id_key":"x"}`,
		canonical.URI(target), now.Unix())
	proof, err := jose.Sign(key, jose.Header{Algorithm: fapi.ES256, Type: "dpop+jwt", JWK: &jwk}, []byte(payload))
	if err != nil {
		t.Fatalf("jose.Sign: %v", err)
	}
	if _, err := Verify(context.Background(), VerifyRequest{
		Proof: proof, Method: "POST", URL: target, Now: now, MaxProofAge: time.Minute,
		Replay: newMemoryReplayChecker(),
	}); err != nil {
		t.Fatalf("Verify(unrecognized private claim) = %v, want nil", err)
	}
}
