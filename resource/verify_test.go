package resource_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"net/url"
	"strings"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/dpop"
	"github.com/idfoundry/fapigo/internal/jose"
	"github.com/idfoundry/fapigo/internal/token"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/resource"
	"github.com/idfoundry/fapigo/storage"
	"github.com/idfoundry/fapigo/storage/memstore"
)

// fixture bundles a signed access token and matching DPoP proof for a
// single simulated request, plus the pieces a test needs to mutate to
// exercise a failure path.
type fixture struct {
	verifier    *resource.Verifier
	accessToken string
	jti         string
	dpopProof   string
	target      *url.URL
	replay      *fakeReplayStore
	revocation  *fakeRevocationChecker
	now         time.Time
}

func newFixture(t *testing.T) fixture {
	t.Helper()

	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate issuer key: %v", err)
	}
	dpopKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate dpop key: %v", err)
	}

	dpopJWK, err := jose.NewJWK(dpopKey.Public(), fapi.ES256)
	if err != nil {
		t.Fatalf("dpop jwk: %v", err)
	}
	thumbprint, err := dpopJWK.Thumbprint()
	if err != nil {
		t.Fatalf("dpop thumbprint: %v", err)
	}

	now := time.Now()
	target, err := url.Parse("https://rs.example.com/accounts")
	if err != nil {
		t.Fatalf("parse target url: %v", err)
	}

	accessToken, jti, err := token.IssueAccessToken(token.AccessTokenParams{
		Signer: issuerKey, Algorithm: fapi.ES256, KeyID: "as-kid",
		Issuer: testIssuer, Subject: "user-1", Audience: testIssuer,
		ClientID: "client-1", Scope: "read write",
		Confirmation: &token.Confirmation{JKT: thumbprint.String()},
		Now:          now, Lifetime: 5 * time.Minute,
		Random: rand.Reader,
	})
	if err != nil {
		t.Fatalf("issue access token: %v", err)
	}

	dpopProof, err := dpop.CreateProof(dpop.ProofRequest{
		Signer: dpopKey, Algorithm: fapi.ES256,
		Method: "GET", URL: target,
		AccessToken: accessToken,
		Now:         now,
		Random:      rand.Reader,
	})
	if err != nil {
		t.Fatalf("create dpop proof: %v", err)
	}

	issuerURL, err := fapi.ParseIssuerURL(testIssuer)
	if err != nil {
		t.Fatalf("ParseIssuerURL: %v", err)
	}
	replay := &fakeReplayStore{}
	revocation := &fakeRevocationChecker{}
	jwtAccessTokens, err := resource.NewJWTAccessTokens(&fakeIssuerKeySource{set: keys.IssuerKeySet{Keys: []keys.IssuerKey{
		{KeyID: "as-kid", Algorithm: fapi.ES256, PublicKey: issuerKey.Public()},
	}}}, issuerURL, testIssuer, fapi.ES256, 5*time.Minute)
	if err != nil {
		t.Fatalf("NewJWTAccessTokens: %v", err)
	}
	v, err := resource.NewVerifier(validConfig(t), resource.Dependencies{
		AccessTokens: jwtAccessTokens,
		Replay:       replay,
		Revocation:   revocation,
		Clock:        fixedClock{now: now},
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	return fixture{verifier: v, accessToken: accessToken, jti: jti, dpopProof: dpopProof, target: target, replay: replay, revocation: revocation, now: now}
}

func TestVerifyAcceptsValidRequest(t *testing.T) {
	f := newFixture(t)

	authz, err := f.verifier.Verify(context.Background(), resource.VerifyRequest{
		Method:        "GET",
		URL:           f.target,
		Authorization: "DPoP " + f.accessToken,
		DPoPProof:     f.dpopProof,
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if authz.Subject != "user-1" {
		t.Errorf("Subject = %q, want user-1", authz.Subject)
	}
	if authz.ClientID != "client-1" {
		t.Errorf("ClientID = %q, want client-1", authz.ClientID)
	}
	if len(authz.Scopes) != 2 || authz.Scopes[0] != "read" || authz.Scopes[1] != "write" {
		t.Errorf("Scopes = %v, want [read write]", authz.Scopes)
	}
	if !authz.ExpiresAt.Equal(f.now.Add(5 * time.Minute).Truncate(time.Second)) {
		t.Errorf("ExpiresAt = %v, want ~%v", authz.ExpiresAt, f.now.Add(5*time.Minute))
	}
	if authz.Key != f.jti {
		t.Errorf("Key = %q, want %q", authz.Key, f.jti)
	}
}

func TestVerifyRejectsRevokedToken(t *testing.T) {
	f := newFixture(t)
	f.revocation.revoked = map[string]bool{f.jti: true}

	_, err := f.verifier.Verify(context.Background(), resource.VerifyRequest{
		Method:        "GET",
		URL:           f.target,
		Authorization: "DPoP " + f.accessToken,
		DPoPProof:     f.dpopProof,
	})
	if err == nil {
		t.Fatalf("Verify(revoked token) = nil error, want error")
	}
	rerr, ok := err.(*resource.Error)
	if !ok {
		t.Fatalf("error type = %T, want *resource.Error", err)
	}
	if rerr.Code() != resource.ErrorInvalidToken {
		t.Errorf("Code() = %v, want %v", rerr.Code(), resource.ErrorInvalidToken)
	}
}

func TestVerifyAcceptsNotRevokedToken(t *testing.T) {
	f := newFixture(t)
	f.revocation.revoked = map[string]bool{"some-other-jti": true}

	if _, err := f.verifier.Verify(context.Background(), resource.VerifyRequest{
		Method:        "GET",
		URL:           f.target,
		Authorization: "DPoP " + f.accessToken,
		DPoPProof:     f.dpopProof,
	}); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestVerifyRejectsReplayedDPoPProof(t *testing.T) {
	f := newFixture(t)
	req := resource.VerifyRequest{
		Method: "GET", URL: f.target,
		Authorization: "DPoP " + f.accessToken,
		DPoPProof:     f.dpopProof,
	}

	if _, err := f.verifier.Verify(context.Background(), req); err != nil {
		t.Fatalf("first Verify: %v", err)
	}
	if _, err := f.verifier.Verify(context.Background(), req); err == nil {
		t.Fatalf("second Verify with replayed proof = nil error, want error")
	}
}

// TestVerifyRejectsBearerSchemeWithoutCertificate covers the "Bearer"
// scheme's own required credential being absent — Bearer is a real,
// accepted scheme now (RFC 8705 §3.4, for mTLS-bound tokens; see
// TestVerifyAcceptsMTLSBoundToken below), so this presents no
// PeerCertificate rather than testing that the scheme itself is
// rejected outright. f's own token is DPoP-bound anyway, so even a
// presented certificate wouldn't help here — see
// TestVerifyRejectsMTLSBoundTokenPresentedAsDPoP for that mismatch case.
func TestVerifyRejectsBearerSchemeWithoutCertificate(t *testing.T) {
	f := newFixture(t)
	_, err := f.verifier.Verify(context.Background(), resource.VerifyRequest{
		Method: "GET", URL: f.target,
		Authorization: "Bearer " + f.accessToken,
	})
	if err == nil {
		t.Fatalf("Verify(Bearer scheme, no certificate) = nil error, want error")
	}
	rerr, ok := err.(*resource.Error)
	if !ok {
		t.Fatalf("error type = %T, want *resource.Error", err)
	}
	if rerr.Code() != resource.ErrorInvalidRequest {
		t.Errorf("Code() = %v, want %v", rerr.Code(), resource.ErrorInvalidRequest)
	}
}

// TestVerifyRejectsUnrecognizedScheme covers a scheme that's neither
// DPoP nor Bearer — the one case truly rejected outright, regardless of
// what credential accompanies it.
func TestVerifyRejectsUnrecognizedScheme(t *testing.T) {
	f := newFixture(t)
	_, err := f.verifier.Verify(context.Background(), resource.VerifyRequest{
		Method: "GET", URL: f.target,
		Authorization: "Basic " + f.accessToken,
	})
	if err == nil {
		t.Fatalf("Verify(unrecognized scheme) = nil error, want error")
	}
	rerr, ok := err.(*resource.Error)
	if !ok {
		t.Fatalf("error type = %T, want *resource.Error", err)
	}
	if rerr.Code() != resource.ErrorInvalidRequest {
		t.Errorf("Code() = %v, want %v", rerr.Code(), resource.ErrorInvalidRequest)
	}
}

func TestVerifyRejectsMissingDPoPHeader(t *testing.T) {
	f := newFixture(t)
	_, err := f.verifier.Verify(context.Background(), resource.VerifyRequest{
		Method: "GET", URL: f.target,
		Authorization: "DPoP " + f.accessToken,
		DPoPProof:     "",
	})
	if err == nil {
		t.Fatalf("Verify(no DPoP header) = nil error, want error")
	}
}

func TestVerifyRejectsWrongDPoPKey(t *testing.T) {
	f := newFixture(t)

	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate other key: %v", err)
	}
	wrongProof, err := dpop.CreateProof(dpop.ProofRequest{
		Signer: otherKey, Algorithm: fapi.ES256,
		Method: "GET", URL: f.target,
		AccessToken: f.accessToken,
		Now:         f.now,
		Random:      rand.Reader,
	})
	if err != nil {
		t.Fatalf("create proof with wrong key: %v", err)
	}

	_, err = f.verifier.Verify(context.Background(), resource.VerifyRequest{
		Method: "GET", URL: f.target,
		Authorization: "DPoP " + f.accessToken,
		DPoPProof:     wrongProof,
	})
	if err == nil {
		t.Fatalf("Verify(wrong DPoP key) = nil error, want error")
	}
}

func TestVerifyRejectsMethodMismatch(t *testing.T) {
	f := newFixture(t)
	_, err := f.verifier.Verify(context.Background(), resource.VerifyRequest{
		Method: "POST", URL: f.target,
		Authorization: "DPoP " + f.accessToken,
		DPoPProof:     f.dpopProof,
	})
	if err == nil {
		t.Fatalf("Verify(method mismatch) = nil error, want error")
	}
}

func TestVerifyRejectsMalformedAuthorizationHeader(t *testing.T) {
	f := newFixture(t)
	cases := []string{"", "DPoP", "not-a-scheme-with-no-space-and-token"}
	for _, authz := range cases {
		_, err := f.verifier.Verify(context.Background(), resource.VerifyRequest{
			Method: "GET", URL: f.target,
			Authorization: authz,
			DPoPProof:     f.dpopProof,
		})
		if err == nil {
			t.Fatalf("Verify(Authorization=%q) = nil error, want error", authz)
		}
	}
}

// opaqueFixture bundles a stored opaque access token and matching
// dpopKey for one simulated request, the opaque counterpart of
// newFixture. lifetime is added to now to compute the stored token's
// ExpiresAt — pass a negative value to build an already-expired token.
type opaqueFixture struct {
	verifier   *resource.Verifier
	store      *memstore.AccessTokenStore
	dpopKey    *ecdsa.PrivateKey
	rawToken   string
	thumbprint jose.Thumbprint
	target     *url.URL
	now        time.Time
}

func newOpaqueFixture(t *testing.T, lifetime time.Duration) opaqueFixture {
	t.Helper()

	store := memstore.NewAccessTokenStore()
	dpopKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate dpop key: %v", err)
	}
	dpopJWK, err := jose.NewJWK(dpopKey.Public(), fapi.ES256)
	if err != nil {
		t.Fatalf("dpop jwk: %v", err)
	}
	thumbprint, err := dpopJWK.Thumbprint()
	if err != nil {
		t.Fatalf("dpop thumbprint: %v", err)
	}

	now := time.Now()
	target, err := url.Parse("https://rs.example.com/accounts")
	if err != nil {
		t.Fatalf("parse target url: %v", err)
	}

	const rawToken = "opaque-access-token-value"
	hash := sha256.Sum256([]byte(rawToken))
	if err := store.CreateAccessToken(context.Background(), storage.NewAccessToken{
		TokenHash: hash, ClientID: "client-1", Subject: "user-1",
		Scope: []string{"read", "write"}, Thumbprint: thumbprint.String(),
		ExpiresAt: now.Add(lifetime),
	}); err != nil {
		t.Fatalf("CreateAccessToken: %v", err)
	}

	v, err := resource.NewVerifier(validConfig(t), resource.Dependencies{
		AccessTokens: resource.OpaqueAccessTokens{Store: store},
		Replay:       &fakeReplayStore{},
		Revocation:   &fakeRevocationChecker{},
		Clock:        fixedClock{now: now},
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	return opaqueFixture{
		verifier: v, store: store, dpopKey: dpopKey, rawToken: rawToken,
		thumbprint: thumbprint, target: target, now: now,
	}
}

// proof builds a DPoP proof over f's token, signed by signer (normally
// f.dpopKey; a test can pass a different key to simulate a proof
// presented alongside a token it isn't bound to).
func (f opaqueFixture) proof(t *testing.T, signer *ecdsa.PrivateKey) string {
	t.Helper()
	proof, err := dpop.CreateProof(dpop.ProofRequest{
		Signer: signer, Algorithm: fapi.ES256,
		Method: "GET", URL: f.target,
		AccessToken: f.rawToken,
		Now:         f.now,
		Random:      rand.Reader,
	})
	if err != nil {
		t.Fatalf("create dpop proof: %v", err)
	}
	return proof
}

// TestVerifyAcceptsOpaqueAccessToken exercises Verify() end to end
// (Authorization header, DPoP proof, revocation check — not just
// ResolveAccessToken in isolation) with OpaqueAccessTokens instead of
// the default JWTAccessTokens, confirming the pluggable
// AccessTokenResolver boundary actually works through the public
// entry point, not just when called directly.
func TestVerifyAcceptsOpaqueAccessToken(t *testing.T) {
	f := newOpaqueFixture(t, 5*time.Minute)

	authz, err := f.verifier.Verify(context.Background(), resource.VerifyRequest{
		Method:        "GET",
		URL:           f.target,
		Authorization: "DPoP " + f.rawToken,
		DPoPProof:     f.proof(t, f.dpopKey),
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if authz.Subject != "user-1" {
		t.Errorf("Subject = %q, want user-1", authz.Subject)
	}
	if authz.ClientID != "client-1" {
		t.Errorf("ClientID = %q, want client-1", authz.ClientID)
	}
	if len(authz.Scopes) != 2 || authz.Scopes[0] != "read" || authz.Scopes[1] != "write" {
		t.Errorf("Scopes = %v, want [read write]", authz.Scopes)
	}
}

// TestVerifyRejectsOpaqueTokenWrongDPoPKey is
// TestVerifyRejectsWrongDPoPKey's opaque-mode counterpart — before
// this refactor, OpaqueAccessTokens checked DPoP binding itself, so
// this path was only exercised via a direct ResolveAccessToken call in
// server/token_test.go, never through the public Verify() entry point.
// Now that binding is checked once, uniformly, by Verify() for every
// AccessTokenResolver, this proves the singular check actually applies
// to the opaque path too, not just JWT.
func TestVerifyRejectsOpaqueTokenWrongDPoPKey(t *testing.T) {
	f := newOpaqueFixture(t, 5*time.Minute)

	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate other key: %v", err)
	}

	_, err = f.verifier.Verify(context.Background(), resource.VerifyRequest{
		Method:        "GET",
		URL:           f.target,
		Authorization: "DPoP " + f.rawToken,
		DPoPProof:     f.proof(t, otherKey),
	})
	if err == nil {
		t.Fatalf("Verify(wrong DPoP key) = nil error, want error")
	}
}

// TestVerifyRejectsExpiredOpaqueToken proves ordinary expiry is
// actually enforced through the public Verify() entry point. Before
// this refactor, no test anywhere exercised "expired token rejected"
// at this level for either access-token format — only deep inside
// internal/token's own now-removed unit test, which never proved
// Verify() itself applied the check.
func TestVerifyRejectsExpiredOpaqueToken(t *testing.T) {
	f := newOpaqueFixture(t, -10*time.Second)

	_, err := f.verifier.Verify(context.Background(), resource.VerifyRequest{
		Method:        "GET",
		URL:           f.target,
		Authorization: "DPoP " + f.rawToken,
		DPoPProof:     f.proof(t, f.dpopKey),
	})
	if err == nil {
		t.Fatalf("Verify(expired token) = nil error, want error")
	}
}

// TestErrorAccessors verifies resource.Error's own public contract —
// Code, PublicDescription, HTTPStatus, Error and Unwrap — which,
// despite being ARCHITECTURE.md design rule 16 ("errors carry their
// own exposure"), had no direct test of its own: existing tests only
// ever check Code(). A malformed DPoP proof is the simplest trigger
// that carries a real underlying cause, exercising Unwrap for real
// rather than against a nil cause.
func TestErrorAccessors(t *testing.T) {
	f := newFixture(t)

	_, err := f.verifier.Verify(context.Background(), resource.VerifyRequest{
		Method:        "GET",
		URL:           f.target,
		Authorization: "DPoP " + f.accessToken,
		DPoPProof:     "not-a-valid-dpop-proof",
	})
	if err == nil {
		t.Fatalf("Verify(malformed DPoP proof) = nil error, want error")
	}
	rerr, ok := err.(*resource.Error)
	if !ok {
		t.Fatalf("error type = %T, want *resource.Error", err)
	}
	if rerr.Code() != resource.ErrorInvalidToken {
		t.Fatalf("Code() = %q, want %q", rerr.Code(), resource.ErrorInvalidToken)
	}
	if rerr.PublicDescription() != "DPoP proof verification failed" {
		t.Fatalf("PublicDescription() = %q, want %q", rerr.PublicDescription(), "DPoP proof verification failed")
	}
	if rerr.HTTPStatus() != 401 {
		t.Fatalf("HTTPStatus() = %d, want 401", rerr.HTTPStatus())
	}
	if !strings.Contains(rerr.Error(), rerr.PublicDescription()) {
		t.Fatalf("Error() = %q, want it to include PublicDescription() %q", rerr.Error(), rerr.PublicDescription())
	}
	if rerr.Unwrap() == nil {
		t.Fatalf("Unwrap() = nil, want the underlying DPoP verification error")
	}
}

// TestErrorAccessorsWithoutCause covers Error()'s other format branch —
// TestErrorAccessors above only ever exercises the with-cause branch.
// An empty Method is the simplest trigger for a resource.Error that
// carries no underlying cause at all.
func TestErrorAccessorsWithoutCause(t *testing.T) {
	f := newFixture(t)

	_, err := f.verifier.Verify(context.Background(), resource.VerifyRequest{
		Method: "",
		URL:    f.target,
	})
	if err == nil {
		t.Fatalf("Verify(empty method) = nil error, want error")
	}
	rerr, ok := err.(*resource.Error)
	if !ok {
		t.Fatalf("error type = %T, want *resource.Error", err)
	}
	if rerr.Unwrap() != nil {
		t.Fatalf("Unwrap() = %v, want nil", rerr.Unwrap())
	}
	if rerr.Error() != "resource: invalid_request: method is required" {
		t.Fatalf("Error() = %q, want %q", rerr.Error(), "resource: invalid_request: method is required")
	}
}
