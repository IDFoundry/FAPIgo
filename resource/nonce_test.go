package resource_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/url"
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

// nonceFixture mirrors newFixture, but builds its DPoP proof with an
// explicit (possibly empty) nonce claim and wires a memstore.NonceStore
// into the verifier, so nonce-challenge tests don't have to duplicate
// every other piece of a valid request. nonces may be shared across
// fixtures (pass the same store to simulate a client's next request
// after a challenge or a successful response), or left nil to get a
// fresh, empty one.
type nonceFixture struct {
	verifier    *resource.Verifier
	nonces      *memstore.NonceStore
	accessToken string
	dpopProof   string
	target      *url.URL
}

func newNonceFixture(t *testing.T, proofNonce string, nonces *memstore.NonceStore) nonceFixture {
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
	target, err := url.Parse("https://rs.example.com/userinfo")
	if err != nil {
		t.Fatalf("parse target url: %v", err)
	}

	accessToken, _, err := token.IssueAccessToken(token.AccessTokenParams{
		Signer: issuerKey, Algorithm: fapi.ES256, KeyID: "as-kid",
		Issuer: testIssuer, Subject: "user-1", Audience: testIssuer,
		ClientID: "client-1", Scope: "openid",
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
		Nonce:       proofNonce,
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
	jwtAccessTokens, err := resource.NewJWTAccessTokens(&fakeIssuerKeySource{set: keys.IssuerKeySet{Keys: []keys.IssuerKey{
		{KeyID: "as-kid", Algorithm: fapi.ES256, PublicKey: issuerKey.Public()},
	}}}, issuerURL, testIssuer, fapi.ES256, 5*time.Minute, 8)
	if err != nil {
		t.Fatalf("NewJWTAccessTokens: %v", err)
	}

	if nonces == nil {
		nonces = memstore.NewNonceStore()
	}
	cfg := validConfig(t)
	cfg.Limits.DPoPNonceLifetime = time.Minute
	v, err := resource.NewVerifier(cfg, resource.Dependencies{
		AccessTokens: jwtAccessTokens,
		Replay:       &fakeReplayStore{},
		Revocation:   &fakeRevocationChecker{},
		Clock:        fixedClock{now: now},
		Nonces:       nonces,
		Random:       rand.Reader,
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	return nonceFixture{verifier: v, nonces: nonces, accessToken: accessToken, dpopProof: dpopProof, target: target}
}

func (f nonceFixture) verify(t *testing.T) (resource.AuthorizationContext, error) {
	t.Helper()
	return f.verifier.Verify(context.Background(), resource.VerifyRequest{
		Method:        "GET",
		URL:           f.target,
		Authorization: "DPoP " + f.accessToken,
		DPoPProof:     f.dpopProof,
	})
}

func TestVerifyNonceDisabledByDefault(t *testing.T) {
	// The ordinary newFixture from verify_test.go never sets
	// Dependencies.Nonces — confirms nonce-challenge support changes
	// nothing for a verifier that never opted in.
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
	if authz.NextDPoPNonce != "" {
		t.Errorf("NextDPoPNonce = %q, want empty when nonces disabled", authz.NextDPoPNonce)
	}
}

func TestVerifyChallengesMissingNonce(t *testing.T) {
	f := newNonceFixture(t, "", nil)

	_, err := f.verify(t)
	if err == nil {
		t.Fatalf("Verify(no nonce) = nil error, want error")
	}
	rerr, ok := err.(*resource.Error)
	if !ok {
		t.Fatalf("error type = %T, want *resource.Error", err)
	}
	if rerr.Code() != resource.ErrorUseDPoPNonce {
		t.Errorf("Code() = %v, want %v", rerr.Code(), resource.ErrorUseDPoPNonce)
	}
	if rerr.Nonce() == "" {
		t.Errorf("Nonce() is empty, want a freshly issued nonce")
	}
}

func TestVerifyChallengesUnknownNonce(t *testing.T) {
	f := newNonceFixture(t, "never-issued", nil)

	_, err := f.verify(t)
	rerr, ok := err.(*resource.Error)
	if !ok {
		t.Fatalf("error type = %T, want *resource.Error", err)
	}
	if rerr.Code() != resource.ErrorUseDPoPNonce {
		t.Errorf("Code() = %v, want %v", rerr.Code(), resource.ErrorUseDPoPNonce)
	}
}

// TestVerifyChallengesExpiredNonce confirms a nonce that was validly
// issued but has since passed its own ExpiresAt is rejected exactly
// like an unknown one — and is still consumed in the process (a stale
// nonce can't be retried indefinitely).
func TestVerifyChallengesExpiredNonce(t *testing.T) {
	nonces := memstore.NewNonceStore()
	if err := nonces.Issue(context.Background(), storage.NonceIssuance{
		Nonce: "stale-nonce", ExpiresAt: time.Now().Add(-time.Minute),
	}); err != nil {
		t.Fatalf("Issue: %v", err)
	}

	f := newNonceFixture(t, "stale-nonce", nonces)
	_, err := f.verify(t)
	rerr, ok := err.(*resource.Error)
	if !ok {
		t.Fatalf("error type = %T, want *resource.Error", err)
	}
	if rerr.Code() != resource.ErrorUseDPoPNonce {
		t.Errorf("Code() = %v, want %v", rerr.Code(), resource.ErrorUseDPoPNonce)
	}
}

func TestVerifyAcceptsValidNonceAndIssuesNext(t *testing.T) {
	first := newNonceFixture(t, "", nil)

	// First call: challenged, but the issued nonce is now valid for the
	// retry — exactly the flow ResourceClient.Do drives on the client
	// side. A real retry is a fresh request (new access token, new DPoP
	// proof/jti), sharing only the resource server's own nonce store.
	_, err := first.verify(t)
	rerr, ok := err.(*resource.Error)
	if !ok {
		t.Fatalf("error type = %T, want *resource.Error", err)
	}
	issued := rerr.Nonce()

	retry := newNonceFixture(t, issued, first.nonces)
	authz, err := retry.verify(t)
	if err != nil {
		t.Fatalf("Verify(valid nonce): %v", err)
	}
	if authz.NextDPoPNonce == "" {
		t.Fatalf("NextDPoPNonce is empty, want a freshly issued nonce")
	}
	if authz.NextDPoPNonce == issued {
		t.Fatalf("NextDPoPNonce = %q, want different from the just-consumed nonce %q", authz.NextDPoPNonce, issued)
	}

	// The consumed nonce is single-use: a third request presenting it
	// again must fail even though it was validly issued once.
	reused := newNonceFixture(t, issued, first.nonces)
	if _, err := reused.verify(t); err == nil {
		t.Fatalf("Verify(reused nonce) = nil error, want error")
	}
}
