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

type countingNonceStore struct {
	*memstore.NonceStore
	issued int
}

func (c *countingNonceStore) Issue(ctx context.Context, issuance storage.NonceIssuance) error {
	c.issued++
	return c.NonceStore.Issue(ctx, issuance)
}

// TestVerifyUnauthenticatedProofWritesNothing checks that a DPoP proof
// the caller signed with its own key, presented with an access token the
// verifier doesn't accept, is rejected without writing a nonce or a jti
// record: neither store may be writable by a caller holding no valid
// token.
func TestVerifyUnauthenticatedProofWritesNothing(t *testing.T) {
	now := time.Now()
	target, _ := url.Parse("https://rs.example.com/userinfo")
	issuerKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	attackerKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	attackerJWK, err := jose.NewJWK(attackerKey.Public(), fapi.ES256)
	if err != nil {
		t.Fatalf("NewJWK: %v", err)
	}
	thumbprint, _ := attackerJWK.Thumbprint()

	// A token bound to the attacker's key but signed by a key the
	// verifier doesn't trust — the attacker's own forgery.
	forged, _, err := token.IssueAccessToken(token.AccessTokenParams{
		Signer: attackerKey, Algorithm: fapi.ES256, KeyID: "as-kid",
		Issuer: testIssuer, Subject: "user-1", Audience: testIssuer, ClientID: "client-1", Scope: "openid",
		Confirmation: &token.Confirmation{JKT: thumbprint.String()},
		Now:          now, Lifetime: 5 * time.Minute, Random: rand.Reader,
	})
	if err != nil {
		t.Fatalf("IssueAccessToken: %v", err)
	}

	issuerURL, _ := fapi.ParseIssuerURL(testIssuer)
	accessTokens, err := resource.NewJWTAccessTokens(&fakeIssuerKeySource{set: keys.IssuerKeySet{Keys: []keys.IssuerKey{
		{KeyID: "as-kid", Algorithm: fapi.ES256, PublicKey: issuerKey.Public()},
	}}}, issuerURL, testIssuer, fapi.ES256, 5*time.Minute, 8)
	if err != nil {
		t.Fatalf("NewJWTAccessTokens: %v", err)
	}
	nonces := &countingNonceStore{NonceStore: memstore.NewNonceStore()}
	replay := &fakeReplayStore{}
	cfg := validConfig(t)
	cfg.Limits.DPoPNonceLifetime = time.Minute
	v, err := resource.NewVerifier(cfg, resource.Dependencies{
		AccessTokens: accessTokens, Replay: replay, Revocation: &fakeRevocationChecker{},
		Clock: fixedClock{now: now}, Nonces: nonces, Random: rand.Reader,
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	for i := 0; i < 3; i++ {
		proof, err := dpop.CreateProof(dpop.ProofRequest{
			Signer: attackerKey, Algorithm: fapi.ES256, Method: "GET", URL: target,
			AccessToken: forged, Now: now, Random: rand.Reader,
		})
		if err != nil {
			t.Fatalf("CreateProof: %v", err)
		}
		_, err = v.Verify(context.Background(), resource.VerifyRequest{
			Method: "GET", URL: target, Authorization: "DPoP " + forged, DPoPProofs: []string{proof},
		})
		rerr, ok := err.(*resource.Error)
		if !ok || rerr.Code() != resource.ErrorInvalidToken || rerr.Nonce() != "" {
			t.Fatalf("Verify(forged token) = %v, want invalid_token with no nonce", err)
		}
	}
	if nonces.issued != 0 || len(replay.seen) != 0 {
		t.Fatalf("stores written by an unauthenticated caller: %d nonces, %d jti records", nonces.issued, len(replay.seen))
	}
}

// TestVerifyNonceChallengeDoesNotSpendJTI checks that a proof rejected
// only for lacking a current nonce leaves its jti unrecorded, and that
// the same proof's jti is recorded once it is accepted.
func TestVerifyNonceChallengeDoesNotSpendJTI(t *testing.T) {
	f := newNonceFixture(t, "", nil)
	_, err := f.verify(t)
	if rerr, ok := err.(*resource.Error); !ok || rerr.Code() != resource.ErrorUseDPoPNonce {
		t.Fatalf("Verify(no nonce) = %v, want use_dpop_nonce", err)
	}
	if len(f.replay.seen) != 0 {
		t.Fatalf("jti recorded for a proof rejected by the nonce challenge")
	}

	accepted := newNonceFixture(t, "n", nil)
	if err := accepted.nonces.Issue(context.Background(), storage.NonceIssuance{Nonce: "n", ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if _, err := accepted.verify(t); err != nil {
		t.Fatalf("Verify(valid nonce): %v", err)
	}
	if len(accepted.replay.seen) != 1 {
		t.Fatalf("jti records = %d, want 1 after an accepted proof", len(accepted.replay.seen))
	}
	if _, err := accepted.verify(t); err == nil {
		t.Fatal("Verify(replayed proof) = nil error, want replay rejection")
	}
}
