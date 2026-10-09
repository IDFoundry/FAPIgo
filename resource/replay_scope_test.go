package resource_test

import (
	"bytes"
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
)

// TestVerifyScopesDPoPReplayToTheKey: a DPoP proof's jti is recorded for
// the key that signed it, so a proof from another client's key carrying
// the same jti doesn't make this key's proof fail as a replay. The same
// key sending its jti twice is still refused.
func TestVerifyScopesDPoPReplayToTheKey(t *testing.T) {
	now := time.Now()
	target, err := url.Parse("https://rs.example.com/accounts")
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}
	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate issuer key: %v", err)
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
	v, err := resource.NewVerifier(validConfig(t), resource.Dependencies{
		AccessTokens: jwtAccessTokens,
		Replay:       &fakeReplayStore{},
		Revocation:   &fakeRevocationChecker{},
		Clock:        fixedClock{now: now},
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	// request returns a request carrying a token bound to key and a proof
	// whose jti is the same for every key.
	request := func(key *ecdsa.PrivateKey, clientID string) resource.VerifyRequest {
		t.Helper()
		jwk, err := jose.NewJWK(key.Public(), fapi.ES256)
		if err != nil {
			t.Fatalf("NewJWK: %v", err)
		}
		thumbprint, err := jwk.Thumbprint()
		if err != nil {
			t.Fatalf("Thumbprint: %v", err)
		}
		accessToken, _, err := token.IssueAccessToken(token.AccessTokenParams{
			Signer: issuerKey, Algorithm: fapi.ES256, KeyID: "as-kid",
			Issuer: testIssuer, Subject: "user-1", Audience: testIssuer,
			ClientID: clientID, Scope: "read",
			Confirmation: &token.Confirmation{JKT: thumbprint.String()},
			Now:          now, Lifetime: 5 * time.Minute, Random: rand.Reader,
		})
		if err != nil {
			t.Fatalf("IssueAccessToken: %v", err)
		}
		proof, err := dpop.CreateProof(dpop.ProofRequest{
			Signer: key, Algorithm: fapi.ES256, Method: "GET", URL: target,
			AccessToken: accessToken, Now: now,
			Random: bytes.NewReader(bytes.Repeat([]byte{7}, 16)),
		})
		if err != nil {
			t.Fatalf("CreateProof: %v", err)
		}
		return resource.VerifyRequest{Method: "GET", URL: target, Authorization: "DPoP " + accessToken, DPoPProofs: []string{proof}}
	}

	attackerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	victimKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	ctx := context.Background()
	if _, err := v.Verify(ctx, request(attackerKey, "client-2")); err != nil {
		t.Fatalf("Verify with the first key's proof: %v", err)
	}
	victim := request(victimKey, "client-1")
	if _, err := v.Verify(ctx, victim); err != nil {
		t.Fatalf("Verify with another key's proof carrying the same jti: %v", err)
	}
	if _, err := v.Verify(ctx, victim); err == nil {
		t.Fatal("Verify replaying a key's own proof = nil error, want error")
	}
}
