package resource_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/url"
	"strconv"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/dpop"
	"github.com/idfoundry/fapigo/internal/jose"
	"github.com/idfoundry/fapigo/internal/token"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/resource"
)

// verifyJWTAccessTokenWith presents, at now, a DPoP-bound JWT access
// token issued at issuedAt and carrying extra (such as an nbf) to a
// Verifier with validConfig's 5s clock skew.
func verifyJWTAccessTokenWith(t *testing.T, now, issuedAt time.Time, extra map[string]json.RawMessage) error {
	t.Helper()
	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dpopKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dpopJWK, err := jose.NewJWK(dpopKey.Public(), fapi.ES256)
	if err != nil {
		t.Fatal(err)
	}
	thumbprint, err := dpopJWK.Thumbprint()
	if err != nil {
		t.Fatal(err)
	}
	target, _ := url.Parse("https://rs.example.com/accounts")
	accessToken, _, err := token.IssueAccessToken(token.AccessTokenParams{
		Signer: issuerKey, Algorithm: fapi.ES256, KeyID: "as-kid",
		Issuer: testIssuer, Subject: "user-1", Audience: testIssuer,
		ClientID: "client-1", Scope: "read",
		Confirmation: &token.Confirmation{JKT: thumbprint.String()},
		Now:          issuedAt, Lifetime: time.Minute, Random: rand.Reader,
		Parameters: extra,
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	proof, err := dpop.CreateProof(dpop.ProofRequest{
		Signer: dpopKey, Algorithm: fapi.ES256, Method: "GET", URL: target,
		AccessToken: accessToken, Now: now, Random: rand.Reader,
	})
	if err != nil {
		t.Fatal(err)
	}
	issuerURL, _ := fapi.ParseIssuerURL(testIssuer)
	jwtAccessTokens, err := resource.NewJWTAccessTokens(&fakeIssuerKeySource{set: keys.IssuerKeySet{Keys: []keys.IssuerKey{
		{KeyID: "as-kid", Algorithm: fapi.ES256, PublicKey: issuerKey.Public()},
	}}}, issuerURL, testIssuer, fapi.ES256, time.Minute, 8)
	if err != nil {
		t.Fatal(err)
	}
	v, err := resource.NewVerifier(validConfig(t), resource.Dependencies{
		AccessTokens: jwtAccessTokens, Replay: &fakeReplayStore{}, Revocation: &fakeRevocationChecker{}, Clock: fixedClock{now: now},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = v.Verify(context.Background(), resource.VerifyRequest{
		Method: "GET", URL: target, Authorization: "DPoP " + accessToken, DPoPProofs: []string{proof},
	})
	return err
}

// RFC 7519 §4.1.5: a JWT access token "MUST NOT be accepted for
// processing" before its nbf. A FAPIgo authorization server never sets
// one, but JWTAccessTokens verifies any RFC 9068 issuer's tokens.
func TestVerifyRefusesNotYetValidJWTAccessToken(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	nbf := func(at time.Time) map[string]json.RawMessage {
		return map[string]json.RawMessage{"nbf": json.RawMessage(strconv.FormatInt(at.Unix(), 10))}
	}
	if err := verifyJWTAccessTokenWith(t, now, now, nbf(now.Add(time.Hour))); err == nil {
		t.Error("Verify accepted a token whose nbf is an hour ahead")
	}
	if err := verifyJWTAccessTokenWith(t, now, now, nbf(now.Add(5*time.Second))); err != nil {
		t.Errorf("Verify of a token whose nbf is within the clock skew = %v, want success", err)
	}
}

// FAPI 2.0 Security Profile §5.3.2.1 item 13: a JWT whose iat is further
// in the future than the clock skew is refused, while an issuer whose
// clock runs ahead within it can still use the full lifetime.
func TestVerifyBoundsJWTAccessTokenIssuedAt(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	if err := verifyJWTAccessTokenWith(t, now, now.Add(5*time.Second), nil); err != nil {
		t.Errorf("Verify of a full-lifetime token from an issuer 5s ahead = %v, want success", err)
	}
	if err := verifyJWTAccessTokenWith(t, now, now.Add(6*time.Second), nil); err == nil {
		t.Error("Verify accepted a token issued 6s in the future with a 5s skew")
	}
}
