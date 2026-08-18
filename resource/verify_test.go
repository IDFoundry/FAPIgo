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
)

// fixture bundles a signed access token and matching DPoP proof for a
// single simulated request, plus the pieces a test needs to mutate to
// exercise a failure path.
type fixture struct {
	verifier    *resource.Verifier
	accessToken string
	dpopProof   string
	target      *url.URL
	replay      *fakeReplayStore
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

	accessToken, err := token.IssueAccessToken(token.AccessTokenParams{
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

	replay := &fakeReplayStore{}
	v, err := resource.NewVerifier(validConfig(t), resource.Dependencies{
		IssuerKeys: &fakeIssuerKeySource{set: keys.IssuerKeySet{Keys: []keys.IssuerKey{
			{KeyID: "as-kid", Algorithm: fapi.ES256, PublicKey: issuerKey.Public()},
		}}},
		Replay: replay,
		Clock:  fixedClock{now: now},
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	return fixture{verifier: v, accessToken: accessToken, dpopProof: dpopProof, target: target, replay: replay, now: now}
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

func TestVerifyRejectsBearerScheme(t *testing.T) {
	f := newFixture(t)
	_, err := f.verifier.Verify(context.Background(), resource.VerifyRequest{
		Method: "GET", URL: f.target,
		Authorization: "Bearer " + f.accessToken,
		DPoPProof:     f.dpopProof,
	})
	if err == nil {
		t.Fatalf("Verify(Bearer scheme) = nil error, want error")
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
