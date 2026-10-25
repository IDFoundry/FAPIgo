package resource_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"net/url"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/dpop"
	"github.com/idfoundry/fapigo/internal/jose"
	"github.com/idfoundry/fapigo/resource"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
	"github.com/idfoundry/fapigo/storage/memstore"
)

// TestOpaqueAccessTokenFromAnotherIssuerIsRefused covers two issuers
// whose servers share one AccessTokenStore and name one resource: a
// token tenant A issued is refused by tenant B's resource server, which
// would otherwise act for tenant B's user with the same subject, and
// accepted by tenant A's, which reports tenant A as its issuer.
func TestOpaqueAccessTokenFromAnotherIssuerIsRefused(t *testing.T) {
	const (
		issuerA = "https://idp.example/tenant-a"
		issuerB = "https://idp.example/tenant-b"
		api     = "https://api.example"
	)
	now := time.Now()
	shared := memstore.NewAccessTokenStore()

	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwk, err := jose.NewJWK(clientKey.Public(), fapi.ES256)
	if err != nil {
		t.Fatal(err)
	}
	thumb, err := jwk.Thumbprint()
	if err != nil {
		t.Fatal(err)
	}
	tenantA, err := server.NewOpaqueAccessTokens(shared)
	if err != nil {
		t.Fatal(err)
	}
	raw, _, err := tenantA.IssueAccessToken(context.Background(), server.AccessTokenParams{
		ClientID: "client-1", Subject: "user-42", Scope: []string{"accounts"},
		Thumbprint: thumb.String(), SenderConstrain: storage.SenderConstrainDPoP,
		Issuer: issuerA, Audience: api, Now: now, Lifetime: 5 * time.Minute, Random: rand.Reader,
	})
	if err != nil {
		t.Fatal(err)
	}

	target, _ := url.Parse(api + "/accounts")
	verify := func(issuer string) (resource.AuthorizationContext, error) {
		issuerURL, err := fapi.ParseIssuerURL(issuer)
		if err != nil {
			t.Fatal(err)
		}
		v, err := resource.NewVerifier(validConfig(t), resource.Dependencies{
			AccessTokens: resource.OpaqueAccessTokens{Store: shared, Issuer: issuerURL, Audience: api},
			Replay:       &fakeReplayStore{}, Revocation: &fakeRevocationChecker{}, Clock: fixedClock{now: now},
		})
		if err != nil {
			t.Fatal(err)
		}
		proof, err := dpop.CreateProof(dpop.ProofRequest{
			Signer: clientKey, Algorithm: fapi.ES256, Method: "GET", URL: target,
			AccessToken: raw, Now: now, Random: rand.Reader,
		})
		if err != nil {
			t.Fatal(err)
		}
		return v.Verify(context.Background(), resource.VerifyRequest{
			Method: "GET", URL: target, Authorization: "DPoP " + raw, DPoPProofs: []string{proof},
		})
	}

	_, err = verify(issuerB)
	var rerr *resource.Error
	if !errors.As(err, &rerr) || rerr.Code() != resource.ErrorInvalidToken {
		t.Fatalf("tenant B verifying tenant A's token = %v, want invalid_token", err)
	}
	authz, err := verify(issuerA)
	if err != nil {
		t.Fatalf("tenant A verifying its own token: %v", err)
	}
	if authz.Issuer != issuerA || authz.InternalSubject != "user-42" {
		t.Errorf("tenant A's token: Issuer %q, InternalSubject %q; want %q, user-42", authz.Issuer, authz.InternalSubject, issuerA)
	}
}

func TestServerOpaqueAccessTokensRequiresIssuer(t *testing.T) {
	tokens, err := server.NewOpaqueAccessTokens(memstore.NewAccessTokenStore())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := tokens.IssueAccessToken(context.Background(), server.AccessTokenParams{
		ClientID: "client-1", Subject: "user-1", Audience: "https://api.example",
		Now: time.Now(), Lifetime: time.Minute, Random: rand.Reader,
	}); err == nil {
		t.Fatal("IssueAccessToken without an issuer = nil error, want error")
	}
}
