package resource_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/token"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/resource"
	"github.com/idfoundry/fapigo/server"
)

// gettingStartedMaxTokenLifetime is the MaxTokenLifetime
// GETTING_STARTED.md step 7 passes to resource.NewJWTAccessTokens.
const gettingStartedMaxTokenLifetime = 10 * time.Minute

// TestGettingStartedStep7MaxTokenLifetimeAcceptsRecommendedTokens: a
// resource server configured as GETTING_STARTED.md step 7 shows accepts
// an access token issued for the full lifetime server.RecommendedLimits
// gives one. A MaxTokenLifetime below the authorization server's
// AccessTokenLifetime refuses every token it issues.
func TestGettingStartedStep7MaxTokenLifetimeAcceptsRecommendedTokens(t *testing.T) {
	issuer, err := fapi.ParseIssuerURL(testIssuer)
	if err != nil {
		t.Fatalf("ParseIssuerURL: %v", err)
	}
	signingKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	now := time.Now()
	accessToken, _, err := token.IssueAccessToken(token.AccessTokenParams{
		Signer: signingKey, Algorithm: fapi.ES256,
		Issuer: testIssuer, Subject: "user-1", Audience: testIssuer,
		ClientID: "client-1", Now: now, Lifetime: server.RecommendedLimits().AccessTokenLifetime,
		Random: rand.Reader,
	})
	if err != nil {
		t.Fatalf("IssueAccessToken: %v", err)
	}
	jwt, err := resource.NewJWTAccessTokens(
		&fakeIssuerKeySource{set: keys.IssuerKeySet{Keys: []keys.IssuerKey{{KeyID: "kid-1", Algorithm: fapi.ES256, PublicKey: signingKey.Public()}}}},
		issuer, testIssuer, fapi.ES256, gettingStartedMaxTokenLifetime, 8,
	)
	if err != nil {
		t.Fatalf("NewJWTAccessTokens: %v", err)
	}
	if _, err := jwt.ResolveAccessToken(context.Background(), resource.ResolveAccessTokenRequest{Raw: accessToken, Now: now}); err != nil {
		t.Fatalf("ResolveAccessToken(token for server.RecommendedLimits' AccessTokenLifetime): %v", err)
	}
}
