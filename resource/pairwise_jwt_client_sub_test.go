package resource_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/url"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/mtls"
	"github.com/idfoundry/fapigo/internal/token"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/resource"
)

// TestVerifyIgnoresClientSubInJWTAccessTokens: client_sub is how a
// server-side record keeps the client's pairwise sub beside the internal
// one; a JWT access token's sub is already the client's, so a client_sub
// claim in one is never taken as ClientSubject, nor its sub as the
// internal subject. A pairwise JWT is still looked up under its sector.
func TestVerifyIgnoresClientSubInJWTAccessTokens(t *testing.T) {
	sector := stringClaim("client.example")
	for name, tc := range map[string]struct {
		subject     string
		claims      map[string]json.RawMessage
		wantSubject string
		wantClient  string
	}{
		"pairwise, with client_sub": {subject: "pw:abc",
			claims:      map[string]json.RawMessage{"client_sub": stringClaim("user-2"), "pairwise_sector": sector},
			wantSubject: "user-1", wantClient: "pw:abc"},
		"public, with client_sub": {subject: "user-3",
			claims:      map[string]json.RawMessage{"client_sub": stringClaim("pw:zzz")},
			wantSubject: "user-3", wantClient: "user-3"},
	} {
		t.Run(name, func(t *testing.T) {
			authz, err := verifyJWTWithClaims(t, tc.subject, tc.claims)
			checkSubjects(t, authz, err, tc.wantSubject, tc.wantClient, "")
		})
	}
}

// verifyJWTWithClaims verifies an mTLS-bound JWT access token for
// subject carrying claims, through JWTAccessTokens and a verifier
// mapping the pairwise sub "pw:abc" (sector client.example) to "user-1".
func verifyJWTWithClaims(t *testing.T, subject string, claims map[string]json.RawMessage) (resource.AuthorizationContext, error) {
	t.Helper()
	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := selfSignedTestClientCert(t, "client-1")
	now := time.Now()
	accessToken, _, err := token.IssueAccessToken(token.AccessTokenParams{
		Signer: issuerKey, Algorithm: fapi.ES256, KeyID: "as-kid",
		Issuer: testIssuer, Subject: subject, Audience: testIssuer, ClientID: "client-1",
		Confirmation: &token.Confirmation{X5TS256: mtls.Thumbprint(cert)},
		Now:          now, Lifetime: 5 * time.Minute, Random: rand.Reader,
		Parameters: claims,
	})
	if err != nil {
		t.Fatalf("issue access token: %v", err)
	}
	issuerURL, err := fapi.ParseIssuerURL(testIssuer)
	if err != nil {
		t.Fatal(err)
	}
	resolver, err := resource.NewJWTAccessTokens(&fakeIssuerKeySource{set: keys.IssuerKeySet{Keys: []keys.IssuerKey{
		{KeyID: "as-kid", Algorithm: fapi.ES256, PublicKey: issuerKey.Public()},
	}}}, issuerURL, testIssuer, fapi.ES256, 5*time.Minute, 8)
	if err != nil {
		t.Fatalf("NewJWTAccessTokens: %v", err)
	}
	v := pairwiseVerifier(t, resolver, fakeLookup{issuer: testIssuer, sector: "client.example", body: "abc"}, now)
	target, err := url.Parse("https://rs.example.com/accounts")
	if err != nil {
		t.Fatal(err)
	}
	return v.Verify(context.Background(), resource.VerifyRequest{Method: "GET", URL: target, Authorization: "Bearer " + accessToken, PeerCertificate: cert})
}
