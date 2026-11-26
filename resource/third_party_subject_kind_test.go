package resource_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"net/url"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/jose"
	"github.com/idfoundry/fapigo/internal/mtls"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/resource"
)

// TestVerifySubjectKindOfThirdPartyJWTAccessTokens pins what SubjectKind
// and EndUser report for RFC 9068 access tokens from an authorization
// server other than FAPIgo, which sets no "grant_type" claim. RFC 9068
// §2.2 has a client credentials token's sub be the client's own
// client_id, and its §5 leaves keeping client_ids and user identifiers
// apart to the authorization server; nothing in such a token marks it
// as the client's own. So every token without the claim reads as
// SubjectEndUser, and EndUser reports a client credentials token's sub,
// the client_id, as a user: a client whose client_id equals a user's
// identifier gets an InternalSubject indistinguishable from that user's
// own token's. Verify doesn't guess from sub == client_id, which a
// user's own token can also have (a user whose identifier is a client's
// client_id, or a client acting for a user named like it). A token
// carrying FAPIgo's grant_type claim is still SubjectClient.
func TestVerifySubjectKindOfThirdPartyJWTAccessTokens(t *testing.T) {
	for name, tc := range map[string]struct {
		sub, clientID, extra string
		want                 resource.SubjectKind
		wantEndUser          bool
	}{
		"client credentials, sub is the client_id": {sub: "client-1", clientID: "client-1", want: resource.SubjectEndUser, wantEndUser: true},
		"client_id colliding with a user's sub":    {sub: "alice", clientID: "alice", want: resource.SubjectEndUser, wantEndUser: true},
		"that user's own token":                    {sub: "alice", clientID: "client-1", want: resource.SubjectEndUser, wantEndUser: true},
		"FAPIgo's grant_type claim":                {sub: "client-1", clientID: "client-1", extra: `,"grant_type":"client_credentials"`, want: resource.SubjectClient},
	} {
		t.Run(name, func(t *testing.T) {
			authz, err := verifyThirdPartyJWT(t, tc.clientID, func(c thirdPartyToken) string {
				return thirdPartyClaims(tc.sub, tc.clientID, c) + tc.extra + `}`
			})
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			assertSubjectKind(t, authz, tc.want, tc.wantEndUser)
			if authz.InternalSubject != tc.sub || authz.ClientSubject != tc.sub || authz.ClientID != tc.clientID {
				t.Fatalf("InternalSubject, ClientSubject, ClientID = %q, %q, %q; want %q, %q, %q",
					authz.InternalSubject, authz.ClientSubject, authz.ClientID, tc.sub, tc.sub, tc.clientID)
			}
		})
	}
}

// thirdPartyToken is what a third-party access token's claims set
// depends on: its lifetime, and the thumbprint of the client
// certificate it is bound to.
type thirdPartyToken struct {
	exp, iat   int64
	thumbprint string
}

// thirdPartyClaims is an RFC 9068 §2.2 claims set, mTLS-bound as c
// says, without its closing brace.
func thirdPartyClaims(sub, clientID string, c thirdPartyToken) string {
	return fmt.Sprintf(`{"iss":%q,"sub":%q,"aud":%q,"client_id":%q,"exp":%d,"iat":%d,"jti":"jti-1","scope":"accounts","cnf":{"x5t#S256":%q}`,
		testIssuer, sub, testIssuer, clientID, c.exp, c.iat, c.thumbprint)
}

// verifyThirdPartyJWT signs the claims set claims returns, as an
// at+jwt, with a key JWTAccessTokens trusts for testIssuer, and
// verifies it, presented over mTLS with a certificate for clientID.
func verifyThirdPartyJWT(t *testing.T, clientID string, claims func(thirdPartyToken) string) (resource.AuthorizationContext, error) {
	t.Helper()
	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := selfSignedTestClientCert(t, clientID)
	now := time.Now()
	payload := claims(thirdPartyToken{exp: now.Add(5 * time.Minute).Unix(), iat: now.Unix(), thumbprint: mtls.Thumbprint(cert)})
	accessToken, err := jose.Sign(issuerKey, jose.Header{Algorithm: fapi.ES256, Type: "at+jwt", KeyID: "third-party-kid"}, []byte(payload))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	resolver, err := resource.NewJWTAccessTokens(&fakeIssuerKeySource{set: keys.IssuerKeySet{Keys: []keys.IssuerKey{
		{KeyID: "third-party-kid", Algorithm: fapi.ES256, PublicKey: issuerKey.Public()},
	}}}, testIssuerURL, testIssuer, fapi.ES256, 5*time.Minute, 8)
	if err != nil {
		t.Fatalf("NewJWTAccessTokens: %v", err)
	}
	v := pairwiseVerifier(t, resolver, nil, now)
	target, err := url.Parse("https://rs.example.com/accounts")
	if err != nil {
		t.Fatal(err)
	}
	return v.Verify(context.Background(), resource.VerifyRequest{Method: "GET", URL: target, Authorization: "Bearer " + accessToken, PeerCertificate: cert})
}
