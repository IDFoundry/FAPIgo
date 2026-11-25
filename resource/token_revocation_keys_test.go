package resource_test

import (
	"context"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/idfoundry/fapigo/internal/mtls"
	"github.com/idfoundry/fapigo/resource"
)

// singleRevocationChecker is a RevocationChecker without IsAnyRevoked,
// as a custom checker may be.
type singleRevocationChecker struct{ revoked map[string]bool }

func (c singleRevocationChecker) IsRevoked(_ context.Context, key string) (bool, error) {
	return c.revoked[key], nil
}

// namespacedTokenKey is the key a server of issuer revokes the access
// token whose own key is key under, besides key itself.
func namespacedTokenKey(issuer, key string) string {
	return "access-token:" + strconv.Itoa(len(issuer)) + ":" + issuer + key
}

// TestVerifyChecksTheTokenRevocationKeys covers a token's own
// revocation keys: one its issuer revoked under the namespaced key, as
// a server since v0.84.0 writes it, or under the raw key alone, as an
// older server wrote it, refuses the token; another issuer's
// namespaced revocation of the same key doesn't. A resolver reporting
// no issuer is checked under the raw key alone. Each holds for a
// checker with and without IsAnyRevoked.
func TestVerifyChecksTheTokenRevocationKeys(t *testing.T) {
	for name, tc := range map[string]struct {
		revoked  string
		noIssuer bool
		refused  bool
	}{
		"namespaced":                       {revoked: namespacedTokenKey(testIssuer, "token-1"), refused: true},
		"raw, from an older server":        {revoked: "token-1", refused: true},
		"another issuer's namespaced":      {revoked: namespacedTokenKey("https://other.example.com", "token-1")},
		"another token's namespaced":       {revoked: namespacedTokenKey(testIssuer, "token-2")},
		"no issuer, raw":                   {revoked: "token-1", noIssuer: true, refused: true},
		"no issuer, the issuer-namespaced": {revoked: namespacedTokenKey(testIssuer, "token-1"), noIssuer: true},
	} {
		revoked := map[string]bool{tc.revoked: true}
		for kind, checker := range map[string]resource.RevocationChecker{
			"single": singleRevocationChecker{revoked: revoked},
			"batch":  &batchRevocationChecker{revoked: revoked},
		} {
			t.Run(name+"/"+kind, func(t *testing.T) {
				err := verifyWithRevocation(t, checker, tc.noIssuer)
				if !tc.refused {
					requireVerifyOutcome(t, err, "", "")
					return
				}
				requireVerifyOutcome(t, err, resource.ErrorInvalidToken, "access token has been revoked")
			})
		}
	}
}

// verifyWithRevocation verifies an mTLS-bound token with key "token-1"
// and no grant claims against checker.
func verifyWithRevocation(t *testing.T, checker resource.RevocationChecker, noIssuer bool) error {
	t.Helper()
	now := time.Now()
	cert := selfSignedTestClientCert(t, "client-1")
	target, err := url.Parse("https://rs.example.com/accounts")
	if err != nil {
		t.Fatal(err)
	}
	v, err := resource.NewVerifier(validConfig(t), resource.Dependencies{
		AccessTokens: grantClaimResolver{thumbprint: mtls.Thumbprint(cert), now: now, noIssuer: noIssuer},
		Replay:       &fakeReplayStore{},
		Revocation:   checker,
		Clock:        fixedClock{now: now},
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	_, err = v.Verify(context.Background(), resource.VerifyRequest{Method: "GET", URL: target, Authorization: "Bearer token", PeerCertificate: cert})
	return err
}
