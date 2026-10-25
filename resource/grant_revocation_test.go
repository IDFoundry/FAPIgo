package resource_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/fapigo/internal/mtls"
	"github.com/idfoundry/fapigo/resource"
	"github.com/idfoundry/fapigo/storage"
)

// grantKeyFailure is a revocation store that answers for tokens but
// fails for grants.
type grantKeyFailure struct{}

func (grantKeyFailure) IsRevoked(_ context.Context, key string) (bool, error) {
	if strings.HasPrefix(key, "grant:") {
		return false, errors.New("down")
	}
	return false, nil
}

// grantClaimResolver resolves every token as mTLS-bound to cert,
// carrying claims, from testIssuer unless noIssuer.
type grantClaimResolver struct {
	thumbprint string
	claims     map[string]json.RawMessage
	now        time.Time
	noIssuer   bool
}

func (r grantClaimResolver) ResolveAccessToken(context.Context, resource.ResolveAccessTokenRequest) (resource.ResolvedAccessToken, error) {
	issuer := testIssuer
	if r.noIssuer {
		issuer = ""
	}
	return resource.ResolvedAccessToken{
		Subject: "user-1", ClientID: "client-1", Key: "token-1", Claims: r.claims, Issuer: issuer,
		SenderConstrain: storage.SenderConstrainMTLS, Thumbprint: r.thumbprint, ExpiresAt: r.now.Add(time.Minute),
	}, nil
}

// TestVerifyChecksTheGrantRevocation covers a token's grant_id claim: a
// grant its issuer revoked refuses the token, as does one revoked under
// the un-namespaced key servers before v0.61.0 wrote, but another
// issuer's grant of the same ID doesn't; a malformed claim refuses it,
// and a revocation store that fails, or a token whose issuer the
// resolver didn't report, is a server error, never a pass.
func TestVerifyChecksTheGrantRevocation(t *testing.T) {
	now := time.Now()
	cert := selfSignedTestClientCert(t, "client-1")
	target, err := url.Parse("https://rs.example.com/accounts")
	if err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		claim      json.RawMessage
		revocation resource.RevocationChecker
		want       resource.ErrorCode
		noIssuer   bool
	}{
		"not revoked":                    {claim: json.RawMessage(`"grant-1"`), revocation: &fakeRevocationChecker{}},
		"revoked":                        {claim: json.RawMessage(`"grant-1"`), revocation: &fakeRevocationChecker{revoked: map[string]bool{"grant:grant-1@" + testIssuer: true}}, want: resource.ErrorInvalidToken},
		"revoked before v0.61.0":         {claim: json.RawMessage(`"grant-1"`), revocation: &fakeRevocationChecker{revoked: map[string]bool{"grant:grant-1": true}}, want: resource.ErrorInvalidToken},
		"another grant revoked":          {claim: json.RawMessage(`"grant-1"`), revocation: &fakeRevocationChecker{revoked: map[string]bool{"grant:grant-2@" + testIssuer: true}}},
		"another issuer's grant revoked": {claim: json.RawMessage(`"grant-1"`), revocation: &fakeRevocationChecker{revoked: map[string]bool{"grant:grant-1@https://other.example.com": true}}},
		"malformed":                      {claim: json.RawMessage(`42`), revocation: &fakeRevocationChecker{}, want: resource.ErrorInvalidToken},
		"empty":                          {claim: json.RawMessage(`""`), revocation: &fakeRevocationChecker{}, want: resource.ErrorInvalidToken},
		"store fails":                    {claim: json.RawMessage(`"grant-1"`), revocation: grantKeyFailure{}, want: resource.ErrorServerError},
		"no issuer":                      {claim: json.RawMessage(`"grant-1"`), revocation: &fakeRevocationChecker{}, want: resource.ErrorServerError, noIssuer: true},
	} {
		t.Run(name, func(t *testing.T) {
			v, err := resource.NewVerifier(validConfig(t), resource.Dependencies{
				AccessTokens: grantClaimResolver{thumbprint: mtls.Thumbprint(cert), claims: map[string]json.RawMessage{"grant_id": tc.claim}, now: now, noIssuer: tc.noIssuer},
				Replay:       &fakeReplayStore{},
				Revocation:   tc.revocation,
				Clock:        fixedClock{now: now},
			})
			if err != nil {
				t.Fatalf("NewVerifier: %v", err)
			}
			_, err = v.Verify(context.Background(), resource.VerifyRequest{Method: "GET", URL: target, Authorization: "Bearer token", PeerCertificate: cert})
			if tc.want == "" {
				if err != nil {
					t.Fatalf("Verify: %v", err)
				}
				return
			}
			var rerr *resource.Error
			if !errors.As(err, &rerr) || rerr.Code() != tc.want {
				t.Fatalf("Verify = %v, want %s", err, tc.want)
			}
		})
	}
}
