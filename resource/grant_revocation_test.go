package resource_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"testing"
	"time"

	"github.com/idfoundry/fapigo/internal/mtls"
	"github.com/idfoundry/fapigo/resource"
	"github.com/idfoundry/fapigo/storage"
)

// grantClaimResolver resolves every token as mTLS-bound to cert,
// carrying claims.
type grantClaimResolver struct {
	thumbprint string
	claims     map[string]json.RawMessage
	now        time.Time
}

func (r grantClaimResolver) ResolveAccessToken(context.Context, resource.ResolveAccessTokenRequest) (resource.ResolvedAccessToken, error) {
	return resource.ResolvedAccessToken{
		Subject: "user-1", ClientID: "client-1", Key: "token-1", Claims: r.claims,
		SenderConstrain: storage.SenderConstrainMTLS, Thumbprint: r.thumbprint, ExpiresAt: r.now.Add(time.Minute),
	}, nil
}

// TestVerifyChecksTheGrantRevocation covers a token's grant_id claim: a
// revoked grant refuses the token, a malformed claim refuses it, and a
// revocation store that fails is a server error, never a pass.
func TestVerifyChecksTheGrantRevocation(t *testing.T) {
	now := time.Now()
	cert := selfSignedTestClientCert(t, "client-1")
	target, err := url.Parse("https://rs.example.com/accounts")
	if err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		claim      json.RawMessage
		revocation *fakeRevocationChecker
		want       resource.ErrorCode
	}{
		"not revoked":           {json.RawMessage(`"grant-1"`), &fakeRevocationChecker{}, ""},
		"revoked":               {json.RawMessage(`"grant-1"`), &fakeRevocationChecker{revoked: map[string]bool{"grant:grant-1": true}}, resource.ErrorInvalidToken},
		"another grant revoked": {json.RawMessage(`"grant-1"`), &fakeRevocationChecker{revoked: map[string]bool{"grant:grant-2": true}}, ""},
		"malformed":             {json.RawMessage(`42`), &fakeRevocationChecker{}, resource.ErrorInvalidToken},
		"empty":                 {json.RawMessage(`""`), &fakeRevocationChecker{}, resource.ErrorInvalidToken},
		"store fails":           {json.RawMessage(`"grant-1"`), &fakeRevocationChecker{err: errors.New("down")}, resource.ErrorServerError},
	} {
		t.Run(name, func(t *testing.T) {
			v, err := resource.NewVerifier(validConfig(t), resource.Dependencies{
				AccessTokens: grantClaimResolver{thumbprint: mtls.Thumbprint(cert), claims: map[string]json.RawMessage{"grant_id": tc.claim}, now: now},
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
