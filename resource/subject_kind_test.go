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
)

// TestVerifySubjectKind: a client credentials token, which carries
// grant_type, reports SubjectClient; any other token SubjectEndUser; and
// a grant_type the server never sets fails closed.
func TestVerifySubjectKind(t *testing.T) {
	now := time.Now()
	cert := selfSignedTestClientCert(t, "client-1")
	target, err := url.Parse("https://rs.example.com/accounts")
	if err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		claims  map[string]json.RawMessage
		want    resource.SubjectKind
		wantErr resource.ErrorCode
	}{
		"end user":           {nil, resource.SubjectEndUser, ""},
		"client credentials": {map[string]json.RawMessage{"grant_type": json.RawMessage(`"client_credentials"`)}, resource.SubjectClient, ""},
		"other grant type":   {map[string]json.RawMessage{"grant_type": json.RawMessage(`"authorization_code"`)}, 0, resource.ErrorInvalidToken},
		"not a string":       {map[string]json.RawMessage{"grant_type": json.RawMessage(`1`)}, 0, resource.ErrorInvalidToken},
	} {
		t.Run(name, func(t *testing.T) {
			v, err := resource.NewVerifier(validConfig(t), resource.Dependencies{
				AccessTokens: grantClaimResolver{thumbprint: mtls.Thumbprint(cert), claims: tc.claims, now: now},
				Replay:       &fakeReplayStore{},
				Revocation:   &fakeRevocationChecker{},
				Clock:        fixedClock{now: now},
			})
			if err != nil {
				t.Fatalf("NewVerifier: %v", err)
			}
			authz, err := v.Verify(context.Background(), resource.VerifyRequest{Method: "GET", URL: target, Authorization: "Bearer token", PeerCertificate: cert})
			if tc.wantErr != "" {
				var rerr *resource.Error
				if !errors.As(err, &rerr) || rerr.Code() != tc.wantErr {
					t.Fatalf("Verify = %v, want %s", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if authz.SubjectKind != tc.want {
				t.Fatalf("SubjectKind = %v, want %v", authz.SubjectKind, tc.want)
			}
		})
	}
}

// TestVerifyChecksTheCodeGrantRevocation covers a token's code_grant_id
// claim, which the server revokes when the code the grant came from is
// reused.
func TestVerifyChecksTheCodeGrantRevocation(t *testing.T) {
	now := time.Now()
	cert := selfSignedTestClientCert(t, "client-1")
	target, err := url.Parse("https://rs.example.com/accounts")
	if err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		claim   json.RawMessage
		revoked map[string]bool
		want    resource.ErrorCode
	}{
		"not revoked":       {json.RawMessage(`"cg-1"`), nil, ""},
		"revoked":           {json.RawMessage(`"cg-1"`), map[string]bool{"code-grant:cg-1": true}, resource.ErrorInvalidToken},
		"grant key differs": {json.RawMessage(`"cg-1"`), map[string]bool{"grant:cg-1": true}, ""},
		"malformed":         {json.RawMessage(`42`), nil, resource.ErrorInvalidToken},
	} {
		t.Run(name, func(t *testing.T) {
			v, err := resource.NewVerifier(validConfig(t), resource.Dependencies{
				AccessTokens: grantClaimResolver{thumbprint: mtls.Thumbprint(cert), claims: map[string]json.RawMessage{"code_grant_id": tc.claim}, now: now},
				Replay:       &fakeReplayStore{},
				Revocation:   &fakeRevocationChecker{revoked: tc.revoked},
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
