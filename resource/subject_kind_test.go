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
// a grant_type the server never sets fails closed. EndUser reports the
// subject only for the end user's token.
func TestVerifySubjectKind(t *testing.T) {
	now := time.Now()
	cert := selfSignedTestClientCert(t, "client-1")
	target, err := url.Parse("https://rs.example.com/accounts")
	if err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		claims      map[string]json.RawMessage
		want        resource.SubjectKind
		wantEndUser bool
		wantErr     resource.ErrorCode
	}{
		"end user":           {nil, resource.SubjectEndUser, true, ""},
		"client credentials": {map[string]json.RawMessage{"grant_type": json.RawMessage(`"client_credentials"`)}, resource.SubjectClient, false, ""},
		"other grant type":   {map[string]json.RawMessage{"grant_type": json.RawMessage(`"authorization_code"`)}, 0, false, resource.ErrorInvalidToken},
		"not a string":       {map[string]json.RawMessage{"grant_type": json.RawMessage(`1`)}, 0, false, resource.ErrorInvalidToken},
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
			assertSubjectKind(t, authz, tc.want, tc.wantEndUser)
		})
	}
}

// assertSubjectKind checks authz's SubjectKind, and that EndUser reports
// InternalSubject exactly when wantEndUser.
func assertSubjectKind(t *testing.T, authz resource.AuthorizationContext, want resource.SubjectKind, wantEndUser bool) {
	t.Helper()
	if authz.SubjectKind != want {
		t.Fatalf("SubjectKind = %v, want %v", authz.SubjectKind, want)
	}
	if sub, ok := authz.EndUser(); ok != wantEndUser || (ok && sub != authz.InternalSubject) {
		t.Fatalf("EndUser = %q, %v; want ok %v", sub, ok, wantEndUser)
	}
}

// TestEndUser: only a token issued for an end user names one; a client
// credentials token for a client whose client_id equals a user's
// identifier doesn't, nor does a hand-built context with no SubjectKind
// or one with no InternalSubject.
func TestEndUser(t *testing.T) {
	for name, tc := range map[string]struct {
		authz resource.AuthorizationContext
		want  string
		ok    bool
	}{
		"end user":              {resource.AuthorizationContext{SubjectKind: resource.SubjectEndUser, InternalSubject: "alice", ClientSubject: "alice"}, "alice", true},
		"client named as alice": {resource.AuthorizationContext{SubjectKind: resource.SubjectClient, InternalSubject: "alice", ClientSubject: "alice", ClientID: "alice"}, "", false},
		"no subject kind":       {resource.AuthorizationContext{InternalSubject: "alice"}, "", false},
		"pairwise, not mapped":  {resource.AuthorizationContext{SubjectKind: resource.SubjectEndUser, ClientSubject: "pairwise-1"}, "", false},
	} {
		t.Run(name, func(t *testing.T) {
			if got, ok := tc.authz.EndUser(); got != tc.want || ok != tc.ok {
				t.Fatalf("EndUser = %q, %v; want %q, %v", got, ok, tc.want, tc.ok)
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
		"not revoked":            {json.RawMessage(`"cg-1"`), nil, ""},
		"revoked":                {json.RawMessage(`"cg-1"`), map[string]bool{"code-grant:cg-1@" + testIssuer: true}, resource.ErrorInvalidToken},
		"revoked before v0.61.0": {json.RawMessage(`"cg-1"`), map[string]bool{"code-grant:cg-1": true}, resource.ErrorInvalidToken},
		"another issuer's":       {json.RawMessage(`"cg-1"`), map[string]bool{"code-grant:cg-1@https://other.example.com": true}, ""},
		"grant key differs":      {json.RawMessage(`"cg-1"`), map[string]bool{"grant:cg-1@" + testIssuer: true}, ""},
		"malformed":              {json.RawMessage(`42`), nil, resource.ErrorInvalidToken},
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
