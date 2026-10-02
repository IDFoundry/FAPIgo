package server_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/fapigo/internal/clientassertion"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage/memstore"
)

// writeOnlyRevocationSink records revocations but can't be asked about
// them: no grant can be made revocable with it.
type writeOnlyRevocationSink struct{}

func (writeOnlyRevocationSink) Revoke(context.Context, string, time.Time) error { return nil }

// authorizeWithGrantID is an Authorize result for user-1 naming its
// grant grantID.
func authorizeWithGrantID(t *testing.T, now time.Time, grantID string, scope ...string) server.InteractionResult {
	t.Helper()
	subjectID, err := server.NewSubjectID("user-1")
	if err != nil {
		t.Fatal(err)
	}
	subject, err := server.NewAuthenticatedSubject(subjectID)
	if err != nil {
		t.Fatal(err)
	}
	auth, err := server.NewAuthenticationContext(now, "acr-1", []string{"pwd"})
	if err != nil {
		t.Fatal(err)
	}
	if len(scope) == 0 {
		scope = []string{"openid", "accounts"}
	}
	return server.Authorize(subject, auth, server.GrantedAuthorization{Scope: scope, GrantID: grantID})
}

func TestCompleteAuthorizationRejectsInvalidGrantID(t *testing.T) {
	for name, id := range map[string]string{
		"a space":   "grant 1",
		"a slash":   "grant/1",
		"non-ASCII": "grünt",
		"too long":  strings.Repeat("g", 129),
		"a colon":   "grant:1",
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, server.ProfileFAPISecurity, true)
			result, err := h.server.CompleteAuthorization(context.Background(), server.CompleteAuthorizationRequest{
				Handle: beginInteraction(t, h), Result: authorizeWithGrantID(t, h.now, id),
			})
			if err != nil {
				t.Fatalf("CompleteAuthorization: %v", err)
			}
			if _, ok := result.(server.AuthorizationLocalError); !ok {
				t.Fatalf("CompleteAuthorization(grant ID %q) = %T, want a local error", id, result)
			}
		})
	}
	h := newHarness(t, server.ProfileFAPISecurity, true)
	result, err := h.server.CompleteAuthorization(context.Background(), server.CompleteAuthorizationRequest{
		Handle: beginInteraction(t, h), Result: authorizeWithGrantID(t, h.now, "Grant-1_a.b~c"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := result.(server.AuthorizationRedirect); !ok {
		t.Fatalf("CompleteAuthorization(valid grant ID) = %T, want a redirect", result)
	}
}

// TestGrantIDNeedsACheckableRevocationStore covers a grant ID with a
// Dependencies.Revocation that couldn't enforce its revocation:
// completion and RevokeGrant both refuse, rather than leaving a grant
// revocable in name only.
func TestGrantIDNeedsACheckableRevocationStore(t *testing.T) {
	for name, sink := range map[string]server.RevocationSink{
		"NoRevocation": server.NoRevocation{},
		"write-only":   writeOnlyRevocationSink{},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarnessWithBackchannelOptions(t, memstore.NewBackchannelAuthenticationStore(), nil, func(d *server.Dependencies) { d.Revocation = sink })
			required := beginBackchannel(t, h, standardBackchannelParams(t))
			err := h.server.CompleteBackchannelAuthentication(context.Background(), server.CompleteBackchannelAuthenticationRequest{
				Handle: required.Handle, Result: authorizeWithGrantID(t, h.now, "grant-1"),
			})
			if err == nil || !strings.Contains(err.Error(), "grant ID") {
				t.Fatalf("CompleteBackchannelAuthentication(grant ID) = %v, want the grant ID refused", err)
			}
			if err := h.server.RevokeGrant(context.Background(), "grant-1"); err == nil {
				t.Fatal("RevokeGrant = nil error, want refusal")
			}
		})
	}
}

func TestRevokeGrantRecordsUntilEverythingFromTheGrantExpires(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	if err := h.server.RevokeGrant(context.Background(), "grant-1"); err != nil {
		t.Fatalf("RevokeGrant: %v", err)
	}
	if err := h.server.RevokeGrant(context.Background(), ""); err == nil {
		t.Error("RevokeGrant(\"\") = nil error, want error")
	}
	// The harness's RefreshTokenLifetime and AccessTokenLifetime are 5
	// minutes each (longer than its code lifetime), and its
	// MaxClockSkew 5 seconds.
	if got, want := h.revocation.until["grant:grant-1"], h.now.Add(10*time.Minute+5*time.Second); !got.Equal(want) {
		t.Errorf("revoked until %v, want %v", got, want)
	}
}

// TestCIBARevokedGrant covers a CIBA grant revoked between approval and
// the client's token request.
func TestCIBARevokedGrant(t *testing.T) {
	h := newHarnessWithBackchannelOptions(t, memstore.NewBackchannelAuthenticationStore(), nil, func(d *server.Dependencies) {
		d.Revocation = memstore.NewRevocationStore()
	})
	required := beginBackchannel(t, h, standardBackchannelParams(t))
	ctx := context.Background()
	if err := h.server.CompleteBackchannelAuthentication(ctx, server.CompleteBackchannelAuthenticationRequest{
		Handle: required.Handle, Result: authorizeWithGrantID(t, h.now, "grant-1"),
	}); err != nil {
		t.Fatalf("CompleteBackchannelAuthentication: %v", err)
	}
	if err := h.server.RevokeGrant(ctx, "grant-1"); err != nil {
		t.Fatalf("RevokeGrant: %v", err)
	}
	_, err := h.server.ExchangeBackchannelAuthentication(ctx, server.BackchannelTokenExchangeRequest{
		HTTP: server.FormRequest{Parameters: []server.FormParameter{
			formParam("client_assertion", h.clientAssertion(t)),
			formParam("client_assertion_type", clientassertion.AssertionType),
			formParam("grant_type", server.CIBAGrantType),
			formParam("auth_req_id", required.AuthReqID.String()),
		}},
		DPoPProofs: []string{createDPoPProof(t, generateKey(t), h.now)},
	})
	if code := serverErrorCode(t, err); code != server.ErrorInvalidGrant {
		t.Fatalf("ExchangeBackchannelAuthentication(revoked grant) code = %q, want %q", code, server.ErrorInvalidGrant)
	}
}
