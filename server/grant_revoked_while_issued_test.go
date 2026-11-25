package server_test

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/idfoundry/fapigo/internal/clientassertion"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
	"github.com/idfoundry/fapigo/storage/memstore"
)

// A grant revoked while its refresh token is being stored, after the
// token request checked it, gets no refresh token, and the token request
// answers invalid_grant, the grant being refused, not the server_error of
// a store failure — whichever of the two checks after storing the token
// finds the revocation. A store failing in those checks, or failing to
// withdraw the token, is still server_error.

// afterCreateGrants is a fakeGrantStore that runs after once a refresh
// token has been created, as a revocation racing the issuance would run
// between the token's store write and the checks after it.
type afterCreateGrants struct {
	*fakeGrantStore
	after func(context.Context)
}

func (g afterCreateGrants) CreateRefreshToken(ctx context.Context, tok storage.NewRefreshToken) error {
	err := g.fakeGrantStore.CreateRefreshToken(ctx, tok)
	if err == nil {
		g.after(ctx)
	}
	return err
}

// downAfterCreateRevocation is a fakeRevocationSink whose IsRevoked fails
// once down is set.
type downAfterCreateRevocation struct {
	*fakeRevocationSink
	down *atomic.Bool
}

func (r downAfterCreateRevocation) IsRevoked(ctx context.Context, key string) (bool, error) {
	if r.down.Load() {
		return false, errStoreDown
	}
	return r.fakeRevocationSink.IsRevoked(ctx, key)
}

// wantTokenError fails t unless err is an *server.Error of code.
func wantTokenError(t *testing.T, what string, err error, code server.ErrorCode) {
	t.Helper()
	var serverErr *server.Error
	if !errors.As(err, &serverErr) || serverErr.Code() != code {
		t.Fatalf("%s = %v, want %s", what, err, code)
	}
}

// revokedGrantIssuance is a harness, without a GrantRegistry, whose
// GrantStore runs after once each refresh token is created, and an
// attested instance of its client.
func revokedGrantIssuance(t *testing.T, after func(h *harness, ctx context.Context), mutate ...func(*server.Dependencies)) (*harness, *attestedInstance) {
	t.Helper()
	var hp *harness
	h, owner := registryHarness(t, nil, append([]func(*server.Dependencies){func(deps *server.Dependencies) {
		deps.Grants = afterCreateGrants{deps.Grants.(*fakeGrantStore), func(ctx context.Context) { after(hp, ctx) }}
	}}, mutate...)...)
	hp = &h
	return hp, owner
}

// issueGrantRefreshToken is IssueRefreshToken of grant-1 for owner.
func issueGrantRefreshToken(t *testing.T, h *harness, owner *attestedInstance) error {
	t.Helper()
	attested, binding := embedderTokenRequest(t, owner)
	_, err := h.server.IssueRefreshToken(context.Background(), server.IssueRefreshTokenRequest{
		GrantType: preAuthorizedCodeGrant, Client: attested, Binding: binding,
		Subject: mustSubjectID(t, "holder-1"), Scope: []string{"accounts"}, GrantID: "grant-1",
	})
	return err
}

// TestGrantRevokedWhileIssuedIsInvalidGrant: RevokeGrant landing once
// IssueRefreshToken has stored the refresh token is found by the check
// that the grant isn't revoked: the token is withdrawn and the issuance
// is invalid_grant, audited as such.
func TestGrantRevokedWhileIssuedIsInvalidGrant(t *testing.T) {
	var once sync.Once
	h, owner := revokedGrantIssuance(t, func(h *harness, ctx context.Context) {
		once.Do(func() {
			if err := h.server.RevokeGrant(ctx, "grant-1"); err != nil {
				t.Errorf("RevokeGrant: %v", err)
			}
		})
	})
	before := len(h.grants.refreshTokens)
	wantTokenError(t, "IssueRefreshToken of a grant revoked meanwhile", issueGrantRefreshToken(t, h, owner), server.ErrorInvalidGrant)
	checkNoLiveRefreshTokenSince(t, *h, before)
	wantLastAudit(t, h, server.AuditEventIssueRefreshToken, string(server.ErrorInvalidGrant))
}

// TestGrantRevocationUncheckableWhileIssuedIsServerError: a revocation
// store failing the check after the refresh token is stored is a store
// failure, server_error, and the token is withdrawn.
func TestGrantRevocationUncheckableWhileIssuedIsServerError(t *testing.T) {
	var down atomic.Bool
	h, owner := revokedGrantIssuance(t, func(*harness, context.Context) { down.Store(true) }, func(deps *server.Dependencies) {
		deps.Revocation = downAfterCreateRevocation{deps.Revocation.(*fakeRevocationSink), &down}
	})
	before := len(h.grants.refreshTokens)
	wantTokenError(t, "IssueRefreshToken whose revocation check fails", issueGrantRefreshToken(t, h, owner), server.ErrorServerError)
	checkNoLiveRefreshTokenSince(t, *h, before)
}

// TestGrantRevokedWhileIssuedWithdrawalFailsIsServerError: a grant found
// revoked whose refresh token then can't be withdrawn is a store
// failure, server_error: the token may still be live.
func TestGrantRevokedWhileIssuedWithdrawalFailsIsServerError(t *testing.T) {
	var once sync.Once
	h, owner := revokedGrantIssuance(t, func(h *harness, ctx context.Context) {
		once.Do(func() {
			// The revocation record is written; the store then refuses to
			// revoke the grant's refresh tokens, and the withdrawal.
			h.grants.failRevokeRefresh = errStoreDown
			_ = h.server.RevokeGrant(ctx, "grant-1")
		})
	})
	wantTokenError(t, "IssueRefreshToken of a revoked grant whose token can't be withdrawn", issueGrantRefreshToken(t, h, owner), server.ErrorServerError)
}

// tokensRecorderGrants is an afterCreateGrants that is a
// storage.IssuedTokensRecorder, so a code exchange stores its refresh
// token before its access token.
type tokensRecorderGrants struct{ afterCreateGrants }

func (g tokensRecorderGrants) RecordIssuedTokens(ctx context.Context, codeHash [32]byte, accessKey string, accessExpiresAt time.Time, refreshHash [32]byte, refreshExpiresAt time.Time) error {
	if err := g.RecordIssuedAccessToken(ctx, codeHash, accessKey, accessExpiresAt); err != nil {
		return err
	}
	return g.RecordIssuedRefreshToken(ctx, codeHash, refreshHash, refreshExpiresAt)
}

// TestCodeReuseWhileIssuedIsInvalidGrant: a reuse of an authorization
// code landing once its exchange has stored the refresh token revokes
// the code's grant, and the exchange answers invalid_grant, as the reuse
// does, issuing nothing live — with a GrantStore that records the
// exchange's tokens together (storage.IssuedTokensRecorder) and one that
// doesn't.
func TestCodeReuseWhileIssuedIsInvalidGrant(t *testing.T) {
	for name, recorder := range map[string]bool{"IssuedTokensRecorder": true, "no IssuedTokensRecorder": false} {
		t.Run(name, func(t *testing.T) {
			var once sync.Once
			var owner *attestedInstance
			var code string
			var reuseErr error
			h, owner := revokedGrantIssuance(t, func(h *harness, ctx context.Context) {
				once.Do(func() {
					_, reuseErr = h.server.ExchangeAuthorizationCode(ctx, owner.exchangeCodeRequest(code, testCodeVerifier))
				})
			}, func(deps *server.Dependencies) {
				if recorder {
					deps.Grants = tokensRecorderGrants{deps.Grants.(afterCreateGrants)}
				}
			})
			code = owner.attestedCode()
			before := len(h.grants.refreshTokens)
			_, err := owner.exchangeCode(code, testCodeVerifier)
			wantTokenError(t, "the exchange whose code was reused while it issued", err, server.ErrorInvalidGrant)
			wantTokenError(t, "the reuse", reuseErr, server.ErrorInvalidGrant)
			checkNoLiveRefreshTokenSince(t, *h, before)
			wantLastAudit(t, h, server.AuditEventExchangeAuthorizationCode, string(server.ErrorInvalidGrant))
		})
	}
}

// TestGrantEntryGoneWhileIssuedIsInvalidGrant: a grant whose registry
// entry is gone by the time its refresh token is stored, deleted by a
// revocation in between, is invalid_grant; a registry that can't say
// whether it's there is server_error; and so is an entry gone whose
// refresh token can't then be withdrawn.
func TestGrantEntryGoneWhileIssuedIsInvalidGrant(t *testing.T) {
	for name, tc := range map[string]struct {
		registry      storage.GrantRegistry
		withdrawFails bool
		want          server.ErrorCode
	}{
		"entry gone":                           {racingRegistry{memstore.NewGrantRegistry()}, false, server.ErrorInvalidGrant},
		"registry can't say":                   {listFailsAfterRecord{memstore.NewGrantRegistry()}, false, server.ErrorServerError},
		"entry gone, token can't be withdrawn": {racingRegistry{memstore.NewGrantRegistry()}, true, server.ErrorServerError},
	} {
		t.Run(name, func(t *testing.T) {
			h, owner := registryHarness(t, tc.registry)
			if tc.withdrawFails {
				h.grants.failRevokeRefresh = errStoreDown
			}
			err := issueGrantRefreshToken(t, &h, owner)
			wantTokenError(t, "IssueRefreshToken", err, tc.want)
			wantLastAudit(t, &h, server.AuditEventIssueRefreshToken, string(tc.want))
		})
	}
}

// wantLastAudit fails t unless h's last audit event is a failure of
// eventType with reason.
func wantLastAudit(t *testing.T, h *harness, eventType server.AuditEventType, reason string) {
	t.Helper()
	events := h.audit.all()
	if len(events) == 0 {
		t.Fatal("no audit event recorded")
	}
	last := events[len(events)-1]
	if last.Type != eventType || last.Outcome != server.AuditOutcomeFailure || last.Description != reason {
		t.Fatalf("last audit event = %+v, want a %v failure with reason %s", last, eventType, reason)
	}
}

// TestCIBAGrantRevokedWhileIssuedIsInvalidGrant: RevokeGrant landing
// once a CIBA token request has stored the refresh token makes that
// request invalid_grant too.
func TestCIBAGrantRevokedWhileIssuedIsInvalidGrant(t *testing.T) {
	var once sync.Once
	var srv *server.Server
	grants, audit := &fakeGrantStore{}, &fakeAuditSink{}
	h := newHarnessWithBackchannelOptions(t, memstore.NewBackchannelAuthenticationStore(), nil, func(d *server.Dependencies) {
		d.Revocation, d.Audit = &fakeRevocationSink{}, audit
		d.Grants = afterCreateGrants{grants, func(ctx context.Context) {
			once.Do(func() {
				if err := srv.RevokeGrant(ctx, "ciba-grant"); err != nil {
					t.Errorf("RevokeGrant: %v", err)
				}
			})
		}}
	})
	srv, h.grants, h.audit = h.server, grants, audit
	params := standardBackchannelParams(t)
	params["scope"] = json.RawMessage(`"openid accounts offline_access"`)
	required := beginBackchannel(t, h, params)
	subject, _ := server.NewSubjectID("user-1")
	authenticated, _ := server.NewAuthenticatedSubject(subject)
	authCtx, _ := server.NewAuthenticationContext(h.now, "", nil)
	if err := h.server.CompleteBackchannelAuthentication(context.Background(), server.CompleteBackchannelAuthenticationRequest{
		Handle: required.Handle,
		Result: server.Authorize(authenticated, authCtx, server.GrantedAuthorization{Scope: []string{"openid", "accounts", "offline_access"}, GrantID: "ciba-grant"}),
	}); err != nil {
		t.Fatalf("CompleteBackchannelAuthentication: %v", err)
	}
	before := len(h.grants.refreshTokens)
	_, err := h.server.ExchangeBackchannelAuthentication(context.Background(), server.BackchannelTokenExchangeRequest{
		HTTP: server.FormRequest{Parameters: []server.FormParameter{
			formParam("client_assertion", h.clientAssertion(t)),
			formParam("client_assertion_type", clientassertion.AssertionType),
			formParam("grant_type", server.CIBAGrantType),
			formParam("auth_req_id", required.AuthReqID.String()),
		}},
		DPoPProofs: []string{createDPoPProof(t, generateKey(t), h.now)},
	})
	wantTokenError(t, "the CIBA token request whose grant was revoked while it issued", err, server.ErrorInvalidGrant)
	checkNoLiveRefreshTokenSince(t, h, before)
	wantLastAudit(t, &h, server.AuditEventExchangeBackchannelAuthentication, string(server.ErrorInvalidGrant))
}
