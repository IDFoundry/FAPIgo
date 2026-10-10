package server_test

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
)

const testRevocationEndpoint = "https://as.example/revoke"

// newRevocationHarness is the attestation harness with the revocation
// endpoint enabled and testClientID allowed offline_access.
func newRevocationHarness(t *testing.T, attesterKey *ecdsa.PrivateKey) harness {
	t.Helper()
	revocation, err := fapi.ParseEndpointURL(testRevocationEndpoint)
	if err != nil {
		t.Fatal(err)
	}
	return newAttestationHarness(t, time.Now(), attesterKey, server.RegisteredAttesterKeys{}, func(cfg *server.Config, c *storage.RegisteredClientConfig) {
		cfg.Endpoints.Revocation = revocation
		cfg.AdditionalGrantTypes = []string{preAuthorizedCodeGrant}
		c.AllowedScopes = []string{"openid", "accounts", "offline_access"}
	})
}

// revoke asks the revocation endpoint to revoke token, authenticated as
// instance.
func (i *attestedInstance) revoke(params ...server.FormParameter) error {
	_, err := i.revokeResult(params...)
	return err
}

// revokeResult is revoke, with what RevokeToken reports it revoked.
func (i *attestedInstance) revokeResult(params ...server.FormParameter) (server.TokenRevocationResult, error) {
	attestations, pops := i.headers()
	return i.h.server.RevokeToken(context.Background(), server.TokenRevocationRequest{
		HTTP:               server.FormRequest{Parameters: append([]server.FormParameter{formParam("client_id", testClientID.String())}, params...)},
		ClientAttestations: attestations, ClientAttestationPoPs: pops,
	})
}

func lastAudit(t *testing.T, h harness) server.AuditEvent {
	t.Helper()
	events := h.audit.all()
	return events[len(events)-1]
}

// TestRevokeTokenRevokesOnlyTheOwnersRefreshToken covers RFC 7009 for a
// client authenticated by Client Attestation: another installation's
// request is answered 200 but revokes nothing, the owning
// installation's revokes the token, and a repeat is still 200.
func TestRevokeTokenRevokesOnlyTheOwnersRefreshToken(t *testing.T) {
	attesterKey := generateKey(t)
	h := newRevocationHarness(t, attesterKey)
	owner := &attestedInstance{t: t, h: h, attesterKey: attesterKey, instanceKey: generateKey(t)}
	other := &attestedInstance{t: t, h: h, attesterKey: attesterKey, instanceKey: generateKey(t)}
	refreshToken := owner.issueRefreshToken()

	if err := other.revoke(formParam("token", refreshToken), formParam("token_type_hint", "refresh_token")); err != nil {
		t.Fatalf("revoke by another instance: %v, want 200", err)
	}
	if last := lastAudit(t, h); last.Outcome != server.AuditOutcomeSuccess || last.Description != "not revoked" {
		t.Errorf("audit for another instance's request = %+v, want a success described as not revoked", last)
	}
	if _, err := owner.refresh(refreshToken); err != nil {
		t.Fatalf("refresh after another instance's revocation: %v, want the token still live", err)
	}

	if err := owner.revoke(formParam("token", refreshToken)); err != nil {
		t.Fatalf("revoke by the owner: %v", err)
	}
	if last := lastAudit(t, h); last.Type != server.AuditEventRevokeToken || last.Outcome != server.AuditOutcomeSuccess || last.Description != "" {
		t.Errorf("last audit event = %+v, want a RevokeToken success that revoked the token", last)
	}
	if _, err := owner.refresh(refreshToken); serverErrorCode(t, err) != server.ErrorInvalidGrant {
		t.Fatalf("refresh after revocation: %v, want invalid_grant", err)
	}
	if err := owner.revoke(formParam("token", refreshToken)); err != nil {
		t.Fatalf("revoking an already revoked token: %v, want 200", err)
	}
	if err := owner.revoke(formParam("token", "unknown-token")); err != nil {
		t.Fatalf("revoking an unknown token: %v, want 200", err)
	}
	if last := lastAudit(t, h); last.Description != "not revoked" {
		t.Errorf("audit for an unknown token = %+v, want it described as not revoked", last)
	}
}

// TestRevokeTokenRevokesTheGrant covers a refresh token whose grant has
// a GrantID: revoking it revokes the grant, so the grant's access tokens
// stop working too (RFC 7009 §2.1).
func TestRevokeTokenRevokesTheGrant(t *testing.T) {
	attesterKey := generateKey(t)
	h := newRevocationHarness(t, attesterKey)
	owner := &attestedInstance{t: t, h: h, attesterKey: attesterKey, instanceKey: generateKey(t)}
	attested, binding := embedderTokenRequest(t, owner)
	refreshToken, err := h.server.IssueRefreshToken(context.Background(), server.IssueRefreshTokenRequest{
		GrantType: preAuthorizedCodeGrant, Client: attested, Binding: binding,
		Subject: mustSubjectID(t, "holder-1"), Scope: []string{"accounts"}, GrantID: "grant-1",
	})
	if err != nil {
		t.Fatalf("IssueRefreshToken: %v", err)
	}
	if err := owner.revoke(formParam("token", refreshToken.Reveal())); err != nil {
		t.Fatalf("RevokeToken: %v", err)
	}
	h.revocation.mu.Lock()
	_, revoked := h.revocation.until["grant:grant-1"]
	h.revocation.mu.Unlock()
	if !revoked {
		t.Error("the refresh token's grant wasn't revoked")
	}
}

// TestRevokeTokenRevokesTheCodeGrant covers a refresh token from the
// authorization code flow with no GrantID: revoking it revokes the code
// grant it came from, as code reuse does, so the access tokens issued
// under it stop working too (RFC 7009 §2.1).
func TestRevokeTokenRevokesTheCodeGrant(t *testing.T) {
	attesterKey := generateKey(t)
	h := newRevocationHarness(t, attesterKey)
	owner := &attestedInstance{t: t, h: h, attesterKey: attesterKey, instanceKey: generateKey(t)}
	refreshToken := owner.issueRefreshToken()
	if err := owner.revoke(formParam("token", refreshToken)); err != nil {
		t.Fatalf("RevokeToken: %v", err)
	}
	h.revocation.mu.Lock()
	defer h.revocation.mu.Unlock()
	var codeGrants int
	for key := range h.revocation.until {
		if strings.HasPrefix(key, "code-grant:") {
			codeGrants++
		}
	}
	if codeGrants != 1 {
		t.Errorf("revoked %d code grants, want the refresh token's one", codeGrants)
	}
}

// TestRevokeTokenRefusals covers every request RevokeToken answers with
// an error rather than 200, each recorded as a failure.
func TestRevokeTokenRefusals(t *testing.T) {
	attesterKey := generateKey(t)
	h := newRevocationHarness(t, attesterKey)
	owner := &attestedInstance{t: t, h: h, attesterKey: attesterKey, instanceKey: generateKey(t)}
	ctx := context.Background()

	cases := map[string]struct {
		revoke func() error
		want   server.ErrorCode
	}{
		"no token": {func() error { return owner.revoke() }, server.ErrorInvalidRequest},
		"access token hint": {func() error {
			return owner.revoke(formParam("token", "opaque"), formParam("token_type_hint", "access_token"))
		}, server.ErrorUnsupportedTokenType},
		"access token in JWT form": {func() error {
			return owner.revoke(formParam("token", "eyJhbGciOiJFUzI1NiJ9.e30.c2ln"))
		}, server.ErrorUnsupportedTokenType},
		"repeated token": {func() error {
			return owner.revoke(formParam("token", "a"), formParam("token", "b"))
		}, server.ErrorInvalidRequest},
		"no client authentication": {func() error {
			_, err := h.server.RevokeToken(ctx, server.TokenRevocationRequest{HTTP: server.FormRequest{Parameters: []server.FormParameter{formParam("token", "x")}}})
			return err
		}, server.ErrorInvalidClient},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if code := serverErrorCode(t, tc.revoke()); code != tc.want {
				t.Fatalf("error code = %q, want %q", code, tc.want)
			}
			if last := lastAudit(t, h); last.Type != server.AuditEventRevokeToken || last.Outcome != server.AuditOutcomeFailure {
				t.Errorf("last audit event = %+v, want a RevokeToken failure", last)
			}
		})
	}
}

// TestRevokeTokenNeedsTheEndpointConfigured covers a server without
// Config.Endpoints.Revocation: RevokeToken refuses, and Metadata has no
// revocation_endpoint.
func TestRevokeTokenNeedsTheEndpointConfigured(t *testing.T) {
	attesterKey := generateKey(t)
	h := newHarnessWithAttestationClientCredentials(t, attesterKey)
	instance := &attestedInstance{t: t, h: h, attesterKey: attesterKey, instanceKey: generateKey(t)}
	if code := serverErrorCode(t, instance.revoke(formParam("token", "x"))); code != server.ErrorServerError {
		t.Fatalf("RevokeToken without the endpoint: code %q, want server_error", code)
	}
	md := h.server.Metadata(context.Background())
	if md.RevocationEndpoint != nil || md.RevocationEndpointAuthMethodsSupported != nil {
		t.Errorf("Metadata advertises revocation without the endpoint: %v %v", md.RevocationEndpoint, md.RevocationEndpointAuthMethodsSupported)
	}
}

func TestMetadataAdvertisesRevocationEndpoint(t *testing.T) {
	h := newRevocationHarness(t, generateKey(t))
	raw, err := json.Marshal(h.server.Metadata(context.Background()))
	if err != nil {
		t.Fatal(err)
	}
	var md struct {
		RevocationEndpoint string   `json:"revocation_endpoint"`
		AuthMethods        []string `json:"revocation_endpoint_auth_methods_supported"`
		TokenAuthMethods   []string `json:"token_endpoint_auth_methods_supported"`
	}
	if err := json.Unmarshal(raw, &md); err != nil {
		t.Fatal(err)
	}
	if md.RevocationEndpoint != testRevocationEndpoint {
		t.Errorf("revocation_endpoint = %q, want %q", md.RevocationEndpoint, testRevocationEndpoint)
	}
	if strings.Join(md.AuthMethods, " ") != strings.Join(md.TokenAuthMethods, " ") || !strings.Contains(strings.Join(md.AuthMethods, " "), "attest_jwt_client_auth") {
		t.Errorf("revocation_endpoint_auth_methods_supported = %v, want the token endpoint's %v", md.AuthMethods, md.TokenAuthMethods)
	}
}

func TestTokenRevocationRequestFromHTTP(t *testing.T) {
	form := url.Values{"token": {"rt-1"}, "token_type_hint": {"refresh_token"}, "client_id": {testClientID.String()}}
	r := httptest.NewRequest(http.MethodPost, testRevocationEndpoint, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("OAuth-Client-Attestation", "attestation")
	r.Header.Set("OAuth-Client-Attestation-PoP", "pop")
	req, err := server.TokenRevocationRequestFromHTTP(r)
	if err != nil {
		t.Fatalf("TokenRevocationRequestFromHTTP: %v", err)
	}
	if req.HTTP.Get("token") != "rt-1" || len(req.ClientAttestations) != 1 || len(req.ClientAttestationPoPs) != 1 {
		t.Errorf("request = %+v, want the form and attestation headers", req)
	}
}

// TestRevokeTokenFaults covers the server's own failures, which are
// reported rather than answered 200: a stored grant that won't decode,
// and a store that fails to revoke the token or the grant.
func TestRevokeTokenFaults(t *testing.T) {
	storeDown := errors.New("store unavailable")
	for name, tc := range map[string]struct {
		grantID string
		break_  func(h harness)
	}{
		"grant won't decode": {"", func(h harness) { h.grants.corruptAll() }},
		"token revoke fails": {"", func(h harness) { h.grants.failRevokeRefresh = storeDown }},
		"grant revoke fails": {"grant-1", func(h harness) { h.revocation.fail = storeDown }},
	} {
		t.Run(name, func(t *testing.T) {
			attesterKey := generateKey(t)
			h := newRevocationHarness(t, attesterKey)
			owner := &attestedInstance{t: t, h: h, attesterKey: attesterKey, instanceKey: generateKey(t)}
			attested, binding := embedderTokenRequest(t, owner)
			refreshToken, err := h.server.IssueRefreshToken(context.Background(), server.IssueRefreshTokenRequest{
				GrantType: preAuthorizedCodeGrant, Client: attested, Binding: binding,
				Subject: mustSubjectID(t, "holder-1"), Scope: []string{"accounts"}, GrantID: tc.grantID,
			})
			if err != nil {
				t.Fatalf("IssueRefreshToken: %v", err)
			}
			tc.break_(h)
			if code := serverErrorCode(t, owner.revoke(formParam("token", refreshToken.Reveal()))); code != server.ErrorServerError {
				t.Fatalf("RevokeToken = code %q, want server_error", code)
			}
			if last := lastAudit(t, h); last.Type != server.AuditEventRevokeToken || last.Outcome != server.AuditOutcomeFailure {
				t.Errorf("last audit event = %+v, want a RevokeToken failure", last)
			}
		})
	}
}

// TestRevokeTokenRevokesEveryGrantSharingItsGrantID pins what
// GrantedAuthorization.GrantID's doc warns about: revoking a refresh
// token revokes its grant by ID, so a grant ID shared by two grants
// would let one client end the other's. Each grant needs its own.
func TestRevokeTokenRevokesEveryGrantSharingItsGrantID(t *testing.T) {
	attesterKey := generateKey(t)
	h := newRevocationHarness(t, attesterKey)
	a := &attestedInstance{t: t, h: h, attesterKey: attesterKey, instanceKey: generateKey(t)}
	b := &attestedInstance{t: t, h: h, attesterKey: attesterKey, instanceKey: generateKey(t)}
	issue := func(i *attestedInstance) string {
		attested, binding := embedderTokenRequest(t, i)
		rt, err := h.server.IssueRefreshToken(context.Background(), server.IssueRefreshTokenRequest{
			GrantType: preAuthorizedCodeGrant, Client: attested, Binding: binding,
			Subject: mustSubjectID(t, "holder-1"), Scope: []string{"accounts"}, GrantID: "shared-id",
		})
		if err != nil {
			t.Fatalf("IssueRefreshToken: %v", err)
		}
		return rt.Reveal()
	}
	tokenA, tokenB := issue(a), issue(b)
	if err := a.revoke(formParam("token", tokenA)); err != nil {
		t.Fatalf("RevokeToken: %v", err)
	}
	if _, err := b.refresh(tokenB); serverErrorCode(t, err) != server.ErrorInvalidGrant {
		t.Fatalf("refresh of the other grant sharing the ID: %v, want invalid_grant", err)
	}
}

// TestRevokeTokenReportsTheGrantItEnded covers TokenRevocationResult: it
// names the grant a revocation ended, so the embedder can delete what it
// kept for it, and reports nothing when nothing was revoked.
func TestRevokeTokenReportsTheGrantItEnded(t *testing.T) {
	attesterKey := generateKey(t)
	h := newRevocationHarness(t, attesterKey)
	owner := &attestedInstance{t: t, h: h, attesterKey: attesterKey, instanceKey: generateKey(t)}
	other := &attestedInstance{t: t, h: h, attesterKey: attesterKey, instanceKey: generateKey(t)}
	issue := func(grantID string) string {
		attested, binding := embedderTokenRequest(t, owner)
		rt, err := h.server.IssueRefreshToken(context.Background(), server.IssueRefreshTokenRequest{
			GrantType: preAuthorizedCodeGrant, Client: attested, Binding: binding,
			Subject: mustSubjectID(t, "holder-1"), Scope: []string{"accounts"}, GrantID: grantID,
		})
		if err != nil {
			t.Fatalf("IssueRefreshToken: %v", err)
		}
		return rt.Reveal()
	}
	withGrant, withoutGrant := issue("passport-grant-1"), issue("")

	for name, tc := range map[string]struct {
		revoke func() (server.TokenRevocationResult, error)
		want   server.TokenRevocationResult
	}{
		"another installation's token": {func() (server.TokenRevocationResult, error) {
			return other.revokeResult(formParam("token", withGrant))
		}, server.TokenRevocationResult{}},
		"unknown token": {func() (server.TokenRevocationResult, error) {
			return owner.revokeResult(formParam("token", "unknown-token"))
		}, server.TokenRevocationResult{}},
		"token without a grant ID": {func() (server.TokenRevocationResult, error) {
			return owner.revokeResult(formParam("token", withoutGrant))
		}, server.TokenRevocationResult{Revoked: true}},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := tc.revoke()
			if err != nil || got != tc.want {
				t.Fatalf("RevokeToken = %+v, %v; want %+v", got, err, tc.want)
			}
		})
	}

	// Ordered: the owner revokes the grant's token, then again.
	got, err := owner.revokeResult(formParam("token", withGrant))
	if err != nil || got != (server.TokenRevocationResult{Revoked: true, GrantID: "passport-grant-1"}) {
		t.Fatalf("RevokeToken(owner) = %+v, %v; want the grant passport-grant-1 revoked", got, err)
	}
	if got, err := owner.revokeResult(formParam("token", withGrant)); err != nil || got != (server.TokenRevocationResult{}) {
		t.Fatalf("RevokeToken(already revoked) = %+v, %v; want nothing revoked", got, err)
	}
}

// TestRevokeTokenFailsClosed covers a failure part way through revoking
// a refresh token whose grant has a GrantID. The grant is revoked
// first: if that fails, the refresh token is left for a retry to find
// and finish; if deleting the token fails after it, the grant is
// already revoked, so the token is refused with it.
func TestRevokeTokenFailsClosed(t *testing.T) {
	storeDown := errors.New("store unavailable")
	issue := func(t *testing.T) (harness, *attestedInstance, string) {
		attesterKey := generateKey(t)
		h := newRevocationHarness(t, attesterKey)
		owner := &attestedInstance{t: t, h: h, attesterKey: attesterKey, instanceKey: generateKey(t)}
		attested, binding := embedderTokenRequest(t, owner)
		rt, err := h.server.IssueRefreshToken(context.Background(), server.IssueRefreshTokenRequest{
			GrantType: preAuthorizedCodeGrant, Client: attested, Binding: binding,
			Subject: mustSubjectID(t, "holder-1"), Scope: []string{"accounts"}, GrantID: "grant-1",
		})
		if err != nil {
			t.Fatalf("IssueRefreshToken: %v", err)
		}
		return h, owner, rt.Reveal()
	}

	t.Run("grant revocation fails", func(t *testing.T) {
		h, owner, refreshToken := issue(t)
		h.revocation.fail = storeDown
		if code := serverErrorCode(t, owner.revoke(formParam("token", refreshToken))); code != server.ErrorServerError {
			t.Fatalf("RevokeToken = code %q, want server_error", code)
		}
		h.revocation.fail = nil
		result, err := owner.revokeResult(formParam("token", refreshToken))
		if err != nil || !result.Revoked || result.GrantID != "grant-1" {
			t.Fatalf("retry = %+v, %v; want the token found and grant-1 revoked", result, err)
		}
	})

	t.Run("token deletion fails", func(t *testing.T) {
		h, owner, refreshToken := issue(t)
		h.grants.failRevokeRefresh = storeDown
		if code := serverErrorCode(t, owner.revoke(formParam("token", refreshToken))); code != server.ErrorServerError {
			t.Fatalf("RevokeToken = code %q, want server_error", code)
		}
		h.grants.failRevokeRefresh = nil
		h.revocation.mu.Lock()
		_, revoked := h.revocation.until["grant:grant-1"]
		h.revocation.mu.Unlock()
		if !revoked {
			t.Fatal("the grant wasn't revoked before the token deletion failed")
		}
		if _, err := owner.refresh(refreshToken); serverErrorCode(t, err) != server.ErrorInvalidGrant {
			t.Fatalf("refresh after the partial revocation: %v, want invalid_grant", err)
		}
	})

	t.Run("code grant revocation fails", func(t *testing.T) {
		attesterKey := generateKey(t)
		h := newRevocationHarness(t, attesterKey)
		owner := &attestedInstance{t: t, h: h, attesterKey: attesterKey, instanceKey: generateKey(t)}
		refreshToken := owner.issueRefreshToken()
		h.revocation.fail = storeDown
		if code := serverErrorCode(t, owner.revoke(formParam("token", refreshToken))); code != server.ErrorServerError {
			t.Fatalf("RevokeToken = code %q, want server_error", code)
		}
		if last := lastAudit(t, h); last.Type != server.AuditEventRevokeToken || last.Outcome != server.AuditOutcomeFailure {
			t.Errorf("last audit event = %+v, want a RevokeToken failure", last)
		}
		h.revocation.fail = nil
		// The token outlives the failure, so a retry can finish the job.
		if _, err := owner.refresh(refreshToken); err != nil {
			t.Fatalf("refresh after the failed revocation: %v, want the token still usable", err)
		}
	})
}

// TestRevokeTokenWithoutARevocationReader covers a refresh token whose
// code grant was named while the revocation store was readable, sent to
// an instance whose store no longer is: its grant's revocation can't be
// checked, so RevokeToken fails closed with server_error and deletes
// nothing, leaving the token for an instance that can check it.
func TestRevokeTokenWithoutARevocationReader(t *testing.T) {
	attesterKey := generateKey(t)
	h := newRevocationHarness(t, attesterKey)
	owner := &attestedInstance{t: t, h: h, attesterKey: attesterKey, instanceKey: generateKey(t)}
	refreshToken := owner.issueRefreshToken()

	deps := h.deps
	deps.Revocation = writeOnlyRevocationSink{}
	writeOnly, err := server.New(h.cfg, deps)
	if err != nil {
		t.Fatalf("server.New(write-only revocation): %v", err)
	}
	other := *owner
	other.h.server = writeOnly
	if code := serverErrorCode(t, other.revoke(formParam("token", refreshToken))); code != server.ErrorServerError {
		t.Fatalf("RevokeToken without a revocation reader = code %q, want server_error", code)
	}
	owner.pops = other.pops // the instance's PoPs must stay unique across both servers
	if _, err := owner.refresh(refreshToken); err != nil {
		t.Fatalf("refresh after the refused revocation: %v, want the token still usable", err)
	}
	if err := owner.revoke(formParam("token", refreshToken)); err != nil {
		t.Fatalf("RevokeToken with the readable store: %v", err)
	}
}

// TestRevokeTokenSearchesPastTheHint covers RFC 7009 §2.1's "the hint
// is only a hint": a refresh token sent with token_type_hint
// access_token is still revoked, while a token that isn't one is
// answered unsupported_token_type, as the access token it was said to
// be.
func TestRevokeTokenSearchesPastTheHint(t *testing.T) {
	attesterKey := generateKey(t)
	h := newRevocationHarness(t, attesterKey)
	owner := &attestedInstance{t: t, h: h, attesterKey: attesterKey, instanceKey: generateKey(t)}
	refreshToken := owner.issueRefreshToken()

	result, err := owner.revokeResult(formParam("token", refreshToken), formParam("token_type_hint", "access_token"))
	if err != nil || !result.Revoked {
		t.Fatalf("revoking a refresh token hinted as an access token = %+v, %v; want it revoked", result, err)
	}
	if _, err := owner.refresh(refreshToken); serverErrorCode(t, err) != server.ErrorInvalidGrant {
		t.Fatalf("refresh after revocation: %v, want invalid_grant", err)
	}
	if code := serverErrorCode(t, owner.revoke(formParam("token", "opaque-access-token"), formParam("token_type_hint", "access_token"))); code != server.ErrorUnsupportedTokenType {
		t.Fatalf("revoking an unknown token hinted as an access token = code %q, want unsupported_token_type", code)
	}
}
