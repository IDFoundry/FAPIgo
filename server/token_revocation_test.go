package server_test

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
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
	if _, err := owner.refresh(refreshToken); err != nil {
		t.Fatalf("refresh after another instance's revocation: %v, want the token still live", err)
	}

	if err := owner.revoke(formParam("token", refreshToken)); err != nil {
		t.Fatalf("revoke by the owner: %v", err)
	}
	if last := lastAudit(t, h); last.Type != server.AuditEventRevokeToken || last.Outcome != server.AuditOutcomeSuccess {
		t.Errorf("last audit event = %+v, want a RevokeToken success", last)
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
			return h.server.RevokeToken(ctx, server.TokenRevocationRequest{HTTP: server.FormRequest{Parameters: []server.FormParameter{formParam("token", "x")}}})
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
