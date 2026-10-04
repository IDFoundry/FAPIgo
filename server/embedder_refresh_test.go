package server_test

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/extension"
	"github.com/idfoundry/fapigo/internal/token"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
)

// testCredentialDetail is a second RAR type, registered with the server
// but not for testClientID.
type testCredentialDetail struct {
	Type string `json:"type"`
	ID   string `json:"credential_configuration_id"`
}

// newEmbedderRefreshHarness serves the pre-authorized code grant itself
// (Config.AdditionalGrantTypes), with testClientID authenticated by
// attestation and registered for the "payment" RAR type only.
func newEmbedderRefreshHarness(t *testing.T, attesterKey *ecdsa.PrivateKey) harness {
	t.Helper()
	registry, err := extension.NewRARRegistry(4096, 4, paymentRARDef,
		extension.RARDefinition[testCredentialDetail]{Type: "openid_credential", MaxObjects: 5, MaxBytesPerObject: 1024})
	if err != nil {
		t.Fatalf("NewRARRegistry: %v", err)
	}
	return newAttestationHarness(t, time.Now(), attesterKey, server.RegisteredAttesterKeys{}, func(cfg *server.Config, c *storage.RegisteredClientConfig) {
		cfg.AdditionalGrantTypes = []string{preAuthorizedCodeGrant}
		cfg.RAR = registry
		c.AllowedScopes = []string{"openid", "accounts"}
		c.AuthorizationDetailsTypes = []string{"payment"}
	})
}

// embedderTokenRequest authenticates a pre-authorized code token request
// from instance and verifies its DPoP binding, as an embedder serving
// the grant does before issuing tokens.
func embedderTokenRequest(t *testing.T, instance *attestedInstance) (server.AttestedClient, server.TokenBinding) {
	t.Helper()
	attestations, pops := instance.headers()
	header := dpopHeader(dpopProofAt(t, generateKey(t), testTokenEndpoint, "", instance.h.now))
	header.Set("OAuth-Client-Attestation", attestations[0])
	header.Set("OAuth-Client-Attestation-PoP", pops[0])
	req := extensionTokenRequest(t, preAuthorizedForm(), header, nil)
	ctx := context.Background()
	attested, err := instance.h.server.AuthenticateAttestedClient(ctx, req.AttestedClientAuthentication())
	if err != nil {
		t.Fatalf("AuthenticateAttestedClient: %v", err)
	}
	binding, err := instance.h.server.VerifyTokenRequestBinding(ctx, attested.Client, req)
	if err != nil {
		t.Fatalf("VerifyTokenRequestBinding: %v", err)
	}
	return attested, binding
}

func mustSubjectID(t *testing.T, value string) server.SubjectID {
	t.Helper()
	id, err := server.NewSubjectID(value)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

var testPaymentDetailJSON = json.RawMessage(`{"type":"payment","actions":["initiate"],"amount":"10.00"}`)

// TestIssueRefreshTokenForEmbedderGrant covers the refresh token an
// embedder issues for a grant it served itself: RefreshAccessToken
// redeems it for the grant's subject, scope and authorization details,
// with no ID token, and only for the instance it was issued to.
func TestIssueRefreshTokenForEmbedderGrant(t *testing.T) {
	attesterKey := generateKey(t)
	h := newEmbedderRefreshHarness(t, attesterKey)
	issuing := &attestedInstance{t: t, h: h, attesterKey: attesterKey, instanceKey: generateKey(t)}
	other := &attestedInstance{t: t, h: h, attesterKey: attesterKey, instanceKey: generateKey(t)}
	attested, binding := embedderTokenRequest(t, issuing)

	refreshToken, err := h.server.IssueRefreshToken(context.Background(), server.IssueRefreshTokenRequest{
		GrantType: preAuthorizedCodeGrant, Client: attested, Binding: binding,
		Subject: mustSubjectID(t, "holder-1"), Scope: []string{"accounts"},
		AuthorizationDetails: []json.RawMessage{testPaymentDetailJSON},
	})
	if err != nil {
		t.Fatalf("IssueRefreshToken: %v", err)
	}
	if last := h.audit.all()[len(h.audit.all())-1]; last.Type != server.AuditEventIssueRefreshToken || last.Outcome != server.AuditOutcomeSuccess {
		t.Errorf("last audit event = %+v, want an IssueRefreshToken success", last)
	}

	result, err := issuing.refresh(refreshToken.Reveal())
	if err != nil {
		t.Fatalf("RefreshAccessToken: %v", err)
	}
	if result.HasIDToken {
		t.Error("refresh issued an ID token for a grant with no authenticated user")
	}
	if result.Scope != "accounts" {
		t.Errorf("Scope = %q, want accounts", result.Scope)
	}
	var details []json.RawMessage
	if err := json.Unmarshal(result.AuthorizationDetails, &details); err != nil || len(details) != 1 {
		t.Fatalf("AuthorizationDetails = %s (%v), want the one granted", result.AuthorizationDetails, err)
	}
	parsed, err := token.ParseAccessToken(result.AccessToken.Reveal())
	if err != nil {
		t.Fatal(err)
	}
	validated, err := parsed.Validate(&h.serverKey.PublicKey, token.AccessTokenValidatePolicy{
		ExpectedIssuer: testIssuer, ExpectedAudience: testIssuer, Algorithm: fapi.ES256, Now: h.now, MaxLifetime: 10 * time.Minute,
	})
	if err != nil {
		t.Fatalf("Validate access token: %v", err)
	}
	if validated.Subject != "holder-1" || validated.Parameters["authorization_details"] == nil {
		t.Errorf("access token sub = %q, authorization_details = %s; want holder-1 and the grant's details", validated.Subject, validated.Parameters["authorization_details"])
	}

	_, err = other.refresh(refreshToken.Reveal())
	var serverErr *server.Error
	if !errors.As(err, &serverErr) || serverErr.Code() != server.ErrorInvalidGrant {
		t.Fatalf("refresh by another instance: err = %v, want invalid_grant", err)
	}
}

// TestIssueRefreshTokenRevokedGrant covers GrantID: RevokeGrant stops
// the refresh token working.
func TestIssueRefreshTokenRevokedGrant(t *testing.T) {
	attesterKey := generateKey(t)
	h := newEmbedderRefreshHarness(t, attesterKey)
	issuing := &attestedInstance{t: t, h: h, attesterKey: attesterKey, instanceKey: generateKey(t)}
	attested, binding := embedderTokenRequest(t, issuing)
	refreshToken, err := h.server.IssueRefreshToken(context.Background(), server.IssueRefreshTokenRequest{
		GrantType: preAuthorizedCodeGrant, Client: attested, Binding: binding,
		Subject: mustSubjectID(t, "holder-1"), Scope: []string{"accounts"}, GrantID: "grant-1",
	})
	if err != nil {
		t.Fatalf("IssueRefreshToken: %v", err)
	}
	if err := h.server.RevokeGrant(context.Background(), "grant-1"); err != nil {
		t.Fatalf("RevokeGrant: %v", err)
	}
	if _, err := issuing.refresh(refreshToken.Reveal()); err == nil {
		t.Fatal("refresh of a revoked grant succeeded")
	}
}

// TestIssueRefreshTokenRefusals covers every request IssueRefreshToken
// refuses, each recorded as a failure.
func TestIssueRefreshTokenRefusals(t *testing.T) {
	attesterKey := generateKey(t)
	h := newEmbedderRefreshHarness(t, attesterKey)
	instance := &attestedInstance{t: t, h: h, attesterKey: attesterKey, instanceKey: generateKey(t)}
	attested, binding := embedderTokenRequest(t, instance)
	otherClient, err := storage.NewRegisteredClient(storage.RegisteredClientConfig{
		ID: "other-client", RedirectURIs: []fapi.RegisteredRedirectURI{testRedirectURI},
		ClientAuthMethod: storage.ClientAuthMethodAttestation, ExpectedAttesterIssuer: testAttesterIssuer,
		ClientAttestationAlgorithm: fapi.ES256, AllowedScopes: []string{"accounts"},
	})
	if err != nil {
		t.Fatal(err)
	}
	valid := func() server.IssueRefreshTokenRequest {
		return server.IssueRefreshTokenRequest{
			GrantType: preAuthorizedCodeGrant, Client: attested, Binding: binding,
			Subject: mustSubjectID(t, "holder-1"), Scope: []string{"accounts"},
		}
	}
	cases := map[string]struct {
		mutate func(*server.IssueRefreshTokenRequest)
		want   server.ErrorCode
	}{
		"grant type not configured":           {func(r *server.IssueRefreshTokenRequest) { r.GrantType = "authorization_code" }, server.ErrorServerError},
		"client not authenticated":            {func(r *server.IssueRefreshTokenRequest) { r.Client = server.AttestedClient{Client: attested.Client} }, server.ErrorServerError},
		"client swapped after authentication": {func(r *server.IssueRefreshTokenRequest) { r.Client.Client = otherClient }, server.ErrorServerError},
		"no binding":                          {func(r *server.IssueRefreshTokenRequest) { r.Binding = server.TokenBinding{} }, server.ErrorServerError},
		"binding for another client":          {func(r *server.IssueRefreshTokenRequest) { r.Binding.SenderConstrain = storage.SenderConstrainMTLS }, server.ErrorServerError},
		"no subject":                          {func(r *server.IssueRefreshTokenRequest) { r.Subject = server.SubjectID{} }, server.ErrorServerError},
		"nothing granted":                     {func(r *server.IssueRefreshTokenRequest) { r.Scope = nil }, server.ErrorServerError},
		"openid":                              {func(r *server.IssueRefreshTokenRequest) { r.Scope = []string{"openid", "accounts"} }, server.ErrorInvalidScope},
		"scope not allowed":                   {func(r *server.IssueRefreshTokenRequest) { r.Scope = []string{"payments"} }, server.ErrorInvalidScope},
		"unregistered detail type": {func(r *server.IssueRefreshTokenRequest) {
			r.AuthorizationDetails = []json.RawMessage{json.RawMessage(`{"type":"unknown"}`)}
		}, server.ErrorInvalidAuthorizationDetails},
		"detail type not for client": {func(r *server.IssueRefreshTokenRequest) {
			r.AuthorizationDetails = []json.RawMessage{json.RawMessage(`{"type":"openid_credential","credential_configuration_id":"x"}`)}
		}, server.ErrorInvalidAuthorizationDetails},
		"detail with case variant": {func(r *server.IssueRefreshTokenRequest) {
			r.AuthorizationDetails = []json.RawMessage{json.RawMessage(`{"type":"payment","actions":["a"],"AMOUNT":"1"}`)}
		}, server.ErrorInvalidAuthorizationDetails},
		"invalid grant ID": {func(r *server.IssueRefreshTokenRequest) { r.GrantID = "has space" }, server.ErrorServerError},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			req := valid()
			tc.mutate(&req)
			_, err := h.server.IssueRefreshToken(context.Background(), req)
			if code := serverErrorCode(t, err); code != tc.want {
				t.Fatalf("error code = %q (%v), want %q", code, err, tc.want)
			}
			last := h.audit.all()[len(h.audit.all())-1]
			if last.Type != server.AuditEventIssueRefreshToken || last.Outcome != server.AuditOutcomeFailure {
				t.Errorf("last audit event = %+v, want an IssueRefreshToken failure", last)
			}
		})
	}
	if _, err := h.server.IssueRefreshToken(context.Background(), valid()); err != nil {
		t.Fatalf("valid request refused: %v", err)
	}
}
