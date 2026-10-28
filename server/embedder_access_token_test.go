package server_test

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/mtls"
	"github.com/idfoundry/fapigo/internal/token"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/resource"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
	"github.com/idfoundry/fapigo/storage/memstore"
)

// embedderAccessTokenRequest is a valid IssueAccessTokenRequest for the
// pre-authorized code grant, authenticated as instance and bound to
// dpopKey.
func embedderAccessTokenRequest(t *testing.T, instance *attestedInstance, dpopKey *ecdsa.PrivateKey) server.IssueAccessTokenRequest {
	t.Helper()
	attested, binding := embedderTokenRequestBoundTo(t, instance, dpopKey)
	return server.IssueAccessTokenRequest{
		GrantType: preAuthorizedCodeGrant, Client: attested, Binding: binding,
		Subject: mustSubjectID(t, "holder-1"), Scope: []string{"accounts"},
	}
}

// withOpaqueAccessTokens rebuilds h's server over the same stores, with
// OpaqueAccessTokens in place of JWTAccessTokens.
func withOpaqueAccessTokens(t *testing.T, h harness) (harness, *memstore.AccessTokenStore) {
	t.Helper()
	store := memstore.NewAccessTokenStore()
	deps := h.deps
	deps.AccessTokens = server.OpaqueAccessTokens{Store: store}
	srv, err := server.New(h.cfg, deps)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	h.server = srv
	h.deps = deps
	return h, store
}

// embedderResourceVerifier is a resource server accepting h's access
// tokens, JWT or (with store) opaque, and refusing revoked grants.
func embedderResourceVerifier(t *testing.T, h harness, store *memstore.AccessTokenStore) *resource.Verifier {
	t.Helper()
	var resolver resource.AccessTokenResolver = resource.OpaqueAccessTokens{Issuer: testIssuerURL, Store: store}
	if store == nil {
		issuerKeys, err := keys.NewLocalIssuerKeys(h.cfg.Issuer, h.deps.Keys)
		if err != nil {
			t.Fatal(err)
		}
		jwt, err := resource.NewJWTAccessTokens(issuerKeys, h.cfg.Issuer, testIssuer, fapi.ES256, 10*time.Minute, 4)
		if err != nil {
			t.Fatal(err)
		}
		resolver = jwt
	}
	verifier, err := resource.NewVerifier(resource.Config{
		Limits:       resource.Limits{MaxDPoPProofAge: time.Minute, MaxClockSkew: 5 * time.Second},
		Assurance:    resource.AssuranceDevelopment,
		ResourceURLs: testResourceServerURLs(t),
	}, resource.Dependencies{
		AccessTokens: resolver,
		Replay:       memstore.NewReplayStore(),
		Revocation:   revocationCheckerFromSink{sink: h.revocation},
		Clock:        fixedClock{now: h.now},
	})
	if err != nil {
		t.Fatalf("resource.NewVerifier: %v", err)
	}
	return verifier
}

func requireInvalidToken(t *testing.T, err error, what string) {
	t.Helper()
	var rerr *resource.Error
	if !errors.As(err, &rerr) || rerr.Code() != resource.ErrorInvalidToken {
		t.Fatalf("Verify(%s) = %v, want invalid_token", what, err)
	}
}

// TestIssueAccessTokenEndsWithItsGrant covers GrantID on the first
// access token: once the grant is revoked, by RevokeGrant or by revoking
// the refresh token issued for it, a resource server refuses the access
// token too, whether it's a JWT or opaque.
func TestIssueAccessTokenEndsWithItsGrant(t *testing.T) {
	revokers := map[string]func(t *testing.T, instance *attestedInstance, refreshToken string){
		"RevokeGrant": func(t *testing.T, instance *attestedInstance, _ string) {
			if err := instance.h.server.RevokeGrant(context.Background(), "grant-1"); err != nil {
				t.Fatalf("RevokeGrant: %v", err)
			}
		},
		"RevokeToken": func(t *testing.T, instance *attestedInstance, refreshToken string) {
			result, err := instance.revokeResult(formParam("token", refreshToken))
			if err != nil || !result.Revoked || result.GrantID != "grant-1" {
				t.Fatalf("RevokeToken = %+v, %v; want grant-1 revoked", result, err)
			}
		},
	}
	for _, format := range []string{"jwt", "opaque"} {
		for name, revoke := range revokers {
			t.Run(format+"/"+name, func(t *testing.T) {
				checkAccessTokenEndsWithGrant(t, format == "opaque", revoke)
			})
		}
	}
}

// checkAccessTokenEndsWithGrant issues an access token and a refresh
// token for one grant, then checks that once revoke ends the grant a
// resource server refuses the access token.
func checkAccessTokenEndsWithGrant(t *testing.T, opaque bool, revoke func(t *testing.T, instance *attestedInstance, refreshToken string)) {
	t.Helper()
	attesterKey := generateKey(t)
	h := newRevocationHarness(t, attesterKey)
	var store *memstore.AccessTokenStore
	if opaque {
		h, store = withOpaqueAccessTokens(t, h)
	}
	instance := &attestedInstance{t: t, h: h, attesterKey: attesterKey, instanceKey: generateKey(t)}
	dpopKey := generateKey(t)
	req := embedderAccessTokenRequest(t, instance, dpopKey)
	req.GrantID = "grant-1"

	result, err := h.server.IssueAccessToken(context.Background(), req)
	if err != nil {
		t.Fatalf("IssueAccessToken: %v", err)
	}
	refreshToken, err := h.server.IssueRefreshToken(context.Background(), server.IssueRefreshTokenRequest(req))
	if err != nil {
		t.Fatalf("IssueRefreshToken: %v", err)
	}
	verifier := embedderResourceVerifier(t, h, store)
	if err := verifyWithDPoP(t, verifier, dpopKey, result.AccessToken.Reveal(), h.now); err != nil {
		t.Fatalf("Verify(access token, before revocation): %v", err)
	}

	revoke(t, instance, refreshToken.Reveal())

	requireInvalidToken(t, verifyWithDPoP(t, verifier, dpopKey, result.AccessToken.Reveal(), h.now), "access token, after revocation")
}

// TestIssueAccessTokenMatchesRefreshedTokens: the first access token
// carries the same claims as the ones a refresh token for the grant
// issues later, bound to the request's own DPoP key, and the result is
// a complete token response.
func TestIssueAccessTokenMatchesRefreshedTokens(t *testing.T) {
	attesterKey := generateKey(t)
	h := newEmbedderRefreshHarness(t, attesterKey)
	instance := &attestedInstance{t: t, h: h, attesterKey: attesterKey, instanceKey: generateKey(t)}
	dpopKey := generateKey(t)
	req := embedderAccessTokenRequest(t, instance, dpopKey)
	req.AuthorizationDetails = []json.RawMessage{testPaymentDetailJSON}
	req.GrantID = "grant-1"
	// The harness issues no DPoP nonces; one from VerifyTokenRequestBinding
	// is passed through as is.
	req.Binding.NextDPoPNonce = "nonce-1"

	first, err := h.server.IssueAccessToken(context.Background(), req)
	if err != nil {
		t.Fatalf("IssueAccessToken: %v", err)
	}
	if last := lastAudit(t, h); last.Type != server.AuditEventIssueAccessToken || last.Outcome != server.AuditOutcomeSuccess {
		t.Errorf("last audit event = %+v, want an IssueAccessToken success", last)
	}
	checkFirstTokenResponse(t, first, req.Binding)
	refreshToken, err := h.server.IssueRefreshToken(context.Background(), server.IssueRefreshTokenRequest(req))
	if err != nil {
		t.Fatalf("IssueRefreshToken: %v", err)
	}
	refreshed, err := instance.refresh(refreshToken.Reveal())
	if err != nil {
		t.Fatalf("RefreshAccessToken: %v", err)
	}

	firstClaims := validatedAccessToken(t, h, first.AccessToken.Reveal())
	refreshedClaims := validatedAccessToken(t, h, refreshed.AccessToken.Reveal())
	if firstClaims.JKT != req.Binding.Thumbprint || firstClaims.X5TS256 != "" {
		t.Errorf("first token cnf = jkt %q, x5t#S256 %q; want jkt %q", firstClaims.JKT, firstClaims.X5TS256, req.Binding.Thumbprint)
	}
	if firstClaims.Subject != refreshedClaims.Subject || firstClaims.ClientID != refreshedClaims.ClientID || firstClaims.Scope != refreshedClaims.Scope {
		t.Errorf("first token sub/client_id/scope = %q/%q/%q, refreshed = %q/%q/%q",
			firstClaims.Subject, firstClaims.ClientID, firstClaims.Scope, refreshedClaims.Subject, refreshedClaims.ClientID, refreshedClaims.Scope)
	}
	if !maps.EqualFunc(firstClaims.Parameters, refreshedClaims.Parameters, func(a, b json.RawMessage) bool { return string(a) == string(b) }) {
		t.Errorf("first token claims = %v, refreshed = %v; want the same", firstClaims.Parameters, refreshedClaims.Parameters)
	}
	if string(firstClaims.Parameters["grant_id"]) != `"grant-1"` {
		t.Errorf("grant_id = %s, want \"grant-1\"", firstClaims.Parameters["grant_id"])
	}
}

func checkFirstTokenResponse(t *testing.T, result server.TokenResult, binding server.TokenBinding) {
	t.Helper()
	if result.TokenType != "DPoP" || result.ExpiresIn != 5*time.Minute || result.Scope != "accounts" {
		t.Errorf("TokenType/ExpiresIn/Scope = %q/%v/%q, want DPoP/5m/accounts", result.TokenType, result.ExpiresIn, result.Scope)
	}
	if result.HasIDToken || result.HasRefreshToken {
		t.Errorf("HasIDToken/HasRefreshToken = %v/%v, want neither", result.HasIDToken, result.HasRefreshToken)
	}
	if result.NextDPoPNonce == "" || result.NextDPoPNonce != binding.NextDPoPNonce {
		t.Errorf("NextDPoPNonce = %q, want the binding's %q", result.NextDPoPNonce, binding.NextDPoPNonce)
	}
	var details []json.RawMessage
	if err := json.Unmarshal(result.AuthorizationDetails, &details); err != nil || len(details) != 1 {
		t.Errorf("AuthorizationDetails = %s (%v), want the one granted", result.AuthorizationDetails, err)
	}
}

func validatedAccessToken(t *testing.T, h harness, raw string) token.ValidatedAccessToken {
	t.Helper()
	parsed, err := token.ParseAccessToken(raw)
	if err != nil {
		t.Fatal(err)
	}
	validated, err := parsed.Validate(&h.serverKey.PublicKey, token.AccessTokenValidatePolicy{
		ExpectedIssuer: testIssuer, ExpectedAudience: testIssuer, Algorithm: fapi.ES256, Now: h.now, MaxLifetime: 10 * time.Minute,
	})
	if err != nil {
		t.Fatalf("Validate access token: %v", err)
	}
	return validated
}

// TestIssueAccessTokenMTLSBinding: for an mTLS-bound client the token
// is a Bearer token bound to the certificate's thumbprint.
func TestIssueAccessTokenMTLSBinding(t *testing.T) {
	attesterKey := generateKey(t)
	h := newAttestationHarness(t, time.Now(), attesterKey, server.RegisteredAttesterKeys{}, func(cfg *server.Config, c *storage.RegisteredClientConfig) {
		cfg.AdditionalGrantTypes = []string{preAuthorizedCodeGrant}
		c.SenderConstrain = storage.SenderConstrainMTLS
	})
	instance := &attestedInstance{t: t, h: h, attesterKey: attesterKey, instanceKey: generateKey(t)}
	attestations, pops := instance.headers()
	header := http.Header{}
	header.Set("OAuth-Client-Attestation", attestations[0])
	header.Set("OAuth-Client-Attestation-PoP", pops[0])
	attested, err := h.server.AuthenticateAttestedClient(context.Background(), extensionTokenRequest(t, preAuthorizedForm(), header, nil).AttestedClientAuthentication())
	if err != nil {
		t.Fatalf("AuthenticateAttestedClient: %v", err)
	}
	cert := newTestCert(t, "client", certOptions{}).cert
	binding, err := h.server.VerifyTokenRequestBinding(context.Background(), attested.Client, extensionTokenRequest(t, preAuthorizedForm(), header, cert))
	if err != nil {
		t.Fatalf("VerifyTokenRequestBinding: %v", err)
	}
	thumbprint := mtls.Thumbprint(cert)
	result, err := h.server.IssueAccessToken(context.Background(), server.IssueAccessTokenRequest{
		GrantType: preAuthorizedCodeGrant, Client: attested, Binding: binding,
		Subject: mustSubjectID(t, "holder-1"), Scope: []string{"accounts"},
	})
	if err != nil {
		t.Fatalf("IssueAccessToken: %v", err)
	}
	if result.TokenType != "Bearer" {
		t.Errorf("TokenType = %q, want Bearer", result.TokenType)
	}
	if cnf := validatedAccessToken(t, h, result.AccessToken.Reveal()); cnf.X5TS256 != thumbprint || cnf.JKT != "" {
		t.Errorf("cnf = jkt %q, x5t#S256 %q; want x5t#S256 %q only", cnf.JKT, cnf.X5TS256, thumbprint)
	}
}

// TestIssueAccessTokenRefusals covers every request IssueAccessToken
// refuses, each recorded as a failure: the same checks as
// IssueRefreshToken's.
func TestIssueAccessTokenRefusals(t *testing.T) {
	attesterKey := generateKey(t)
	h := newEmbedderRefreshHarness(t, attesterKey)
	instance := &attestedInstance{t: t, h: h, attesterKey: attesterKey, instanceKey: generateKey(t)}
	base := embedderAccessTokenRequest(t, instance, generateKey(t))
	otherClient, err := storage.NewRegisteredClient(storage.RegisteredClientConfig{
		ID: "other-client", RedirectURIs: []fapi.RegisteredRedirectURI{testRedirectURI},
		ClientAuthMethod: storage.ClientAuthMethodAttestation, ExpectedAttesterIssuer: testAttesterIssuer,
		ClientAttestationAlgorithm: fapi.ES256, AllowedScopes: []string{"accounts"},
	})
	if err != nil {
		t.Fatal(err)
	}
	otherClientBinding := bindingVerifiedFor(t, h, otherClient, generateKey(t))
	cases := map[string]struct {
		mutate func(*server.IssueAccessTokenRequest)
		want   server.ErrorCode
	}{
		"hand-built binding": {func(r *server.IssueAccessTokenRequest) {
			r.Binding = server.TokenBinding{Thumbprint: r.Binding.Thumbprint, SenderConstrain: r.Binding.SenderConstrain}
		}, server.ErrorServerError},
		"binding verified for another client": {func(r *server.IssueAccessTokenRequest) { r.Binding = otherClientBinding }, server.ErrorServerError},
		"grant type not configured":           {func(r *server.IssueAccessTokenRequest) { r.GrantType = "authorization_code" }, server.ErrorServerError},
		"client not authenticated":            {func(r *server.IssueAccessTokenRequest) { r.Client = server.AttestedClient{Client: r.Client.Client} }, server.ErrorServerError},
		"client swapped after authentication": {func(r *server.IssueAccessTokenRequest) { r.Client.Client = otherClient }, server.ErrorServerError},
		"no binding":                          {func(r *server.IssueAccessTokenRequest) { r.Binding = server.TokenBinding{} }, server.ErrorServerError},
		"binding of another kind":             {func(r *server.IssueAccessTokenRequest) { r.Binding.SenderConstrain = storage.SenderConstrainMTLS }, server.ErrorServerError},
		"no subject":                          {func(r *server.IssueAccessTokenRequest) { r.Subject = server.SubjectID{} }, server.ErrorServerError},
		"nothing granted":                     {func(r *server.IssueAccessTokenRequest) { r.Scope = nil }, server.ErrorServerError},
		"openid":                              {func(r *server.IssueAccessTokenRequest) { r.Scope = []string{"openid", "accounts"} }, server.ErrorInvalidScope},
		"scope not allowed":                   {func(r *server.IssueAccessTokenRequest) { r.Scope = []string{"payments"} }, server.ErrorInvalidScope},
		"detail type not for client": {func(r *server.IssueAccessTokenRequest) {
			r.AuthorizationDetails = []json.RawMessage{json.RawMessage(`{"type":"openid_credential","credential_configuration_id":"x"}`)}
		}, server.ErrorInvalidAuthorizationDetails},
		"invalid grant ID": {func(r *server.IssueAccessTokenRequest) { r.GrantID = "has space" }, server.ErrorServerError},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			req := base
			tc.mutate(&req)
			_, err := h.server.IssueAccessToken(context.Background(), req)
			if code := serverErrorCode(t, err); code != tc.want {
				t.Fatalf("error code = %q (%v), want %q", code, err, tc.want)
			}
			if last := lastAudit(t, h); last.Type != server.AuditEventIssueAccessToken || last.Outcome != server.AuditOutcomeFailure {
				t.Errorf("last audit event = %+v, want an IssueAccessToken failure", last)
			}
		})
	}
	if _, err := h.server.IssueAccessToken(context.Background(), base); err != nil {
		t.Fatalf("valid request refused: %v", err)
	}
}

// bindingVerifiedFor verifies a DPoP-bound token request's binding, signed
// by dpopKey, for client.
func bindingVerifiedFor(t *testing.T, h harness, client storage.RegisteredClient, dpopKey *ecdsa.PrivateKey) server.TokenBinding {
	t.Helper()
	req := extensionTokenRequest(t, preAuthorizedForm(), dpopHeader(dpopProofAt(t, dpopKey, testTokenEndpoint, "", h.now)), nil)
	binding, err := h.server.VerifyTokenRequestBinding(context.Background(), client, req)
	if err != nil {
		t.Fatalf("VerifyTokenRequestBinding: %v", err)
	}
	return binding
}

// TestIssueAccessTokenIssuerFailure: an access token issuer that fails
// is a server_error, recorded as a failure.
func TestIssueAccessTokenIssuerFailure(t *testing.T) {
	attesterKey := generateKey(t)
	h := newEmbedderRefreshHarness(t, attesterKey)
	deps := h.deps
	deps.AccessTokens = failingAccessTokenIssuer{}
	srv, err := server.New(h.cfg, deps)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	h.server = srv
	instance := &attestedInstance{t: t, h: h, attesterKey: attesterKey, instanceKey: generateKey(t)}
	_, err = h.server.IssueAccessToken(context.Background(), embedderAccessTokenRequest(t, instance, generateKey(t)))
	if code := serverErrorCode(t, err); code != server.ErrorServerError {
		t.Fatalf("error code = %q (%v), want server_error", code, err)
	}
	if last := lastAudit(t, h); last.Type != server.AuditEventIssueAccessToken || last.Outcome != server.AuditOutcomeFailure {
		t.Errorf("last audit event = %+v, want an IssueAccessToken failure", last)
	}
}

type failingAccessTokenIssuer struct{}

func (failingAccessTokenIssuer) IssueAccessToken(context.Context, server.AccessTokenParams) (string, string, error) {
	return "", "", errors.New("issuer unavailable")
}

// TestEmbedderGrantRefusesExpiredAttestation: an AttestedClient whose
// attestation expired more than MaxClockSkew ago was kept from an
// earlier request rather than authenticated for this one, so neither
// IssueAccessToken nor IssueRefreshToken issues for it.
func TestEmbedderGrantRefusesExpiredAttestation(t *testing.T) {
	attesterKey := generateKey(t)
	h := newRevocationHarness(t, attesterKey)
	instance := &attestedInstance{t: t, h: h, attesterKey: attesterKey, instanceKey: generateKey(t)}
	req := embedderAccessTokenRequest(t, instance, generateKey(t))
	expiry := req.Client.AttestationExpiresAt.Add(h.cfg.Limits.MaxClockSkew)
	at := func(now time.Time) *server.Server {
		deps := h.deps
		deps.Clock = fixedClock{now: now}
		srv, err := server.New(h.cfg, deps)
		if err != nil {
			t.Fatal(err)
		}
		return srv
	}

	within := at(expiry)
	if _, err := within.IssueAccessToken(context.Background(), req); err != nil {
		t.Fatalf("IssueAccessToken at the attestation's exp plus skew: %v", err)
	}
	past := at(expiry.Add(time.Second))
	if _, err := past.IssueAccessToken(context.Background(), req); serverErrorCode(t, err) != server.ErrorServerError {
		t.Errorf("IssueAccessToken past the attestation's exp = %v, want server_error", err)
	}
	if _, err := past.IssueRefreshToken(context.Background(), server.IssueRefreshTokenRequest(req)); serverErrorCode(t, err) != server.ErrorServerError {
		t.Errorf("IssueRefreshToken past the attestation's exp = %v, want server_error", err)
	}
}

// TestEmbedderGrantRefusesRevokedGrantID: a GrantID already revoked
// issues nothing more, as a refresh of the grant wouldn't: invalid_grant,
// recorded as a failure.
func TestEmbedderGrantRefusesRevokedGrantID(t *testing.T) {
	attesterKey := generateKey(t)
	h := newRevocationHarness(t, attesterKey)
	instance := &attestedInstance{t: t, h: h, attesterKey: attesterKey, instanceKey: generateKey(t)}
	req := embedderAccessTokenRequest(t, instance, generateKey(t))
	req.GrantID = "grant-revoked"
	if err := h.server.RevokeGrant(context.Background(), req.GrantID); err != nil {
		t.Fatal(err)
	}

	if _, err := h.server.IssueAccessToken(context.Background(), req); serverErrorCode(t, err) != server.ErrorInvalidGrant {
		t.Errorf("IssueAccessToken = %v, want invalid_grant", err)
	}
	if last := lastAudit(t, h); last.Type != server.AuditEventIssueAccessToken || last.Outcome != server.AuditOutcomeFailure {
		t.Errorf("last audit event = %+v, want an IssueAccessToken failure", last)
	}
	if _, err := h.server.IssueRefreshToken(context.Background(), server.IssueRefreshTokenRequest(req)); serverErrorCode(t, err) != server.ErrorInvalidGrant {
		t.Errorf("IssueRefreshToken = %v, want invalid_grant", err)
	}

	req.GrantID = "grant-live"
	if _, err := h.server.IssueAccessToken(context.Background(), req); err != nil {
		t.Errorf("IssueAccessToken for a grant not revoked: %v", err)
	}
}
