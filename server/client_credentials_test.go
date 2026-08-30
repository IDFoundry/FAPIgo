package server_test

import (
	"context"
	"crypto/rand"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/extension"
	"github.com/idfoundry/fapigo/internal/clientassertion"
	"github.com/idfoundry/fapigo/internal/mtls"
	"github.com/idfoundry/fapigo/internal/token"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
)

// newHarnessWithClientCredentialsGrant mirrors newHarness (baseline
// profile, request objects allowed) exactly, except
// Config.ClientCredentialsGrant is enabled, testClientID is registered
// with senderConstrain and AllowedScopes ["accounts"] (deliberately
// excluding "openid"/"offline_access" — neither ID tokens nor refresh
// tokens are ever relevant to this grant, so a test scope that could be
// mistaken for triggering either would be misleading), and
// AllowsClientCredentialsGrant is clientAllowsGrant.
func newHarnessWithClientCredentialsGrant(t *testing.T, senderConstrain storage.SenderConstrain, clientAllowsGrant bool) harness {
	t.Helper()
	now := time.Now()
	key := generateKey(t)
	serverKey := generateKey(t)

	client, err := storage.NewRegisteredClient(storage.RegisteredClientConfig{
		ID:                           testClientID,
		RedirectURIs:                 []fapi.RegisteredRedirectURI{testRedirectURI},
		ClientAssertionAlgorithm:     fapi.ES256,
		SenderConstrain:              senderConstrain,
		AllowedScopes:                []string{"accounts"},
		AllowsClientCredentialsGrant: clientAllowsGrant,
	})
	if err != nil {
		t.Fatalf("NewRegisteredClient: %v", err)
	}

	issuer, err := fapi.ParseIssuerURL(testIssuer)
	if err != nil {
		t.Fatalf("ParseIssuerURL: %v", err)
	}

	transactions := &fakeTransactionStore{}
	grants := &fakeGrantStore{}
	audit := &fakeAuditSink{}
	revocation := &fakeRevocationSink{}

	cfg := server.Config{
		Issuer:    issuer,
		Endpoints: testEndpoints(t),
		Profile:   server.ProfileFAPISecurity,
		Algorithms: server.AlgorithmPolicy{
			ClientAssertion: server.AlgorithmSet{fapi.ES256},
			RequestObject:   server.AlgorithmSet{fapi.ES256},
			JARM:            fapi.ES256,
			IDToken:         fapi.ES256,
		},
		Limits: server.Limits{
			PushedRequestLifetime:      90 * time.Second,
			MaxClientAssertionLifetime: time.Minute,
			MaxRequestObjectLifetime:   time.Minute,
			InteractionLifetime:        5 * time.Minute,
			AuthorizationCodeLifetime:  time.Minute,
			JARMResponseLifetime:       time.Minute,
			AccessTokenLifetime:        5 * time.Minute,
			IDTokenLifetime:            5 * time.Minute,
			RefreshTokenLifetime:       5 * time.Minute,
			MaxDPoPProofAge:            time.Minute,
			MaxClockSkew:               5 * time.Second,
		},
		Assurance:              server.AssuranceDevelopment,
		ClientCredentialsGrant: true,
	}
	serverKeyManager := &fakeKeyManager{key: serverKey, keyID: "as-key-1"}
	deps := server.Dependencies{
		Clients:      &fakeClientRepository{clients: map[fapi.ClientID]storage.RegisteredClient{testClientID: client}},
		Transactions: transactions,
		Grants:       grants,
		Replay:       &fakeReplayStore{},
		ClientKeys: &fakeClientKeySource{keysByClient: map[fapi.ClientID][]keys.VerificationKey{
			testClientID: {{Algorithm: fapi.ES256, PublicKey: &key.PublicKey}},
		}},
		Keys:         serverKeyManager,
		AccessTokens: server.JWTAccessTokens{Keys: serverKeyManager, Algorithm: fapi.ES256},
		Revocation:   revocation,
		Audit:        audit,
		Clock:        fixedClock{now: now},
		Random:       rand.Reader,
	}

	srv, err := server.New(cfg, deps)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	return harness{server: srv, key: key, serverKey: serverKey, transactions: transactions, grants: grants, audit: audit, revocation: revocation, now: now}
}

func clientCredentialsFormParams(assertion, scope string) []server.FormParameter {
	return []server.FormParameter{
		formParam("client_assertion", assertion),
		formParam("client_assertion_type", clientassertion.AssertionType),
		formParam("grant_type", "client_credentials"),
		formParam("scope", scope),
	}
}

// newHarnessWithClientCredentialsGrantAndRAR mirrors
// newHarnessWithClientCredentialsGrant (client_credentials always
// enabled, testClientID always opted in) with Config.RAR also set to
// registry — RFC 9396 §6's client_credentials authorization_details
// support has no resource-owner grant step of its own, so it doesn't
// need newHarnessWithRAR's heavier PAR/CIBA-shaped wiring (backchannel
// store, request-object algorithms, etc.).
func newHarnessWithClientCredentialsGrantAndRAR(t *testing.T, registry *extension.RARRegistry) harness {
	t.Helper()
	now := time.Now()
	key := generateKey(t)
	serverKey := generateKey(t)

	client, err := storage.NewRegisteredClient(storage.RegisteredClientConfig{
		ID:                           testClientID,
		RedirectURIs:                 []fapi.RegisteredRedirectURI{testRedirectURI},
		ClientAssertionAlgorithm:     fapi.ES256,
		SenderConstrain:              storage.SenderConstrainDPoP,
		AllowedScopes:                []string{"accounts"},
		AllowsClientCredentialsGrant: true,
	})
	if err != nil {
		t.Fatalf("NewRegisteredClient: %v", err)
	}

	issuer, err := fapi.ParseIssuerURL(testIssuer)
	if err != nil {
		t.Fatalf("ParseIssuerURL: %v", err)
	}

	cfg := server.Config{
		Issuer:    issuer,
		Endpoints: testEndpoints(t),
		Profile:   server.ProfileFAPISecurity,
		Algorithms: server.AlgorithmPolicy{
			ClientAssertion: server.AlgorithmSet{fapi.ES256},
			RequestObject:   server.AlgorithmSet{fapi.ES256},
			JARM:            fapi.ES256,
			IDToken:         fapi.ES256,
		},
		Limits: server.Limits{
			PushedRequestLifetime:      90 * time.Second,
			MaxClientAssertionLifetime: time.Minute,
			MaxRequestObjectLifetime:   time.Minute,
			InteractionLifetime:        5 * time.Minute,
			AuthorizationCodeLifetime:  time.Minute,
			JARMResponseLifetime:       time.Minute,
			AccessTokenLifetime:        5 * time.Minute,
			IDTokenLifetime:            5 * time.Minute,
			RefreshTokenLifetime:       5 * time.Minute,
			MaxDPoPProofAge:            time.Minute,
			MaxClockSkew:               5 * time.Second,
		},
		Assurance:              server.AssuranceDevelopment,
		ClientCredentialsGrant: true,
		RAR:                    registry,
	}
	serverKeyManager := &fakeKeyManager{key: serverKey, keyID: "as-key-1"}
	deps := server.Dependencies{
		Clients:      &fakeClientRepository{clients: map[fapi.ClientID]storage.RegisteredClient{testClientID: client}},
		Transactions: &fakeTransactionStore{},
		Grants:       &fakeGrantStore{},
		Replay:       &fakeReplayStore{},
		ClientKeys: &fakeClientKeySource{keysByClient: map[fapi.ClientID][]keys.VerificationKey{
			testClientID: {{Algorithm: fapi.ES256, PublicKey: &key.PublicKey}},
		}},
		Keys:         serverKeyManager,
		AccessTokens: server.JWTAccessTokens{Keys: serverKeyManager, Algorithm: fapi.ES256},
		Revocation:   server.NoRevocation{},
		Clock:        fixedClock{now: now},
		Random:       rand.Reader,
	}
	srv, err := server.New(cfg, deps)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	return harness{server: srv, key: key, serverKey: serverKey, now: now}
}

// TestRequestClientCredentialsTokenAuthorizationDetailsFlow covers RFC
// 9396 §6: an authorization_details token request parameter, issued
// verbatim into the access token's own claim since this grant has no
// resource owner to narrow it against (unlike
// TestExchangeAuthorizationCodeMergesAuthorizationDetailsWithExistingTokenClaims's
// PAR/consent-shaped flow).
func TestRequestClientCredentialsTokenAuthorizationDetailsFlow(t *testing.T) {
	registry := newTestRARRegistry(t)
	h := newHarnessWithClientCredentialsGrantAndRAR(t, registry)
	params := clientCredentialsFormParams(h.clientAssertion(t), "accounts")
	params = append(params, formParam("authorization_details", `[{"type":"payment","actions":["approve"],"amount":"SGD 10.00"}]`))

	result, err := h.server.RequestClientCredentialsToken(context.Background(), server.ClientCredentialsTokenRequest{
		HTTP:      server.FormRequest{Parameters: params},
		DPoPProof: createDPoPProof(t, generateKey(t), h.now),
	})
	if err != nil {
		t.Fatalf("RequestClientCredentialsToken: %v", err)
	}
	if len(result.AuthorizationDetails) == 0 {
		t.Fatalf("TokenResult.AuthorizationDetails is empty")
	}
	values, err := registry.Parse(result.AuthorizationDetails)
	if err != nil {
		t.Fatalf("Parse granted authorization_details: %v", err)
	}
	details, err := extension.RARGet(values, paymentRARDef)
	if err != nil {
		t.Fatalf("RARGet: %v", err)
	}
	if len(details) != 1 || details[0].Fields.Amount != "SGD 10.00" {
		t.Fatalf("granted details = %+v, want one payment detail for SGD 10.00", details)
	}
	claim := authorizationDetailsAccessTokenClaim(t, result.AccessToken.Reveal(), &h.serverKey.PublicKey)
	if len(claim) == 0 {
		t.Fatalf("access token authorization_details claim is empty")
	}
}

func TestRequestClientCredentialsTokenRejectsMalformedAuthorizationDetails(t *testing.T) {
	h := newHarnessWithClientCredentialsGrantAndRAR(t, newTestRARRegistry(t))
	params := clientCredentialsFormParams(h.clientAssertion(t), "accounts")
	params = append(params, formParam("authorization_details", `[{"type":"unregistered-type"}]`))

	_, err := h.server.RequestClientCredentialsToken(context.Background(), server.ClientCredentialsTokenRequest{
		HTTP:      server.FormRequest{Parameters: params},
		DPoPProof: createDPoPProof(t, generateKey(t), h.now),
	})
	if err == nil {
		t.Fatalf("RequestClientCredentialsToken = nil error, want error")
	}
	if code := serverErrorCode(t, err); code != server.ErrorInvalidRequest {
		t.Fatalf("error code = %q, want %q", code, server.ErrorInvalidRequest)
	}
}

func TestRequestClientCredentialsTokenRejectsAuthorizationDetailsWithoutRARConfigured(t *testing.T) {
	h := newHarnessWithClientCredentialsGrant(t, storage.SenderConstrainDPoP, true) // Config.RAR left nil
	params := clientCredentialsFormParams(h.clientAssertion(t), "accounts")
	params = append(params, formParam("authorization_details", `[{"type":"payment","actions":["approve"]}]`))

	_, err := h.server.RequestClientCredentialsToken(context.Background(), server.ClientCredentialsTokenRequest{
		HTTP:      server.FormRequest{Parameters: params},
		DPoPProof: createDPoPProof(t, generateKey(t), h.now),
	})
	if err == nil {
		t.Fatalf("RequestClientCredentialsToken = nil error, want error")
	}
	if code := serverErrorCode(t, err); code != server.ErrorInvalidRequest {
		t.Fatalf("error code = %q, want %q", code, server.ErrorInvalidRequest)
	}
}

func TestRequestClientCredentialsTokenSuccessDPoP(t *testing.T) {
	h := newHarnessWithClientCredentialsGrant(t, storage.SenderConstrainDPoP, true)
	dpopKey := generateKey(t)

	result, err := h.server.RequestClientCredentialsToken(context.Background(), server.ClientCredentialsTokenRequest{
		HTTP:      server.FormRequest{Parameters: clientCredentialsFormParams(h.clientAssertion(t), "accounts")},
		DPoPProof: createDPoPProof(t, dpopKey, h.now),
	})
	if err != nil {
		t.Fatalf("RequestClientCredentialsToken: %v", err)
	}
	if result.AccessToken.Reveal() == "" {
		t.Fatalf("AccessToken is empty")
	}
	if result.TokenType != "DPoP" {
		t.Fatalf("TokenType = %q, want %q", result.TokenType, "DPoP")
	}
	if result.Scope != "accounts" {
		t.Fatalf("Scope = %q, want %q", result.Scope, "accounts")
	}
	if result.HasIDToken {
		t.Fatalf("HasIDToken = true, want false — client_credentials issues no ID token")
	}
	if result.HasRefreshToken {
		t.Fatalf("HasRefreshToken = true, want false — RFC 6749 §4.4.3")
	}

	parsedAT, err := token.ParseAccessToken(result.AccessToken.Reveal())
	if err != nil {
		t.Fatalf("ParseAccessToken: %v", err)
	}
	dpopJWK, err := jwkThumbprintFor(dpopKey)
	if err != nil {
		t.Fatalf("thumbprint: %v", err)
	}
	validatedAT, err := parsedAT.Validate(&h.serverKey.PublicKey, token.AccessTokenValidatePolicy{
		ExpectedIssuer: testIssuer, ExpectedAudience: testIssuer,
		Algorithm: fapi.ES256, Now: h.now, MaxLifetime: 10 * time.Minute,
	})
	if err != nil {
		t.Fatalf("Validate access token: %v", err)
	}
	if validatedAT.JKT != dpopJWK.String() {
		t.Fatalf("access token JKT = %q, want %q", validatedAT.JKT, dpopJWK.String())
	}
	if validatedAT.Subject != testClientID.String() {
		t.Fatalf("access token Subject = %q, want the client's own ID %q", validatedAT.Subject, testClientID)
	}
	if validatedAT.ClientID != testClientID.String() {
		t.Fatalf("access token ClientID = %q, want %q", validatedAT.ClientID, testClientID)
	}
}

func TestRequestClientCredentialsTokenSuccessMTLS(t *testing.T) {
	h := newHarnessWithClientCredentialsGrant(t, storage.SenderConstrainMTLS, true)
	cert := selfSignedTestClientCert(t)

	result, err := h.server.RequestClientCredentialsToken(context.Background(), server.ClientCredentialsTokenRequest{
		HTTP:            server.FormRequest{Parameters: clientCredentialsFormParams(h.clientAssertion(t), "accounts")},
		PeerCertificate: cert,
	})
	if err != nil {
		t.Fatalf("RequestClientCredentialsToken: %v", err)
	}
	if result.TokenType != "Bearer" {
		t.Fatalf("TokenType = %q, want %q (RFC 8705 §3.4)", result.TokenType, "Bearer")
	}

	parsedAT, err := token.ParseAccessToken(result.AccessToken.Reveal())
	if err != nil {
		t.Fatalf("ParseAccessToken: %v", err)
	}
	validatedAT, err := parsedAT.Validate(&h.serverKey.PublicKey, token.AccessTokenValidatePolicy{
		ExpectedIssuer: testIssuer, ExpectedAudience: testIssuer,
		Algorithm: fapi.ES256, Now: h.now, MaxLifetime: 10 * time.Minute,
	})
	if err != nil {
		t.Fatalf("Validate access token: %v", err)
	}
	if validatedAT.X5TS256 != mtls.Thumbprint(cert) {
		t.Fatalf("access token X5TS256 = %q, want %q", validatedAT.X5TS256, mtls.Thumbprint(cert))
	}
	if validatedAT.JKT != "" {
		t.Fatalf("access token JKT = %q, want empty (mTLS-bound, not DPoP-bound)", validatedAT.JKT)
	}
}

func TestRequestClientCredentialsTokenRejectsWhenServerGrantDisabled(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true) // ClientCredentialsGrant left false

	_, err := h.server.RequestClientCredentialsToken(context.Background(), server.ClientCredentialsTokenRequest{
		HTTP:      server.FormRequest{Parameters: clientCredentialsFormParams(h.clientAssertion(t), "accounts")},
		DPoPProof: createDPoPProof(t, generateKey(t), h.now),
	})
	if err == nil {
		t.Fatalf("RequestClientCredentialsToken = nil error, want error")
	}
	if code := serverErrorCode(t, err); code != server.ErrorUnsupportedGrantType {
		t.Fatalf("error code = %q, want %q", code, server.ErrorUnsupportedGrantType)
	}
}

func TestRequestClientCredentialsTokenRejectsClientNotOptedIn(t *testing.T) {
	h := newHarnessWithClientCredentialsGrant(t, storage.SenderConstrainDPoP, false)

	_, err := h.server.RequestClientCredentialsToken(context.Background(), server.ClientCredentialsTokenRequest{
		HTTP:      server.FormRequest{Parameters: clientCredentialsFormParams(h.clientAssertion(t), "accounts")},
		DPoPProof: createDPoPProof(t, generateKey(t), h.now),
	})
	if err == nil {
		t.Fatalf("RequestClientCredentialsToken = nil error, want error")
	}
	if code := serverErrorCode(t, err); code != server.ErrorUnauthorizedClient {
		t.Fatalf("error code = %q, want %q", code, server.ErrorUnauthorizedClient)
	}
}

func TestRequestClientCredentialsTokenRejectsMissingScope(t *testing.T) {
	h := newHarnessWithClientCredentialsGrant(t, storage.SenderConstrainDPoP, true)

	_, err := h.server.RequestClientCredentialsToken(context.Background(), server.ClientCredentialsTokenRequest{
		HTTP:      server.FormRequest{Parameters: clientCredentialsFormParams(h.clientAssertion(t), "")},
		DPoPProof: createDPoPProof(t, generateKey(t), h.now),
	})
	if err == nil {
		t.Fatalf("RequestClientCredentialsToken = nil error, want error")
	}
	if code := serverErrorCode(t, err); code != server.ErrorInvalidScope {
		t.Fatalf("error code = %q, want %q", code, server.ErrorInvalidScope)
	}
}

func TestRequestClientCredentialsTokenRejectsDisallowedScope(t *testing.T) {
	h := newHarnessWithClientCredentialsGrant(t, storage.SenderConstrainDPoP, true)

	_, err := h.server.RequestClientCredentialsToken(context.Background(), server.ClientCredentialsTokenRequest{
		HTTP:      server.FormRequest{Parameters: clientCredentialsFormParams(h.clientAssertion(t), "openid")},
		DPoPProof: createDPoPProof(t, generateKey(t), h.now),
	})
	if err == nil {
		t.Fatalf("RequestClientCredentialsToken = nil error, want error")
	}
	if code := serverErrorCode(t, err); code != server.ErrorInvalidScope {
		t.Fatalf("error code = %q, want %q", code, server.ErrorInvalidScope)
	}
}

func TestRequestClientCredentialsTokenRejectsWrongGrantType(t *testing.T) {
	h := newHarnessWithClientCredentialsGrant(t, storage.SenderConstrainDPoP, true)
	params := clientCredentialsFormParams(h.clientAssertion(t), "accounts")
	for i := range params {
		if params[i].Name == "grant_type" {
			params[i].Value = "authorization_code"
		}
	}

	_, err := h.server.RequestClientCredentialsToken(context.Background(), server.ClientCredentialsTokenRequest{
		HTTP:      server.FormRequest{Parameters: params},
		DPoPProof: createDPoPProof(t, generateKey(t), h.now),
	})
	if err == nil {
		t.Fatalf("RequestClientCredentialsToken = nil error, want error")
	}
	if code := serverErrorCode(t, err); code != server.ErrorUnsupportedGrantType {
		t.Fatalf("error code = %q, want %q", code, server.ErrorUnsupportedGrantType)
	}
}

func TestRequestClientCredentialsTokenRequiresDPoP(t *testing.T) {
	h := newHarnessWithClientCredentialsGrant(t, storage.SenderConstrainDPoP, true)

	_, err := h.server.RequestClientCredentialsToken(context.Background(), server.ClientCredentialsTokenRequest{
		HTTP: server.FormRequest{Parameters: clientCredentialsFormParams(h.clientAssertion(t), "accounts")},
	})
	if err == nil {
		t.Fatalf("RequestClientCredentialsToken = nil error, want error")
	}
	if code := serverErrorCode(t, err); code != server.ErrorInvalidRequest {
		t.Fatalf("error code = %q, want %q", code, server.ErrorInvalidRequest)
	}
}

func TestRequestClientCredentialsTokenMTLSRequiresPeerCertificate(t *testing.T) {
	h := newHarnessWithClientCredentialsGrant(t, storage.SenderConstrainMTLS, true)

	_, err := h.server.RequestClientCredentialsToken(context.Background(), server.ClientCredentialsTokenRequest{
		HTTP: server.FormRequest{Parameters: clientCredentialsFormParams(h.clientAssertion(t), "accounts")},
	})
	if err == nil {
		t.Fatalf("RequestClientCredentialsToken = nil error, want error")
	}
	if code := serverErrorCode(t, err); code != server.ErrorInvalidRequest {
		t.Fatalf("error code = %q, want %q", code, server.ErrorInvalidRequest)
	}
}

func TestRequestClientCredentialsTokenRejectsDuplicatedParameter(t *testing.T) {
	h := newHarnessWithClientCredentialsGrant(t, storage.SenderConstrainDPoP, true)
	params := clientCredentialsFormParams(h.clientAssertion(t), "accounts")
	params = append(params, formParam("scope", "accounts")) // duplicate

	_, err := h.server.RequestClientCredentialsToken(context.Background(), server.ClientCredentialsTokenRequest{
		HTTP:      server.FormRequest{Parameters: params},
		DPoPProof: createDPoPProof(t, generateKey(t), h.now),
	})
	if err == nil {
		t.Fatalf("RequestClientCredentialsToken = nil error, want error")
	}
	if code := serverErrorCode(t, err); code != server.ErrorInvalidRequest {
		t.Fatalf("error code = %q, want %q", code, server.ErrorInvalidRequest)
	}
}

func TestRequestClientCredentialsTokenRejectsInvalidClientAssertion(t *testing.T) {
	h := newHarnessWithClientCredentialsGrant(t, storage.SenderConstrainDPoP, true)

	_, err := h.server.RequestClientCredentialsToken(context.Background(), server.ClientCredentialsTokenRequest{
		HTTP:      server.FormRequest{Parameters: clientCredentialsFormParams("not-a-valid-jwt", "accounts")},
		DPoPProof: createDPoPProof(t, generateKey(t), h.now),
	})
	if err == nil {
		t.Fatalf("RequestClientCredentialsToken = nil error, want error")
	}
	if code := serverErrorCode(t, err); code != server.ErrorInvalidClient {
		t.Fatalf("error code = %q, want %q", code, server.ErrorInvalidClient)
	}
}

func TestRequestClientCredentialsTokenAuditsOutcomes(t *testing.T) {
	h := newHarnessWithClientCredentialsGrant(t, storage.SenderConstrainDPoP, true)

	if _, err := h.server.RequestClientCredentialsToken(context.Background(), server.ClientCredentialsTokenRequest{
		HTTP:      server.FormRequest{Parameters: clientCredentialsFormParams(h.clientAssertion(t), "openid")},
		DPoPProof: createDPoPProof(t, generateKey(t), h.now),
	}); err == nil {
		t.Fatalf("expected disallowed-scope request to fail")
	}
	if _, err := h.server.RequestClientCredentialsToken(context.Background(), server.ClientCredentialsTokenRequest{
		HTTP:      server.FormRequest{Parameters: clientCredentialsFormParams(h.clientAssertion(t), "accounts")},
		DPoPProof: createDPoPProof(t, generateKey(t), h.now),
	}); err != nil {
		t.Fatalf("RequestClientCredentialsToken: %v", err)
	}

	if len(h.audit.events) != 2 {
		t.Fatalf("recorded %d audit events, want 2", len(h.audit.events))
	}
	if h.audit.events[0].Type != server.AuditEventRequestClientCredentialsToken || h.audit.events[0].Outcome != server.AuditOutcomeFailure {
		t.Fatalf("first event = %+v, want RequestClientCredentialsToken/Failure", h.audit.events[0])
	}
	if h.audit.events[1].Type != server.AuditEventRequestClientCredentialsToken || h.audit.events[1].Outcome != server.AuditOutcomeSuccess {
		t.Fatalf("second event = %+v, want RequestClientCredentialsToken/Success", h.audit.events[1])
	}
}
