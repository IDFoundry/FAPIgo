package server_test

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/extension"
	"github.com/idfoundry/fapigo/internal/clientassertion"
	"github.com/idfoundry/fapigo/internal/token"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
)

// fakeIdentityClaims is a minimal server.IdentityClaimsSource holding a
// fixed set of claims for one known subject and nothing for any other —
// and, per the IdentityClaimsSource contract, only ever returns the
// subset of its claims that names actually asked for.
type fakeIdentityClaims struct {
	subject string
	claims  map[string]json.RawMessage
}

func (f fakeIdentityClaims) ResolveIdentityClaims(_ context.Context, subject string, names []string) (map[string]json.RawMessage, error) {
	if subject != f.subject || len(names) == 0 {
		return nil, nil
	}
	out := make(map[string]json.RawMessage, len(names))
	for _, name := range names {
		if v, ok := f.claims[name]; ok {
			out[name] = v
		}
	}
	return out, nil
}

// completeAuthorizationWithClaims mirrors completeAuthorizationWithDPoPJKT
// but adds a "claims" (OIDC Core §5.5) authorization parameter, so tests
// can exercise which identity claims actually get requested for the
// id_token vs. userinfo delivery locations.
func completeAuthorizationWithClaims(t *testing.T, h harness, claims string) string {
	t.Helper()
	params := []server.FormParameter{
		formParam("client_assertion", h.clientAssertion(t)),
		formParam("client_assertion_type", clientassertion.AssertionType),
		formParam("response_type", "code"),
		formParam("redirect_uri", testRedirectURI),
		formParam("scope", "openid accounts"),
		formParam("code_challenge", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"),
		formParam("code_challenge_method", "S256"),
		formParam("state", "opaque-state"),
		formParam("claims", claims),
	}
	pushResult, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
		HTTP: server.FormRequest{Parameters: params},
	})
	if err != nil {
		t.Fatalf("PushAuthorizationRequest: %v", err)
	}
	action, err := h.server.BeginAuthorization(context.Background(), server.BeginAuthorizationRequest{
		RequestURI: pushResult.RequestURI.String(), ClientID: testClientID,
	})
	if err != nil {
		t.Fatalf("BeginAuthorization: %v", err)
	}
	required, ok := action.(server.InteractionRequired)
	if !ok {
		t.Fatalf("action = %T, want server.InteractionRequired", action)
	}

	subjectID, err := server.NewSubjectID("user-1")
	if err != nil {
		t.Fatalf("NewSubjectID: %v", err)
	}
	subject, err := server.NewAuthenticatedSubject(subjectID)
	if err != nil {
		t.Fatalf("NewAuthenticatedSubject: %v", err)
	}
	authCtx, err := server.NewAuthenticationContext(h.now, "urn:mace:incommon:iap:silver", []string{"pwd"})
	if err != nil {
		t.Fatalf("NewAuthenticationContext: %v", err)
	}
	result, err := h.server.CompleteAuthorization(context.Background(), server.CompleteAuthorizationRequest{
		Handle: required.Handle,
		Result: server.Authorize(subject, authCtx, server.GrantedAuthorization{Scope: []string{"openid", "accounts"}}),
	})
	if err != nil {
		t.Fatalf("CompleteAuthorization: %v", err)
	}
	redirect, ok := result.(server.AuthorizationRedirect)
	if !ok {
		t.Fatalf("result = %T, want server.AuthorizationRedirect", result)
	}
	dest := redirect.Destination().URL()
	code := dest.Query().Get("code")
	if code == "" {
		t.Fatalf("redirect missing code parameter: %q", dest.String())
	}
	return code
}

func newHarnessWithIdentityClaims(t *testing.T, identityClaims server.IdentityClaimsSource) harness {
	t.Helper()
	now := time.Now()
	key := generateKey(t)
	serverKey := generateKey(t)

	client, err := storage.NewRegisteredClient(storage.RegisteredClientConfig{
		ID:                       testClientID,
		RedirectURIs:             []fapi.RegisteredRedirectURI{testRedirectURI},
		ClientAssertionAlgorithm: fapi.ES256,
		AllowedScopes:            []string{"openid", "accounts", "offline_access"},
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
		Assurance: server.AssuranceDevelopment,
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
		Keys:           serverKeyManager,
		AccessTokens:   server.JWTAccessTokens{Keys: serverKeyManager, Algorithm: fapi.ES256},
		Revocation:     server.NoRevocation{},
		Clock:          fixedClock{now: now},
		Random:         rand.Reader,
		IdentityClaims: identityClaims,
	}
	srv, err := server.New(cfg, deps)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	return harness{server: srv, key: key, serverKey: serverKey, now: now}
}

// newHarnessWithIdentityClaimsAndExtensions is newHarnessWithIdentityClaims
// plus a registered extension.Registry, for tests exercising precedence
// between Dependencies.IdentityClaims and a ReturnInTokenClaims
// protocol-extension claim sharing the same wire name.
func newHarnessWithIdentityClaimsAndExtensions(t *testing.T, identityClaims server.IdentityClaimsSource, registry *extension.Registry) harness {
	t.Helper()
	now := time.Now()
	key := generateKey(t)
	serverKey := generateKey(t)

	client, err := storage.NewRegisteredClient(storage.RegisteredClientConfig{
		ID:                       testClientID,
		RedirectURIs:             []fapi.RegisteredRedirectURI{testRedirectURI},
		ClientAssertionAlgorithm: fapi.ES256,
		AllowedScopes:            []string{"openid", "accounts", "offline_access"},
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
		Assurance:  server.AssuranceDevelopment,
		Extensions: registry,
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
		Keys:           serverKeyManager,
		AccessTokens:   server.JWTAccessTokens{Keys: serverKeyManager, Algorithm: fapi.ES256},
		Revocation:     server.NoRevocation{},
		Clock:          fixedClock{now: now},
		Random:         rand.Reader,
		IdentityClaims: identityClaims,
	}
	srv, err := server.New(cfg, deps)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	return harness{server: srv, key: key, serverKey: serverKey, now: now}
}

// Change 2 regression: a server-authoritative identity claim must win
// over a client-registered protocol-extension claim of the same wire
// name — see withIdentityClaims's own doc comment. Before the fix, base
// (which carries the ReturnInTokenClaims extension claim) was merged
// last and so silently overrode the identity source's value; a
// deployment's own IdentityClaimsSource is meant to be authoritative,
// not something a client can shadow just by declaring an extension
// parameter with a matching name.
func TestExchangeAuthorizationCodeIdentityClaimWinsOverExtensionClaimCollision(t *testing.T) {
	emailExtensionDef := extension.Definition[string]{
		Name: "email", Cardinality: extension.Single,
		AllowedSources: extension.SourcePlainParameter, MaxBytes: 64,
		ReturnInTokenClaims: true,
	}
	registry, err := extension.NewRegistry(emailExtensionDef)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	identityClaims := fakeIdentityClaims{
		subject: "user-1",
		claims: map[string]json.RawMessage{
			"email": json.RawMessage(`"identity-source@example.com"`),
		},
	}
	h := newHarnessWithIdentityClaimsAndExtensions(t, identityClaims, registry)

	pushResult, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
		HTTP: server.FormRequest{Parameters: plainFormParameters(t, h.clientAssertion(t), map[string]string{
			"email":  "client-supplied@example.com",
			"claims": `{"id_token":{"email":null}}`,
		})},
	})
	if err != nil {
		t.Fatalf("PushAuthorizationRequest: %v", err)
	}
	action, err := h.server.BeginAuthorization(context.Background(), server.BeginAuthorizationRequest{
		RequestURI: pushResult.RequestURI.String(), ClientID: testClientID,
	})
	if err != nil {
		t.Fatalf("BeginAuthorization: %v", err)
	}
	interaction, ok := action.(server.InteractionRequired)
	if !ok {
		t.Fatalf("action = %T, want server.InteractionRequired", action)
	}

	subjectID, err := server.NewSubjectID("user-1")
	if err != nil {
		t.Fatalf("NewSubjectID: %v", err)
	}
	subject, err := server.NewAuthenticatedSubject(subjectID)
	if err != nil {
		t.Fatalf("NewAuthenticatedSubject: %v", err)
	}
	authCtx, err := server.NewAuthenticationContext(h.now, "urn:mace:incommon:iap:silver", []string{"pwd"})
	if err != nil {
		t.Fatalf("NewAuthenticationContext: %v", err)
	}
	result, err := h.server.CompleteAuthorization(context.Background(), server.CompleteAuthorizationRequest{
		Handle: interaction.Handle,
		Result: server.Authorize(subject, authCtx, server.GrantedAuthorization{Scope: []string{"openid", "accounts"}}),
	})
	if err != nil {
		t.Fatalf("CompleteAuthorization: %v", err)
	}
	redirect, ok := result.(server.AuthorizationRedirect)
	if !ok {
		t.Fatalf("result = %T, want server.AuthorizationRedirect", result)
	}
	dest := redirect.Destination().URL()
	code := dest.Query().Get("code")
	if code == "" {
		t.Fatalf("redirect missing code parameter")
	}

	exchangeResult, err := h.server.ExchangeAuthorizationCode(context.Background(), server.AuthorizationCodeExchangeRequest{
		HTTP:       server.FormRequest{Parameters: exchangeFormParams(h.clientAssertion(t), code, testRedirectURI, testCodeVerifier)},
		DPoPProofs: []string{createDPoPProof(t, generateKey(t), h.now)},
	})
	if err != nil {
		t.Fatalf("ExchangeAuthorizationCode: %v", err)
	}
	if !exchangeResult.HasIDToken {
		t.Fatalf("HasIDToken = false, want true")
	}

	parsed, err := token.ParseIDToken(exchangeResult.IDToken.Reveal())
	if err != nil {
		t.Fatalf("ParseIDToken: %v", err)
	}
	validated, err := parsed.Validate(&h.serverKey.PublicKey, token.IDTokenValidatePolicy{
		ExpectedIssuer:   testIssuer,
		ExpectedAudience: testClientID.String(),
		Algorithm:        fapi.ES256,
		Now:              h.now,
		MaxLifetime:      5 * time.Minute,
		MaxClockSkew:     5 * time.Second,
	})
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}

	email, err := jsonStringParam(validated.Parameters, "email")
	if err != nil {
		t.Fatalf("unmarshal email claim: %v", err)
	}
	if email != "identity-source@example.com" {
		t.Fatalf("id_token email claim = %q, want the identity source's value %q, not the client-supplied extension value", email, "identity-source@example.com")
	}
}

// FAPI2SPFinalTestClaimsParameterIdentityClaims in the OIDF conformance
// suite requires the AS to actually return values for claims it
// advertises in claims_supported, not just tolerate the "claims"
// request parameter. This exercises Dependencies.IdentityClaims end to
// end (authorize -> token) by decoding the issued ID token and
// confirming the resolved claims landed in it — and, just as
// importantly, that a claim the request didn't ask for ("email", here)
// does not: an IdentityClaimsSource may hold more than a given request
// asked for (fakeIdentityClaims does, deliberately, in this test), and
// returning it anyway would be a data-minimization violation.
func TestExchangeAuthorizationCodeEmbedsOnlyRequestedIdentityClaims(t *testing.T) {
	identityClaims := fakeIdentityClaims{
		subject: "user-1", // matches completeAuthorizationWithClaims's fixed subject
		claims: map[string]json.RawMessage{
			"name":  json.RawMessage(`"Conformance Test User"`),
			"email": json.RawMessage(`"conformance-test-user@example.com"`),
		},
	}
	h := newHarnessWithIdentityClaims(t, identityClaims)
	code := completeAuthorizationWithClaims(t, h, `{"id_token":{"name":null}}`)

	result, err := h.server.ExchangeAuthorizationCode(context.Background(), server.AuthorizationCodeExchangeRequest{
		HTTP:       server.FormRequest{Parameters: exchangeFormParams(h.clientAssertion(t), code, testRedirectURI, testCodeVerifier)},
		DPoPProofs: []string{createDPoPProof(t, generateKey(t), h.now)},
	})
	if err != nil {
		t.Fatalf("ExchangeAuthorizationCode: %v", err)
	}
	if !result.HasIDToken {
		t.Fatalf("HasIDToken = false, want true")
	}

	parsed, err := token.ParseIDToken(result.IDToken.Reveal())
	if err != nil {
		t.Fatalf("ParseIDToken: %v", err)
	}
	validated, err := parsed.Validate(&h.serverKey.PublicKey, token.IDTokenValidatePolicy{
		ExpectedIssuer:   testIssuer,
		ExpectedAudience: testClientID.String(),
		Algorithm:        fapi.ES256,
		Now:              h.now,
		MaxLifetime:      5 * time.Minute,
		MaxClockSkew:     5 * time.Second,
	})
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}

	name, err := jsonStringParam(validated.Parameters, "name")
	if err != nil || name != "Conformance Test User" {
		t.Fatalf("id_token name claim = %q, %v; want %q, nil", name, err, "Conformance Test User")
	}
	if _, present := validated.Parameters["email"]; present {
		t.Fatalf("id_token contains 'email', which was never requested via the claims parameter")
	}
}

// The core data-minimization guarantee: an authorization request that
// carries no "claims" parameter at all (the overwhelmingly common case
// — e.g. a plain happy-flow login) must get an ID token with zero
// identity claims, even though IdentityClaimsSource has values it could
// supply. Unconditionally embedding everything a deployment happens to
// know about a subject, regardless of whether it was asked for, is
// exactly the leak fapi2-security-profile-final-happy-flow's
// EnsureIdTokenDoesNotContainNonRequestedClaims warns about.
func TestExchangeAuthorizationCodeOmitsIdentityClaimsWithoutClaimsParameter(t *testing.T) {
	identityClaims := fakeIdentityClaims{
		subject: "user-1",
		claims: map[string]json.RawMessage{
			"name":  json.RawMessage(`"Conformance Test User"`),
			"email": json.RawMessage(`"conformance-test-user@example.com"`),
		},
	}
	h := newHarnessWithIdentityClaims(t, identityClaims)
	code := completeSuccessfulAuthorization(t, h, []string{"openid", "accounts"})

	result, err := h.server.ExchangeAuthorizationCode(context.Background(), server.AuthorizationCodeExchangeRequest{
		HTTP:       server.FormRequest{Parameters: exchangeFormParams(h.clientAssertion(t), code, testRedirectURI, testCodeVerifier)},
		DPoPProofs: []string{createDPoPProof(t, generateKey(t), h.now)},
	})
	if err != nil {
		t.Fatalf("ExchangeAuthorizationCode: %v", err)
	}
	if !result.HasIDToken {
		t.Fatalf("HasIDToken = false, want true")
	}

	parsed, err := token.ParseIDToken(result.IDToken.Reveal())
	if err != nil {
		t.Fatalf("ParseIDToken: %v", err)
	}
	validated, err := parsed.Validate(&h.serverKey.PublicKey, token.IDTokenValidatePolicy{
		ExpectedIssuer:   testIssuer,
		ExpectedAudience: testClientID.String(),
		Algorithm:        fapi.ES256,
		Now:              h.now,
		MaxLifetime:      5 * time.Minute,
		MaxClockSkew:     5 * time.Second,
	})
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	for _, name := range []string{"name", "email"} {
		if _, present := validated.Parameters[name]; present {
			t.Fatalf("id_token contains %q despite no claims parameter being sent", name)
		}
	}
}

// A "claims" parameter requesting a userinfo claim (not an id_token
// one) must not put that claim in the ID token at all — it belongs to
// UserInfo, a separate later call — but the access token must carry
// RequestedUserinfoClaimsKey so an embedder's own UserInfo endpoint
// knows what to return when that call arrives.
func TestExchangeAuthorizationCodeSplitsIDTokenAndUserinfoRequestedClaims(t *testing.T) {
	identityClaims := fakeIdentityClaims{
		subject: "user-1",
		claims: map[string]json.RawMessage{
			"name":  json.RawMessage(`"Conformance Test User"`),
			"email": json.RawMessage(`"conformance-test-user@example.com"`),
		},
	}
	h := newHarnessWithIdentityClaims(t, identityClaims)
	code := completeAuthorizationWithClaims(t, h, `{"userinfo":{"email":null}}`)

	result, err := h.server.ExchangeAuthorizationCode(context.Background(), server.AuthorizationCodeExchangeRequest{
		HTTP:       server.FormRequest{Parameters: exchangeFormParams(h.clientAssertion(t), code, testRedirectURI, testCodeVerifier)},
		DPoPProofs: []string{createDPoPProof(t, generateKey(t), h.now)},
	})
	if err != nil {
		t.Fatalf("ExchangeAuthorizationCode: %v", err)
	}

	parsedIDToken, err := token.ParseIDToken(result.IDToken.Reveal())
	if err != nil {
		t.Fatalf("ParseIDToken: %v", err)
	}
	validatedIDToken, err := parsedIDToken.Validate(&h.serverKey.PublicKey, token.IDTokenValidatePolicy{
		ExpectedIssuer: testIssuer, ExpectedAudience: testClientID.String(), Algorithm: fapi.ES256,
		Now: h.now, MaxLifetime: 5 * time.Minute, MaxClockSkew: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("Validate id_token: %v", err)
	}
	if _, present := validatedIDToken.Parameters["email"]; present {
		t.Fatalf("id_token contains 'email', which was only requested for userinfo delivery")
	}

	parsedAccessToken, err := token.ParseAccessToken(result.AccessToken.Reveal())
	if err != nil {
		t.Fatalf("ParseAccessToken: %v", err)
	}
	validatedAccessToken, err := parsedAccessToken.Validate(&h.serverKey.PublicKey, token.AccessTokenValidatePolicy{
		ExpectedIssuer: testIssuer, ExpectedAudience: testIssuer, Algorithm: fapi.ES256,
		Now: h.now, MaxLifetime: 5 * time.Minute,
	})
	if err != nil {
		t.Fatalf("Validate access_token: %v", err)
	}
	raw, ok := validatedAccessToken.Parameters[server.RequestedUserinfoClaimsKey]
	if !ok {
		t.Fatalf("access_token missing %q claim", server.RequestedUserinfoClaimsKey)
	}
	var names []string
	if err := json.Unmarshal(raw, &names); err != nil || len(names) != 1 || names[0] != "email" {
		t.Fatalf("access_token %q = %s, want [\"email\"]", server.RequestedUserinfoClaimsKey, raw)
	}
}

// A subject fakeIdentityClaims has no data for (a mismatched lookup)
// must not fail the exchange — resolving to nothing is a valid,
// non-error outcome (see IdentityClaimsSource's doc comment).
func TestExchangeAuthorizationCodeToleratesNoIdentityClaims(t *testing.T) {
	identityClaims := fakeIdentityClaims{subject: "someone-else"}
	h := newHarnessWithIdentityClaims(t, identityClaims)

	code := completeSuccessfulAuthorization(t, h, []string{"openid", "accounts"})
	result, err := h.server.ExchangeAuthorizationCode(context.Background(), server.AuthorizationCodeExchangeRequest{
		HTTP:       server.FormRequest{Parameters: exchangeFormParams(h.clientAssertion(t), code, testRedirectURI, testCodeVerifier)},
		DPoPProofs: []string{createDPoPProof(t, generateKey(t), h.now)},
	})
	if err != nil {
		t.Fatalf("ExchangeAuthorizationCode: %v", err)
	}
	if !result.HasIDToken {
		t.Fatalf("HasIDToken = false, want true")
	}
}

// OIDC Core §5.5's "claims" request parameter must not be rejected as
// an unregistered extension parameter — it's core, not a
// deployment-specific extension (see coreAuthorizationParameters).
func TestPushAuthorizationRequestAcceptsClaimsParameter(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, false)
	params := plainFormParameters(t, h.clientAssertion(t), map[string]string{
		"claims": `{"id_token":{"name":null},"userinfo":{"email":null}}`,
	})

	_, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
		HTTP: server.FormRequest{Parameters: params},
	})
	if err != nil {
		t.Fatalf("PushAuthorizationRequest: %v", err)
	}
}

func jsonStringParam(params map[string]json.RawMessage, name string) (string, error) {
	raw, ok := params[name]
	if !ok {
		return "", nil
	}
	var v string
	if err := json.Unmarshal(raw, &v); err != nil {
		return "", err
	}
	return v, nil
}
