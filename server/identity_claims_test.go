package server_test

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"strings"
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
// completeAuthorizationWithClaims completes an authorization whose
// request carries claims, approving every requested identity claim.
func completeAuthorizationWithClaims(t *testing.T, h harness, claims string) string {
	t.Helper()
	result, _ := completeAuthorizationApproving(t, h, claims, server.RequestedClaims.Names)
	redirect, ok := result.(server.AuthorizationRedirect)
	if !ok {
		t.Fatalf("result = %T, want server.AuthorizationRedirect", result)
	}
	dest := redirect.Destination().URL()
	code := dest.Query().Get("code")
	if code == "" {
		t.Fatalf("redirect carries no code")
	}
	return code
}

// completeAuthorizationApproving completes an authorization whose
// request carries claims, approving whatever approve picks from the
// interaction's RequestedClaims, and returns the result along with the
// RequestedClaims the interaction showed.
func completeAuthorizationApproving(t *testing.T, h harness, claims string, approve func(server.RequestedClaims) []string) (server.AuthorizationResult, server.RequestedClaims) {
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
		Result: server.Authorize(subject, authCtx, server.GrantedAuthorization{
			Scope:                  []string{"openid", "accounts"},
			ApprovedIdentityClaims: approve(required.Interaction.RequestedClaims),
		}),
	})
	if err != nil {
		t.Fatalf("CompleteAuthorization: %v", err)
	}
	return result, required.Interaction.RequestedClaims
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
			MaxIDTokenClaimsBytes:      4096,
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
		Keys:                   serverKeyManager,
		AccessTokens:           server.JWTAccessTokens{Keys: serverKeyManager, Algorithm: fapi.ES256},
		Revocation:             server.NoRevocation{},
		ClientCertificateTrust: server.NoClientCertificateChainTrust{},
		Clock:                  fixedClock{now: now},
		Random:                 rand.Reader,
		IdentityClaims:         identityClaims,
	}
	srv, err := server.New(cfg, deps)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	return harness{server: srv, key: key, serverKey: serverKey, now: now}
}

// TestNewRejectsExtensionClaimShadowingManagedClaim checks that an
// extension can't copy a client-supplied value into tokens under a name
// the server or the resource owner supplies — an identity claim such as
// "email", or a claim the server sets itself.
func TestNewRejectsExtensionClaimShadowingManagedClaim(t *testing.T) {
	for _, name := range []string{"email", "acr", "requested_userinfo_claims"} {
		t.Run(name, func(t *testing.T) {
			registry, err := extension.NewRegistry(extension.Definition[string]{
				Name: name, Cardinality: extension.Single,
				AllowedSources: extension.SourcePlainParameter, MaxBytes: 64,
				ReturnInTokenClaims: true,
			})
			if err != nil {
				t.Fatalf("NewRegistry: %v", err)
			}
			cfg := validConfig(t)
			cfg.Extensions = registry
			if _, err := server.New(cfg, validDependencies()); err == nil || !strings.Contains(err.Error(), "ReturnInTokenClaims") {
				t.Fatalf("New(extension %q returned in token claims) = %v, want rejection", name, err)
			}
		})
	}

	// The same name without ReturnInTokenClaims never reaches a token,
	// so it's fine.
	registry, err := extension.NewRegistry(extension.Definition[string]{
		Name: "email", Cardinality: extension.Single,
		AllowedSources: extension.SourcePlainParameter, MaxBytes: 64,
	})
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	cfg := validConfig(t)
	cfg.Extensions = registry
	if _, err := server.New(cfg, validDependencies()); err != nil {
		t.Fatalf("New(extension not returned in token claims): %v", err)
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
		AccessToken:      result.AccessToken.Reveal(),
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
		AccessToken:      result.AccessToken.Reveal(),
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
		AccessToken: result.AccessToken.Reveal(),
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

// TestIdentityClaimsRequireApproval checks that a claim the client
// requested with the "claims" parameter is released only once the
// application approves it, that approval can be partial, that the
// interaction shows what was requested, and that approving a claim the
// client never requested is rejected.
func TestIdentityClaimsRequireApproval(t *testing.T) {
	identityClaims := fakeIdentityClaims{
		subject: "user-1",
		claims: map[string]json.RawMessage{
			"name":         json.RawMessage(`"Test User"`),
			"email":        json.RawMessage(`"user@example.com"`),
			"phone_number": json.RawMessage(`"+15555550100"`),
		},
	}
	request := `{"id_token":{"name":null,"email":null},"userinfo":{"phone_number":null}}`

	idTokenClaimsFor := func(t *testing.T, approve func(server.RequestedClaims) []string) (idToken, accessToken map[string]json.RawMessage) {
		t.Helper()
		h := newHarnessWithIdentityClaims(t, identityClaims)
		result, requested := completeAuthorizationApproving(t, h, request, approve)
		if got := requested.IDToken; len(got) != 2 || got[0] != "email" || got[1] != "name" {
			t.Fatalf("RequestedClaims.IDToken = %v, want [email name]", got)
		}
		if got := requested.UserInfo; len(got) != 1 || got[0] != "phone_number" {
			t.Fatalf("RequestedClaims.UserInfo = %v, want [phone_number]", got)
		}
		redirect, ok := result.(server.AuthorizationRedirect)
		if !ok {
			t.Fatalf("result = %T, want server.AuthorizationRedirect", result)
		}
		dest := redirect.Destination().URL()
		exchanged, err := h.server.ExchangeAuthorizationCode(context.Background(), server.AuthorizationCodeExchangeRequest{
			HTTP:       server.FormRequest{Parameters: exchangeFormParams(h.clientAssertion(t), dest.Query().Get("code"), testRedirectURI, testCodeVerifier)},
			DPoPProofs: []string{createDPoPProof(t, generateKey(t), h.now)},
		})
		if err != nil {
			t.Fatalf("ExchangeAuthorizationCode: %v", err)
		}
		parsed, err := token.ParseIDToken(exchanged.IDToken.Reveal())
		if err != nil {
			t.Fatalf("ParseIDToken: %v", err)
		}
		validated, err := parsed.Validate(&h.serverKey.PublicKey, token.IDTokenValidatePolicy{
			ExpectedIssuer: testIssuer, ExpectedAudience: testClientID.String(), Algorithm: fapi.ES256,
			Now: h.now, MaxLifetime: 5 * time.Minute, MaxClockSkew: 5 * time.Second,
			AccessToken: exchanged.AccessToken.Reveal(),
		})
		if err != nil {
			t.Fatalf("Validate: %v", err)
		}
		parsedAccessToken, err := token.ParseAccessToken(exchanged.AccessToken.Reveal())
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
		return validated.Parameters, validatedAccessToken.Parameters
	}

	none, noneAccess := idTokenClaimsFor(t, func(server.RequestedClaims) []string { return nil })
	if raw, ok := noneAccess[server.RequestedUserinfoClaimsKey]; ok {
		t.Errorf("access token carries %s = %s with nothing approved", server.RequestedUserinfoClaimsKey, raw)
	}
	if _, ok := none["name"]; ok {
		t.Error("unapproved name was released")
	}
	if _, ok := none["email"]; ok {
		t.Error("unapproved email was released")
	}

	partial, partialAccess := idTokenClaimsFor(t, func(server.RequestedClaims) []string { return []string{"email", "phone_number"} })
	if raw := string(partialAccess[server.RequestedUserinfoClaimsKey]); raw != `["phone_number"]` {
		t.Errorf("access token %s = %s, want [\"phone_number\"]", server.RequestedUserinfoClaimsKey, raw)
	}
	if _, ok := partial["email"]; !ok {
		t.Error("approved email was not released")
	}
	if _, ok := partial["name"]; ok {
		t.Error("unapproved name was released alongside approved email")
	}

	h := newHarnessWithIdentityClaims(t, identityClaims)
	result, _ := completeAuthorizationApproving(t, h, request, func(server.RequestedClaims) []string {
		return []string{"email", "address"}
	})
	if _, ok := result.(server.AuthorizationLocalError); !ok {
		t.Fatalf("result = %T, want server.AuthorizationLocalError for approving an unrequested claim", result)
	}
}

// TestCIBAIdentityClaimsRequireApproval checks the backchannel flow's
// counterpart of TestIdentityClaimsRequireApproval: the interaction
// shows the requested claims, and approving an unrequested one fails.
func TestCIBAIdentityClaimsRequireApproval(t *testing.T) {
	authorize := func(t *testing.T, h harness, approved []string) server.InteractionResult {
		t.Helper()
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
		return server.Authorize(subject, authCtx, server.GrantedAuthorization{
			Scope: []string{"openid", "accounts"}, ApprovedIdentityClaims: approved,
		})
	}
	params := func(t *testing.T) map[string]json.RawMessage {
		p := standardBackchannelParams(t)
		p["claims"] = json.RawMessage(`{"id_token":{"email":null}}`)
		return p
	}

	h, _ := newHarnessWithBackchannel(t)
	required := beginBackchannel(t, h, params(t))
	if got := required.Interaction.RequestedClaims.IDToken; len(got) != 1 || got[0] != "email" {
		t.Fatalf("RequestedClaims.IDToken = %v, want [email]", got)
	}
	if err := h.server.CompleteBackchannelAuthentication(context.Background(), server.CompleteBackchannelAuthenticationRequest{
		Handle: required.Handle, Result: authorize(t, h, []string{"phone_number"}),
	}); err == nil {
		t.Fatal("CompleteBackchannelAuthentication(unrequested claim approved) = nil error, want error")
	}

	required = beginBackchannel(t, h, params(t))
	if err := h.server.CompleteBackchannelAuthentication(context.Background(), server.CompleteBackchannelAuthenticationRequest{
		Handle: required.Handle, Result: authorize(t, h, []string{"email"}),
	}); err != nil {
		t.Fatalf("CompleteBackchannelAuthentication(requested claim approved): %v", err)
	}
}
