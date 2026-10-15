package server_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/clientassertion"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/resource"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
	"github.com/idfoundry/fapigo/storage/memstore"
)

const (
	resourceA = "https://issuer-a.example.com"
	resourceB = "https://issuer-b.example.com/tenant"
	resourceC = "https://issuer-c.example.com"
)

// recordingResourcePolicy is a server.ResourcePolicy that records what
// it was asked and answers with err.
type recordingResourcePolicy struct {
	asked [][]string
	err   error
}

func (p *recordingResourcePolicy) AllowResources(_ context.Context, _ storage.RegisteredClient, resources []string) error {
	p.asked = append(p.asked, resources)
	return p.err
}

// withResources rebuilds h's server with Config.Resources and
// Dependencies.ResourcePolicy set, over the same stores.
func withResources(t *testing.T, h harness, resources []string, policy server.ResourcePolicy) harness {
	t.Helper()
	cfg, deps := h.cfg, h.deps
	cfg.Resources = resources
	deps.ResourcePolicy = policy
	srv, err := server.New(cfg, deps)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	h.server, h.cfg, h.deps = srv, cfg, deps
	return h
}

// restrictClientResources re-registers testClientID with AllowedResources.
func restrictClientResources(t *testing.T, h harness, allowed ...string) {
	t.Helper()
	client, err := storage.NewRegisteredClient(storage.RegisteredClientConfig{
		ID:                       testClientID,
		RedirectURIs:             []fapi.RegisteredRedirectURI{testRedirectURI},
		ClientAssertionAlgorithm: fapi.ES256,
		RequestObjectAlgorithm:   fapi.ES256,
		AllowedScopes:            []string{"openid", "accounts", "offline_access"},
		AllowedResources:         allowed,
	})
	if err != nil {
		t.Fatalf("NewRegisteredClient: %v", err)
	}
	h.clients.clients[testClientID] = client
}

// pushWithResources pushes a plain authorization request for "openid
// accounts offline_access" naming resources.
func pushWithResources(t *testing.T, h harness, resources ...string) (server.PushAuthorizationResult, error) {
	t.Helper()
	params := []server.FormParameter{
		formParam("client_assertion", h.clientAssertion(t)),
		formParam("client_assertion_type", clientassertion.AssertionType),
		formParam("response_type", "code"),
		formParam("redirect_uri", testRedirectURI),
		formParam("scope", "openid accounts offline_access"),
		formParam("code_challenge", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"),
		formParam("code_challenge_method", "S256"),
	}
	for _, r := range resources {
		params = append(params, formParam("resource", r))
	}
	return h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
		HTTP: server.FormRequest{Parameters: params},
	})
}

// codeForPushed begins and approves a pushed request, granting "openid
// accounts offline_access", and returns the authorization code.
func codeForPushed(t *testing.T, h harness, pushed server.PushAuthorizationResult) string {
	t.Helper()
	action, err := h.server.BeginAuthorization(context.Background(), server.BeginAuthorizationRequest{
		RequestURI: pushed.RequestURI.String(), ClientID: testClientID,
	})
	if err != nil {
		t.Fatalf("BeginAuthorization: %v", err)
	}
	required, ok := action.(server.InteractionRequired)
	if !ok {
		t.Fatalf("action = %T, want server.InteractionRequired", action)
	}
	subjectID, _ := server.NewSubjectID("user-1")
	subject, _ := server.NewAuthenticatedSubject(subjectID)
	authCtx, err := server.NewAuthenticationContext(h.now, "", []string{"pwd"})
	if err != nil {
		t.Fatalf("NewAuthenticationContext: %v", err)
	}
	result, err := h.server.CompleteAuthorization(context.Background(), server.CompleteAuthorizationRequest{
		Handle: required.Handle,
		Result: server.Authorize(subject, authCtx, server.GrantedAuthorization{Scope: []string{"openid", "accounts", "offline_access"}}),
	})
	if err != nil {
		t.Fatalf("CompleteAuthorization: %v", err)
	}
	redirect, ok := result.(server.AuthorizationRedirect)
	if !ok {
		t.Fatalf("result = %T, want server.AuthorizationRedirect", result)
	}
	dest := redirect.Destination().URL()
	return dest.Query().Get("code")
}

// grantForResources pushes and approves a request naming resources, and
// returns its code.
func grantForResources(t *testing.T, h harness, resources ...string) string {
	t.Helper()
	pushed, err := pushWithResources(t, h, resources...)
	if err != nil {
		t.Fatalf("PushAuthorizationRequest: %v", err)
	}
	return codeForPushed(t, h, pushed)
}

// exchangeWithResources redeems code, naming resources at the token
// endpoint.
func exchangeWithResources(t *testing.T, h harness, code string, resources ...string) (server.TokenResult, error) {
	t.Helper()
	params := exchangeFormParams(h.clientAssertion(t), code, testRedirectURI, testCodeVerifier)
	for _, r := range resources {
		params = append(params, formParam("resource", r))
	}
	return h.server.ExchangeAuthorizationCode(context.Background(), server.AuthorizationCodeExchangeRequest{
		HTTP:       server.FormRequest{Parameters: params},
		DPoPProofs: []string{createDPoPProof(t, generateKey(t), h.now)},
	})
}

// refreshWithResources redeems refreshToken, naming resources.
func refreshWithResources(t *testing.T, h harness, refreshToken string, resources ...string) (server.TokenResult, error) {
	t.Helper()
	params := refreshFormParams(h.clientAssertion(t), refreshToken, "")
	for _, r := range resources {
		params = append(params, formParam("resource", r))
	}
	return h.server.RefreshAccessToken(context.Background(), server.RefreshTokenRequest{
		HTTP:       server.FormRequest{Parameters: params},
		DPoPProofs: []string{createDPoPProof(t, generateKey(t), h.now)},
	})
}

// rawAudience returns a JWT access token's "aud" exactly as encoded: a
// string or an array.
func rawAudience(t *testing.T, accessToken fapi.Secret) any {
	t.Helper()
	parts := strings.Split(accessToken.Reveal(), ".")
	if len(parts) != 3 {
		t.Fatalf("access token is not a JWS: %d parts", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var claims struct {
		Aud any `json:"aud"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	return claims.Aud
}

func wantAudience(t *testing.T, result server.TokenResult, want any) {
	t.Helper()
	got := rawAudience(t, result.AccessToken)
	if fmt.Sprint(got) != fmt.Sprint(want) || reflect.TypeOf(got) != reflect.TypeOf(want) {
		t.Fatalf("aud = %#v, want %#v", got, want)
	}
}

func wantErrorCode(t *testing.T, err error, want server.ErrorCode) {
	t.Helper()
	var serr *server.Error
	if !errors.As(err, &serr) {
		t.Fatalf("err = %v, want a *server.Error %q", err, want)
	}
	if serr.Code() != want {
		t.Fatalf("code = %q (%v), want %q", serr.Code(), err, want)
	}
}

func TestResourceIndicatorsIgnoredWhenNothingConfigured(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	code := grantForResources(t, h, resourceA)
	result, err := exchangeWithResources(t, h, code, resourceA)
	if err != nil {
		t.Fatalf("ExchangeAuthorizationCode: %v", err)
	}
	wantAudience(t, result, testIssuer)

	// "resource" stays an ordinary parameter: not repeatable.
	_, err = pushWithResources(t, h, resourceA, resourceB)
	wantErrorCode(t, err, server.ErrorInvalidRequest)
}

func TestResourceIndicatorsPARValidation(t *testing.T) {
	for name, tc := range map[string]struct {
		resources []string
		want      server.ErrorCode
	}{
		"one listed":         {resources: []string{resourceA}},
		"two listed":         {resources: []string{resourceA, resourceB}},
		"repeated":           {resources: []string{resourceA, resourceA}},
		"unlisted":           {resources: []string{resourceA, resourceC}, want: server.ErrorInvalidTarget},
		"relative":           {resources: []string{"/api"}, want: server.ErrorInvalidTarget},
		"fragment":           {resources: []string{resourceA + "#x"}, want: server.ErrorInvalidTarget},
		"empty":              {resources: []string{""}, want: server.ErrorInvalidTarget},
		"too many":           {resources: manyResources(17), want: server.ErrorInvalidTarget},
		"listed with prefix": {resources: []string{resourceA + "/"}, want: server.ErrorInvalidTarget},
	} {
		t.Run(name, func(t *testing.T) {
			h := withResources(t, newHarness(t, server.ProfileFAPISecurity, true), []string{resourceA, resourceB}, nil)
			_, err := pushWithResources(t, h, tc.resources...)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("PushAuthorizationRequest: %v", err)
				}
				return
			}
			wantErrorCode(t, err, tc.want)
		})
	}
}

func repeated(resource string, n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = resource
	}
	return out
}

func manyResources(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("https://rs%d.example.com", i)
	}
	return out
}

func TestResourceIndicatorsCodeExchangeAudience(t *testing.T) {
	h := withResources(t, newHarness(t, server.ProfileFAPISecurity, true), []string{resourceA, resourceB}, nil)
	for name, tc := range map[string]struct {
		granted, requested []string
		want               any
		wantErr            server.ErrorCode
	}{
		"none requested":        {want: testIssuer},
		"one granted":           {granted: []string{resourceA}, want: resourceA},
		"both granted":          {granted: []string{resourceA, resourceB}, want: []any{resourceA, resourceB}},
		"narrowed":              {granted: []string{resourceA, resourceB}, requested: []string{resourceB}, want: resourceB},
		"narrowed repeated":     {granted: []string{resourceA, resourceB}, requested: []string{resourceB, resourceB}, want: resourceB},
		"widened":               {granted: []string{resourceA}, requested: []string{resourceB}, wantErr: server.ErrorInvalidTarget},
		"named when none":       {requested: []string{resourceA}, wantErr: server.ErrorInvalidTarget},
		"narrowed to too many":  {granted: []string{resourceA}, requested: manyResources(17), wantErr: server.ErrorInvalidTarget},
		"granted, too often":    {granted: []string{resourceA}, requested: repeated(resourceA, 17), wantErr: server.ErrorInvalidTarget},
		"same as granted twice": {granted: []string{resourceA, resourceB}, requested: []string{resourceA, resourceB}, want: []any{resourceA, resourceB}},
	} {
		t.Run(name, func(t *testing.T) {
			code := grantForResources(t, h, tc.granted...)
			result, err := exchangeWithResources(t, h, code, tc.requested...)
			if tc.wantErr != "" {
				wantErrorCode(t, err, tc.wantErr)
				return
			}
			if err != nil {
				t.Fatalf("ExchangeAuthorizationCode: %v", err)
			}
			wantAudience(t, result, tc.want)
		})
	}
}

func TestResourceIndicatorsRefreshKeepsGrantResources(t *testing.T) {
	h := withResources(t, newHarness(t, server.ProfileFAPISecurity, true), []string{resourceA, resourceB}, nil)
	code := grantForResources(t, h, resourceA, resourceB)
	first, err := exchangeWithResources(t, h, code, resourceA)
	if err != nil {
		t.Fatalf("ExchangeAuthorizationCode: %v", err)
	}
	wantAudience(t, first, resourceA)
	refreshToken := first.RefreshToken.Reveal()

	// Narrowing the first access token didn't narrow the grant.
	refreshed, err := refreshWithResources(t, h, refreshToken)
	if err != nil {
		t.Fatalf("RefreshAccessToken: %v", err)
	}
	wantAudience(t, refreshed, []any{resourceA, resourceB})

	narrowed, err := refreshWithResources(t, h, refreshToken, resourceB)
	if err != nil {
		t.Fatalf("RefreshAccessToken narrowed: %v", err)
	}
	wantAudience(t, narrowed, resourceB)

	_, err = refreshWithResources(t, h, refreshToken, resourceC)
	wantErrorCode(t, err, server.ErrorInvalidTarget)

	again, err := refreshWithResources(t, h, refreshToken)
	if err != nil {
		t.Fatalf("RefreshAccessToken after narrowing: %v", err)
	}
	wantAudience(t, again, []any{resourceA, resourceB})
}

func TestResourceIndicatorsRequestObject(t *testing.T) {
	h := withResources(t, newHarness(t, server.ProfileFAPISecurity, true), []string{resourceA, resourceB}, nil)
	push := func(t *testing.T, resource any, outer ...string) (server.PushAuthorizationResult, error) {
		t.Helper()
		params := standardAuthParams(t)
		params["scope"] = jsonRaw(t, "openid accounts offline_access")
		if resource != nil {
			params["resource"] = jsonRaw(t, resource)
		}
		form := []server.FormParameter{
			formParam("client_assertion", h.clientAssertion(t)),
			formParam("client_assertion_type", clientassertion.AssertionType),
			formParam("request", h.requestObject(t, params)),
		}
		for _, r := range outer {
			form = append(form, formParam("resource", r))
		}
		return h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{HTTP: server.FormRequest{Parameters: form}})
	}
	for name, tc := range map[string]struct {
		resource any
		outer    []string
		want     any
		wantErr  server.ErrorCode
	}{
		"string":           {resource: resourceA, want: resourceA},
		"array":            {resource: []string{resourceA, resourceB}, want: []any{resourceA, resourceB}},
		"absent":           {want: testIssuer},
		"outside ignored":  {outer: []string{resourceA}, want: testIssuer},
		"inside wins":      {resource: resourceB, outer: []string{resourceA}, want: resourceB},
		"number":           {resource: 7, wantErr: server.ErrorInvalidTarget},
		"empty array":      {resource: []string{}, wantErr: server.ErrorInvalidTarget},
		"unlisted":         {resource: resourceC, wantErr: server.ErrorInvalidTarget},
		"array with frag":  {resource: []string{resourceA, resourceB + "#f"}, wantErr: server.ErrorInvalidTarget},
		"array of numbers": {resource: []int{1}, wantErr: server.ErrorInvalidTarget},
	} {
		t.Run(name, func(t *testing.T) {
			pushed, err := push(t, tc.resource, tc.outer...)
			if tc.wantErr != "" {
				wantErrorCode(t, err, tc.wantErr)
				return
			}
			if err != nil {
				t.Fatalf("PushAuthorizationRequest: %v", err)
			}
			result, err := exchangeWithResources(t, h, codeForPushed(t, h, pushed))
			if err != nil {
				t.Fatalf("ExchangeAuthorizationCode: %v", err)
			}
			wantAudience(t, result, tc.want)
		})
	}
}

func TestResourceIndicatorsRequestObjectResourceNotStoredWhenDisabled(t *testing.T) {
	// With nothing configured, a request object's "resource" is dropped
	// as an unregistered parameter, as before.
	h := newHarness(t, server.ProfileFAPISecurity, true)
	params := standardAuthParams(t)
	params["resource"] = jsonRaw(t, 7)
	_, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{HTTP: server.FormRequest{Parameters: []server.FormParameter{
		formParam("client_assertion", h.clientAssertion(t)),
		formParam("client_assertion_type", clientassertion.AssertionType),
		formParam("request", h.requestObject(t, params)),
	}}})
	if err != nil {
		t.Fatalf("PushAuthorizationRequest: %v", err)
	}
	if _, ok := storedParameters(t, h.transactions.records[len(h.transactions.records)-1])["resource"]; ok {
		t.Fatal("resource stored, want it dropped")
	}
}

func TestResourceIndicatorsStoredOnlyAsResources(t *testing.T) {
	h := withResources(t, newHarness(t, server.ProfileFAPISecurity, true), []string{resourceA}, nil)
	params := standardAuthParams(t)
	params["resource"] = jsonRaw(t, []string{resourceA})
	if _, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{HTTP: server.FormRequest{Parameters: []server.FormParameter{
		formParam("client_assertion", h.clientAssertion(t)),
		formParam("client_assertion_type", clientassertion.AssertionType),
		formParam("request", h.requestObject(t, params)),
	}}}); err != nil {
		t.Fatalf("PushAuthorizationRequest: %v", err)
	}
	if _, ok := storedParameters(t, h.transactions.records[len(h.transactions.records)-1])["resource"]; ok {
		t.Fatal("resource stored among the parameters")
	}
}

func TestResourceIndicatorsClientAllowedResources(t *testing.T) {
	policy := &recordingResourcePolicy{}
	h := withResources(t, newHarness(t, server.ProfileFAPISecurity, true), []string{resourceA, resourceB}, policy)
	restrictClientResources(t, h, resourceA, resourceC)

	if _, err := pushWithResources(t, h, resourceA); err != nil {
		t.Fatalf("PushAuthorizationRequest for an allowed resource: %v", err)
	}
	// Listed server-wide, but not for this client.
	_, err := pushWithResources(t, h, resourceB)
	wantErrorCode(t, err, server.ErrorInvalidTarget)
	// The client's list never widens what the server accepts: resourceC
	// still needs the policy, and isn't asked about before the client's
	// own list passes.
	policy.err = fmt.Errorf("unknown issuer: %w", server.ErrResourceNotAllowed)
	_, err = pushWithResources(t, h, resourceC)
	wantErrorCode(t, err, server.ErrorInvalidTarget)
	if want := [][]string{{resourceC}}; !reflect.DeepEqual(policy.asked, want) {
		t.Fatalf("policy asked %v, want %v", policy.asked, want)
	}
}

func TestResourceIndicatorsPolicyPrecedence(t *testing.T) {
	for name, tc := range map[string]struct {
		listed    []string
		policyErr error
		requested []string
		wantAsked [][]string
		want      server.ErrorCode
	}{
		"listed only, not asked":     {listed: []string{resourceA}, requested: []string{resourceA}},
		"unlisted asked":             {listed: []string{resourceA}, requested: []string{resourceA, resourceC}, wantAsked: [][]string{{resourceC}}},
		"policy only":                {requested: []string{resourceB, resourceC}, wantAsked: [][]string{{resourceB, resourceC}}},
		"policy refuses":             {listed: []string{resourceA}, policyErr: fmt.Errorf("no: %w", server.ErrResourceNotAllowed), requested: []string{resourceC}, wantAsked: [][]string{{resourceC}}, want: server.ErrorInvalidTarget},
		"policy fails":               {listed: []string{resourceA}, policyErr: errors.New("metadata fetch failed"), requested: []string{resourceC}, wantAsked: [][]string{{resourceC}}, want: server.ErrorServerError},
		"policy fails, listed only":  {listed: []string{resourceA}, policyErr: errors.New("metadata fetch failed"), requested: []string{resourceA}},
		"malformed, policy not used": {requested: []string{"not a uri"}, want: server.ErrorInvalidTarget},
		"too many, policy not used":  {requested: manyResources(17), want: server.ErrorInvalidTarget},
	} {
		t.Run(name, func(t *testing.T) {
			policy := &recordingResourcePolicy{err: tc.policyErr}
			h := withResources(t, newHarness(t, server.ProfileFAPISecurity, true), tc.listed, policy)
			_, err := pushWithResources(t, h, tc.requested...)
			if tc.want == "" && err != nil {
				t.Fatalf("PushAuthorizationRequest: %v", err)
			}
			if tc.want != "" {
				wantErrorCode(t, err, tc.want)
			}
			if !reflect.DeepEqual(policy.asked, tc.wantAsked) {
				t.Fatalf("policy asked %v, want %v", policy.asked, tc.wantAsked)
			}
		})
	}
}

func TestResourceIndicatorsPolicyOnlyEnables(t *testing.T) {
	h := withResources(t, newHarness(t, server.ProfileFAPISecurity, true), nil, &recordingResourcePolicy{})
	code := grantForResources(t, h, resourceA, resourceB)
	result, err := exchangeWithResources(t, h, code, resourceA, resourceA)
	if err != nil {
		t.Fatalf("ExchangeAuthorizationCode: %v", err)
	}
	wantAudience(t, result, resourceA)
}

func TestNewRejectsInvalidResources(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	for name, resources := range map[string][]string{
		"relative": {"/api"},
		"fragment": {resourceA + "#x"},
		"empty":    {""},
		"repeated": {resourceA, resourceB, resourceA},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := h.cfg
			cfg.Resources = resources
			if _, err := server.New(cfg, h.deps); err == nil {
				t.Fatal("New accepted invalid Config.Resources")
			}
		})
	}
}

func TestNewCopiesResources(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	cfg := h.cfg
	cfg.Resources = []string{resourceA}
	srv, err := server.New(cfg, h.deps)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	cfg.Resources[0] = resourceB
	h.server = srv
	code := grantForResources(t, h, resourceA)
	result, err := exchangeWithResources(t, h, code)
	if err != nil {
		t.Fatalf("ExchangeAuthorizationCode: %v", err)
	}
	wantAudience(t, result, resourceA)
}

func TestResourceIndicatorsCIBA(t *testing.T) {
	for name, tc := range map[string]struct {
		resource  any
		requested []string
		want      any
		wantBegin server.ErrorCode
		wantToken server.ErrorCode
	}{
		"none":      {want: testIssuer},
		"string":    {resource: resourceA, want: resourceA},
		"array":     {resource: []string{resourceA, resourceB}, want: []any{resourceA, resourceB}},
		"narrowed":  {resource: []string{resourceA, resourceB}, requested: []string{resourceA}, want: resourceA},
		"widened":   {resource: resourceA, requested: []string{resourceB}, wantToken: server.ErrorInvalidTarget},
		"unlisted":  {resource: resourceC, wantBegin: server.ErrorInvalidTarget},
		"malformed": {resource: "relative", wantBegin: server.ErrorInvalidTarget},
		"number":    {resource: 1, wantBegin: server.ErrorInvalidTarget},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarnessWithBackchannelConfig(t, memstore.NewBackchannelAuthenticationStore(), func(cfg *server.Config) {
				cfg.Resources = []string{resourceA, resourceB}
			})
			params := standardBackchannelParams(t)
			if tc.resource != nil {
				params["resource"] = jsonRaw(t, tc.resource)
			}
			action, err := h.server.BeginBackchannelAuthentication(context.Background(), server.BeginBackchannelAuthenticationRequest{
				HTTP: server.FormRequest{Parameters: backchannelFormParams(h.clientAssertion(t), h.backchannelRequestObject(t, params))},
			})
			if err != nil {
				t.Fatalf("BeginBackchannelAuthentication: %v", err)
			}
			if tc.wantBegin != "" {
				local, ok := action.(server.BackchannelAuthenticationLocalError)
				if !ok || local.Error.Code() != tc.wantBegin {
					t.Fatalf("action = %#v, want a local %q error", action, tc.wantBegin)
				}
				return
			}
			required, ok := action.(server.BackchannelInteractionRequired)
			if !ok {
				t.Fatalf("action = %T, want server.BackchannelInteractionRequired", action)
			}
			if err := h.server.CompleteBackchannelAuthentication(context.Background(), server.CompleteBackchannelAuthenticationRequest{
				Handle: required.Handle, Result: authorizedAs(t, h, "user-1"),
			}); err != nil {
				t.Fatalf("CompleteBackchannelAuthentication: %v", err)
			}
			form := []server.FormParameter{
				formParam("client_assertion", h.clientAssertion(t)),
				formParam("client_assertion_type", clientassertion.AssertionType),
				formParam("grant_type", server.CIBAGrantType),
				formParam("auth_req_id", required.AuthReqID.String()),
			}
			for _, r := range tc.requested {
				form = append(form, formParam("resource", r))
			}
			result, err := h.server.ExchangeBackchannelAuthentication(context.Background(), server.BackchannelTokenExchangeRequest{
				HTTP:       server.FormRequest{Parameters: form},
				DPoPProofs: []string{createDPoPProof(t, generateKey(t), h.now)},
			})
			if tc.wantToken != "" {
				wantErrorCode(t, err, tc.wantToken)
				return
			}
			if err != nil {
				t.Fatalf("ExchangeBackchannelAuthentication: %v", err)
			}
			wantAudience(t, result, tc.want)
		})
	}
}

func TestResourceIndicatorsClientCredentials(t *testing.T) {
	base := newHarnessWithClientCredentialsGrant(t, storage.SenderConstrainDPoP, true)
	h := withResources(t, base, []string{resourceA, resourceB}, nil)
	for name, tc := range map[string]struct {
		resources []string
		want      any
		wantErr   server.ErrorCode
	}{
		"none":     {want: testIssuer},
		"one":      {resources: []string{resourceA}, want: resourceA},
		"two":      {resources: []string{resourceA, resourceB}, want: []any{resourceA, resourceB}},
		"unlisted": {resources: []string{resourceC}, wantErr: server.ErrorInvalidTarget},
	} {
		t.Run(name, func(t *testing.T) {
			form := clientCredentialsFormParams(h.clientAssertion(t), "accounts")
			for _, r := range tc.resources {
				form = append(form, formParam("resource", r))
			}
			result, err := h.server.RequestClientCredentialsToken(context.Background(), server.ClientCredentialsTokenRequest{
				HTTP:       server.FormRequest{Parameters: form},
				DPoPProofs: []string{createDPoPProof(t, generateKey(t), h.now)},
			})
			if tc.wantErr != "" {
				wantErrorCode(t, err, tc.wantErr)
				return
			}
			if err != nil {
				t.Fatalf("RequestClientCredentialsToken: %v", err)
			}
			wantAudience(t, result, tc.want)
		})
	}
}

// newResourceEmbedderHarness is the attestation harness for embedder
// grants, with Config.Resources set to resourceA and resourceB.
func newResourceEmbedderHarness(t *testing.T) (harness, *attestedInstance) {
	t.Helper()
	attesterKey := generateKey(t)
	h := newRevocationHarness(t, attesterKey)
	h = withResources(t, h, []string{resourceA, resourceB}, nil)
	return h, &attestedInstance{t: t, h: h, attesterKey: attesterKey, instanceKey: generateKey(t)}
}

func TestResourceIndicatorsEmbedderGrants(t *testing.T) {
	for name, tc := range map[string]struct {
		resources []string
		want      any
		wantErr   server.ErrorCode
	}{
		"none":      {want: testIssuer},
		"one":       {resources: []string{resourceA}, want: resourceA},
		"two":       {resources: []string{resourceA, resourceB, resourceA}, want: []any{resourceA, resourceB}},
		"unlisted":  {resources: []string{resourceC}, wantErr: server.ErrorInvalidTarget},
		"malformed": {resources: []string{"x"}, wantErr: server.ErrorInvalidTarget},
	} {
		t.Run(name, func(t *testing.T) {
			h, instance := newResourceEmbedderHarness(t)
			req := embedderAccessTokenRequest(t, instance, generateKey(t))
			req.Resources = tc.resources
			result, err := h.server.IssueAccessToken(context.Background(), req)
			_, refreshErr := h.server.IssueRefreshToken(context.Background(), server.IssueRefreshTokenRequest(req))
			if tc.wantErr != "" {
				wantErrorCode(t, err, tc.wantErr)
				wantErrorCode(t, refreshErr, tc.wantErr)
				return
			}
			if err != nil || refreshErr != nil {
				t.Fatalf("IssueAccessToken = %v, IssueRefreshToken = %v", err, refreshErr)
			}
			wantAudience(t, result, tc.want)
		})
	}
}

func TestResourceIndicatorsEmbedderRefreshNarrows(t *testing.T) {
	h, instance := newResourceEmbedderHarness(t)
	req := embedderAccessTokenRequest(t, instance, generateKey(t))
	req.Resources = []string{resourceA, resourceB}
	refreshToken, err := h.server.IssueRefreshToken(context.Background(), server.IssueRefreshTokenRequest(req))
	if err != nil {
		t.Fatalf("IssueRefreshToken: %v", err)
	}
	refresh := func(resources ...string) (server.TokenResult, error) {
		attestations, pops := instance.headers()
		form := []server.FormParameter{
			formParam("client_id", testClientID.String()),
			formParam("grant_type", "refresh_token"),
			formParam("refresh_token", refreshToken.Reveal()),
		}
		for _, r := range resources {
			form = append(form, formParam("resource", r))
		}
		return h.server.RefreshAccessToken(context.Background(), server.RefreshTokenRequest{
			HTTP:               server.FormRequest{Parameters: form},
			DPoPProofs:         []string{createDPoPProof(t, generateKey(t), h.now)},
			ClientAttestations: attestations, ClientAttestationPoPs: pops,
		})
	}
	all, err := refresh()
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	wantAudience(t, all, []any{resourceA, resourceB})
	narrowed, err := refresh(resourceB)
	if err != nil {
		t.Fatalf("refresh narrowed: %v", err)
	}
	wantAudience(t, narrowed, resourceB)
	_, err = refresh(resourceC)
	wantErrorCode(t, err, server.ErrorInvalidTarget)
}

func TestTokenEndpointRequestResources(t *testing.T) {
	body := "grant_type=" + preAuthorizedCodeGrant + "&resource=" + resourceA + "&resource=" + resourceB + "&pre-authorized_code=x"
	req := httptestTokenRequest(t, body)
	params, err := req.Parameters()
	if err != nil {
		t.Fatalf("Parameters: %v", err)
	}
	if params["resource"] != resourceA || params["pre-authorized_code"] != "x" {
		t.Fatalf("Parameters = %v", params)
	}
	if got := req.Resources(); !reflect.DeepEqual(got, []string{resourceA, resourceB}) {
		t.Fatalf("Resources = %v", got)
	}

	// Any other repeated parameter is still refused.
	if _, err := httptestTokenRequest(t, "grant_type=x&code=1&code=2").Parameters(); err == nil {
		t.Fatal("Parameters accepted a repeated code")
	}
	if got := httptestTokenRequest(t, "grant_type=x").Resources(); got != nil {
		t.Fatalf("Resources = %v, want nil", got)
	}
	// Too many parameters: nothing escapes the bound.
	many := "grant_type=x" + strings.Repeat("&resource="+resourceA, 120)
	tooMany := httptestTokenRequest(t, many)
	if _, err := tooMany.Parameters(); err == nil {
		t.Fatal("Parameters accepted too many parameters")
	}
	if got := tooMany.Resources(); got != nil {
		t.Fatalf("Resources = %d values, want nil", len(got))
	}
}

func httptestTokenRequest(t *testing.T, body string) server.TokenEndpointRequest {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, testTokenEndpoint, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req, err := server.TokenEndpointRequestFromHTTP(r)
	if err != nil {
		t.Fatalf("TokenEndpointRequestFromHTTP: %v", err)
	}
	return req
}

// TestResourceIndicatorsResourceServerRefusesAnotherResourcesToken is
// the replay RFC 8707 prevents: a token issued for resource server A
// (which could be malicious) is refused at resource server B, for both
// access token formats, while A — and B for its own token — accept.
func TestResourceIndicatorsResourceServerRefusesAnotherResourcesToken(t *testing.T) {
	for _, opaque := range []bool{false, true} {
		t.Run(fmt.Sprintf("opaque=%v", opaque), func(t *testing.T) {
			h, instance := newResourceEmbedderHarness(t)
			var store *memstore.AccessTokenStore
			if opaque {
				h, store = withOpaqueAccessTokens(t, h)
				instance.h = h
			}
			dpopKey := generateKey(t)
			req := embedderAccessTokenRequest(t, instance, dpopKey)
			req.Resources = []string{resourceA}
			forA, err := h.server.IssueAccessToken(context.Background(), req)
			if err != nil {
				t.Fatalf("IssueAccessToken: %v", err)
			}
			req = embedderAccessTokenRequest(t, instance, dpopKey)
			forIssuer, err := h.server.IssueAccessToken(context.Background(), req)
			if err != nil {
				t.Fatalf("IssueAccessToken (no resource): %v", err)
			}

			atA := audienceVerifier(t, h, store, resourceA)
			atB := audienceVerifier(t, h, store, resourceB)
			atIssuer := audienceVerifier(t, h, store, testIssuer)
			migrating := audienceVerifier(t, h, store, resourceB, testIssuer)

			if err := verifyWithDPoP(t, atA, dpopKey, forA.AccessToken.Reveal(), h.now); err != nil {
				t.Fatalf("A refused its own token: %v", err)
			}
			requireInvalidToken(t, verifyWithDPoP(t, atB, dpopKey, forA.AccessToken.Reveal(), h.now), "A's token at B")
			requireInvalidToken(t, verifyWithDPoP(t, atIssuer, dpopKey, forA.AccessToken.Reveal(), h.now), "A's token at the issuer audience")
			requireInvalidToken(t, verifyWithDPoP(t, migrating, dpopKey, forA.AccessToken.Reveal(), h.now), "A's token at migrating B")
			requireInvalidToken(t, verifyWithDPoP(t, atB, dpopKey, forIssuer.AccessToken.Reveal(), h.now), "an issuer token at B")
			if err := verifyWithDPoP(t, migrating, dpopKey, forIssuer.AccessToken.Reveal(), h.now); err != nil {
				t.Fatalf("migrating B refused an issuer token: %v", err)
			}
			if err := verifyWithDPoP(t, atIssuer, dpopKey, forIssuer.AccessToken.Reveal(), h.now); err != nil {
				t.Fatalf("the issuer audience refused an issuer token: %v", err)
			}
		})
	}
}

// audienceVerifier is a resource server for h's tokens (opaque with
// store) accepting audience, and additional besides it.
func audienceVerifier(t *testing.T, h harness, store *memstore.AccessTokenStore, audience string, additional ...string) *resource.Verifier {
	t.Helper()
	var resolver resource.AccessTokenResolver = resource.OpaqueAccessTokens{Store: store, Audience: audience, AdditionalAudiences: additional}
	if store == nil {
		issuerKeys, err := keys.NewLocalIssuerKeys(h.cfg.Issuer, h.deps.Keys)
		if err != nil {
			t.Fatal(err)
		}
		jwt, err := resource.NewJWTAccessTokens(issuerKeys, h.cfg.Issuer, audience, fapi.ES256, 10*time.Minute, 4)
		if err != nil {
			t.Fatal(err)
		}
		jwt.AdditionalAudiences = additional
		resolver = jwt
	}
	verifier, err := resource.NewVerifier(resource.Config{
		Limits:    resource.Limits{MaxDPoPProofAge: time.Minute, MaxClockSkew: 5 * time.Second},
		Assurance: resource.AssuranceDevelopment,
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

// TestResourceIndicatorsOverHTTP sends several resources as repeated
// form parameters through the HTTP constructors, at PAR and at the token
// endpoint, while any other repeated parameter is still refused.
func TestResourceIndicatorsOverHTTP(t *testing.T) {
	h := withResources(t, newHarness(t, server.ProfileFAPISecurity, true), []string{resourceA, resourceB, resourceC}, nil)
	form := func(params []server.FormParameter) string {
		values := url.Values{}
		for _, p := range params {
			values.Add(p.Name, p.Value)
		}
		return values.Encode()
	}
	post := func(endpoint string, params []server.FormParameter) *http.Request {
		r := httptest.NewRequest(http.MethodPost, endpoint, strings.NewReader(form(params)))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return r
	}
	parParams := []server.FormParameter{
		formParam("client_assertion", h.clientAssertion(t)),
		formParam("client_assertion_type", clientassertion.AssertionType),
		formParam("response_type", "code"),
		formParam("redirect_uri", testRedirectURI),
		formParam("scope", "openid accounts offline_access"),
		formParam("code_challenge", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"),
		formParam("code_challenge_method", "S256"),
		formParam("resource", resourceA),
		formParam("resource", resourceB),
		formParam("resource", resourceC),
	}
	parReq, err := server.PushAuthorizationRequestFromHTTP(post(testPAREndpoint, parParams))
	if err != nil {
		t.Fatalf("PushAuthorizationRequestFromHTTP: %v", err)
	}
	pushed, err := h.server.PushAuthorizationRequest(context.Background(), parReq)
	if err != nil {
		t.Fatalf("PushAuthorizationRequest: %v", err)
	}

	// Another repeated parameter is still invalid_request.
	dupReq, err := server.PushAuthorizationRequestFromHTTP(post(testPAREndpoint, append(parParams, formParam("scope", "openid"))))
	if err != nil {
		t.Fatalf("PushAuthorizationRequestFromHTTP: %v", err)
	}
	_, err = h.server.PushAuthorizationRequest(context.Background(), dupReq)
	wantErrorCode(t, err, server.ErrorInvalidRequest)

	tokenParams := append(exchangeFormParams(h.clientAssertion(t), codeForPushed(t, h, pushed), testRedirectURI, testCodeVerifier),
		formParam("resource", resourceC), formParam("resource", resourceA))
	tokenReq, err := server.TokenEndpointRequestFromHTTP(post(testTokenEndpoint, tokenParams))
	if err != nil {
		t.Fatalf("TokenEndpointRequestFromHTTP: %v", err)
	}
	exchange := tokenReq.AuthorizationCodeExchange()
	exchange.DPoPProofs = []string{createDPoPProof(t, generateKey(t), h.now)}
	result, err := h.server.ExchangeAuthorizationCode(context.Background(), exchange)
	if err != nil {
		t.Fatalf("ExchangeAuthorizationCode: %v", err)
	}
	wantAudience(t, result, []any{resourceC, resourceA})
}
