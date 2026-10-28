package server_test

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
	"github.com/idfoundry/fapigo/storage/memstore"
)

// A client confined by AllowedResources to one resource that names none
// gets tokens for that resource, never ones addressed to the issuer: a
// resource server accepting the issuer as an audience (migrating with it
// in AdditionalAudiences, or the issuer's own) would take those whatever
// AllowedResources says.
func TestResourceIndicatorsAllowedResourcesSingleIsDefault(t *testing.T) {
	h := withResources(t, newHarness(t, server.ProfileFAPISecurity, true), []string{resourceA, resourceB}, nil)
	restrictClientResources(t, h, resourceA)

	_, err := pushWithResources(t, h, resourceB)
	wantErrorCode(t, err, server.ErrorInvalidTarget)

	dpopKey := generateKey(t)
	result, err := h.server.ExchangeAuthorizationCode(context.Background(), server.AuthorizationCodeExchangeRequest{
		HTTP:       server.FormRequest{Parameters: exchangeFormParams(h.clientAssertion(t), grantForResources(t, h), testRedirectURI, testCodeVerifier)},
		DPoPProofs: []string{createDPoPProof(t, dpopKey, h.now)},
	})
	if err != nil {
		t.Fatalf("ExchangeAuthorizationCode: %v", err)
	}
	wantAudience(t, result, resourceA)
	for name, verifier := range map[string]func() error{
		"resource B, also accepting the issuer": func() error {
			return verifyWithDPoP(t, audienceVerifier(t, h, nil, resourceB, testIssuer), dpopKey, result.AccessToken.Reveal(), h.now)
		},
		"the issuer": func() error {
			return verifyWithDPoP(t, audienceVerifier(t, h, nil, testIssuer), dpopKey, result.AccessToken.Reveal(), h.now)
		},
	} {
		if verifier() == nil {
			t.Errorf("%s accepted a token of a client confined to resource A", name)
		}
	}
	if err := verifyWithDPoP(t, audienceVerifier(t, h, nil, resourceA), dpopKey, result.AccessToken.Reveal(), h.now); err != nil {
		t.Errorf("resource A refused the token: %v", err)
	}

	// The grant recorded the default, so it holds even once the client
	// may name more.
	restrictClientResources(t, h, resourceA, resourceB)
	refreshed, err := refreshWithResources(t, h, result.RefreshToken.Reveal())
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	wantAudience(t, refreshed, resourceA)
	_, err = refreshWithResources(t, h, result.RefreshToken.Reveal(), resourceB)
	wantErrorCode(t, err, server.ErrorInvalidTarget)
}

// A client confined to several resources must name which a request is
// for.
func TestResourceIndicatorsAllowedResourcesSeveralRequireOne(t *testing.T) {
	h := withResources(t, newHarness(t, server.ProfileFAPISecurity, true), []string{resourceA, resourceB}, nil)
	restrictClientResources(t, h, resourceA, resourceB)
	_, err := pushWithResources(t, h)
	wantErrorCode(t, err, server.ErrorInvalidTarget)
	if _, err := pushWithResources(t, h, resourceB); err != nil {
		t.Fatalf("PushAuthorizationRequest naming one: %v", err)
	}
}

// The default is checked as a resource the request named would be:
// against Config.Resources and the ResourcePolicy.
func TestResourceIndicatorsAllowedResourcesDefaultIsChecked(t *testing.T) {
	policy := &recordingResourcePolicy{}
	h := withResources(t, newHarness(t, server.ProfileFAPISecurity, true), []string{resourceA}, policy)
	restrictClientResources(t, h, resourceC)
	if _, err := pushWithResources(t, h); err != nil {
		t.Fatalf("PushAuthorizationRequest: %v", err)
	}
	if want := [][]string{{resourceC}}; !reflect.DeepEqual(policy.asked, want) {
		t.Fatalf("policy asked %v, want %v", policy.asked, want)
	}

	h = withResources(t, h, []string{resourceA}, nil)
	_, err := pushWithResources(t, h)
	wantErrorCode(t, err, server.ErrorInvalidTarget)
}

// With resource indicators disabled every token would be addressed to
// the issuer, so a client confined by AllowedResources is refused with
// server_error, at every request, rather than given one: its
// confinement isn't silently lifted. CheckClientRegistration reports it.
func TestResourceIndicatorsAllowedResourcesRefusedWhenDisabled(t *testing.T) {
	h := withResources(t, newHarness(t, server.ProfileFAPISecurity, true), []string{resourceA, resourceB}, nil)
	issued, err := exchangeWithResources(t, h, grantForResources(t, h, resourceA))
	if err != nil {
		t.Fatalf("ExchangeAuthorizationCode: %v", err)
	}
	pending := grantForResources(t, h)

	h = withResources(t, h, nil, nil)
	restrictClientResources(t, h, resourceA, resourceB)
	wantConfinedWithoutResourceIndicators(t, h)
	_, err = pushWithResources(t, h)
	wantErrorCode(t, err, server.ErrorServerError)
	_, err = exchangeWithResources(t, h, pending)
	wantErrorCode(t, err, server.ErrorServerError)
	_, err = refreshWithResources(t, h, issued.RefreshToken.Reveal())
	wantErrorCode(t, err, server.ErrorInvalidTarget)

	restrictClientResources(t, h)
	if err := h.server.CheckClientRegistration(h.clients.clients[testClientID]); err != nil {
		t.Fatalf("CheckClientRegistration for an unconfined client: %v", err)
	}
}

// wantConfinedWithoutResourceIndicators checks CheckClientRegistration
// reports testClientID's AllowedResources on h, whose resource
// indicators are disabled.
func wantConfinedWithoutResourceIndicators(t *testing.T, h harness) {
	t.Helper()
	err := h.server.CheckClientRegistration(h.clients.clients[testClientID])
	if err == nil || !strings.Contains(err.Error(), "resource indicators are disabled") {
		t.Fatalf("CheckClientRegistration = %v, want it to report AllowedResources without resource indicators", err)
	}
}

// A grant made without resources before its client was confined gets
// the default at its token requests too: the single allowed resource,
// or invalid_target when there are several.
func TestResourceIndicatorsAllowedResourcesDefaultForEarlierGrant(t *testing.T) {
	h := withResources(t, newHarness(t, server.ProfileFAPISecurity, true), []string{resourceA, resourceB}, nil)
	first, second := grantForResources(t, h), grantForResources(t, h)
	issued, err := exchangeWithResources(t, h, grantForResources(t, h))
	if err != nil {
		t.Fatalf("ExchangeAuthorizationCode: %v", err)
	}
	wantAudience(t, issued, testIssuer)

	restrictClientResources(t, h, resourceA)
	result, err := exchangeWithResources(t, h, first)
	if err != nil {
		t.Fatalf("ExchangeAuthorizationCode: %v", err)
	}
	wantAudience(t, result, resourceA)
	refreshed, err := refreshWithResources(t, h, issued.RefreshToken.Reveal())
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	wantAudience(t, refreshed, resourceA)

	restrictClientResources(t, h, resourceA, resourceB)
	_, err = exchangeWithResources(t, h, second)
	wantErrorCode(t, err, server.ErrorInvalidTarget)
	_, err = refreshWithResources(t, h, issued.RefreshToken.Reveal())
	wantErrorCode(t, err, server.ErrorInvalidTarget)
}

func TestResourceIndicatorsAllowedResourcesDefaultCIBA(t *testing.T) {
	for name, tc := range map[string]struct {
		allowed   []string
		want      any
		wantBegin server.ErrorCode
	}{
		"one":     {allowed: []string{resourceA}, want: resourceA},
		"several": {allowed: []string{resourceA, resourceB}, wantBegin: server.ErrorInvalidTarget},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarnessWithBackchannelConfig(t, memstore.NewBackchannelAuthenticationStore(), func(cfg *server.Config) {
				cfg.Resources = []string{resourceA, resourceB}
			})
			registerClientResources(t, h, true, tc.allowed...)
			action := beginResourceCIBA(t, h, nil)
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
			if !reflect.DeepEqual(required.Interaction.Resources, []string{resourceA}) {
				t.Errorf("Interaction.Resources = %q, want the default", required.Interaction.Resources)
			}
			result, err := approveAndPollResourceCIBA(t, h, required, nil)
			if err != nil {
				t.Fatalf("ExchangeBackchannelAuthentication: %v", err)
			}
			wantAudience(t, result, tc.want)
		})
	}
}

func TestResourceIndicatorsAllowedResourcesDefaultClientCredentials(t *testing.T) {
	for name, tc := range map[string]struct {
		allowed []string
		want    any
		wantErr server.ErrorCode
	}{
		"one":     {allowed: []string{resourceB}, want: resourceB},
		"several": {allowed: []string{resourceA, resourceB}, wantErr: server.ErrorInvalidTarget},
	} {
		t.Run(name, func(t *testing.T) {
			h := withResources(t, newHarnessWithClientCredentialsGrant(t, storage.SenderConstrainDPoP, true), []string{resourceA, resourceB}, nil)
			client, err := storage.NewRegisteredClient(storage.RegisteredClientConfig{
				ID:                           testClientID,
				RedirectURIs:                 []fapi.RegisteredRedirectURI{testRedirectURI},
				ClientAssertionAlgorithm:     fapi.ES256,
				SenderConstrain:              storage.SenderConstrainDPoP,
				AllowedScopes:                []string{"accounts"},
				AllowsClientCredentialsGrant: true,
				AllowedResources:             tc.allowed,
			})
			if err != nil {
				t.Fatalf("NewRegisteredClient: %v", err)
			}
			h.clients.clients[testClientID] = client
			result, err := h.server.RequestClientCredentialsToken(context.Background(), server.ClientCredentialsTokenRequest{
				HTTP:       server.FormRequest{Parameters: clientCredentialsFormParams(h.clientAssertion(t), "accounts")},
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

// The embedder's grants get the same default, so neither a token it
// issues nor one a refresh of its refresh token issues is addressed to
// the issuer for a confined client — even when it gives the refresh
// token fewer resources than the access token.
func TestResourceIndicatorsAllowedResourcesDefaultEmbedder(t *testing.T) {
	for name, tc := range map[string]struct {
		allowed []string
		want    any
		wantErr server.ErrorCode
	}{
		"one":     {allowed: []string{resourceA}, want: resourceA},
		"several": {allowed: []string{resourceA, resourceB}, wantErr: server.ErrorInvalidTarget},
	} {
		t.Run(name, func(t *testing.T) {
			attesterKey := generateKey(t)
			h := newAttestationHarness(t, time.Now(), attesterKey, server.RegisteredAttesterKeys{}, func(cfg *server.Config, c *storage.RegisteredClientConfig) {
				cfg.AdditionalGrantTypes = []string{preAuthorizedCodeGrant}
				cfg.Resources = []string{resourceA, resourceB}
				c.AllowedScopes = []string{"openid", "accounts", "offline_access"}
				c.AllowedResources = tc.allowed
			})
			instance := &attestedInstance{t: t, h: h, attesterKey: attesterKey, instanceKey: generateKey(t)}
			req := embedderAccessTokenRequest(t, instance, generateKey(t))
			result, err := h.server.IssueAccessToken(context.Background(), req)
			refreshToken, refreshErr := h.server.IssueRefreshToken(context.Background(), server.IssueRefreshTokenRequest(req))
			if tc.wantErr != "" {
				wantErrorCode(t, err, tc.wantErr)
				wantErrorCode(t, refreshErr, tc.wantErr)
				return
			}
			if err != nil || refreshErr != nil {
				t.Fatalf("IssueAccessToken = %v, IssueRefreshToken = %v", err, refreshErr)
			}
			wantAudience(t, result, tc.want)
			attestations, pops := instance.headers()
			refreshed, err := h.server.RefreshAccessToken(context.Background(), server.RefreshTokenRequest{
				HTTP: server.FormRequest{Parameters: []server.FormParameter{
					formParam("client_id", testClientID.String()),
					formParam("grant_type", "refresh_token"),
					formParam("refresh_token", refreshToken.Reveal()),
				}},
				DPoPProofs:         []string{createDPoPProof(t, generateKey(t), h.now)},
				ClientAttestations: attestations, ClientAttestationPoPs: pops,
			})
			if err != nil {
				t.Fatalf("refresh: %v", err)
			}
			wantAudience(t, refreshed, tc.want)
		})
	}
}
