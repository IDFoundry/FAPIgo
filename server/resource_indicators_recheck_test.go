package server_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/clientassertion"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
	"github.com/idfoundry/fapigo/storage/memstore"
)

// resourceRevocation is a way a resource a grant was made for stops
// being allowed afterwards. setUp configures the server so resourceA
// and resourceB are both allowed; revoke then takes resourceB away
// (resourceA too, for one that turns resource indicators off).
type resourceRevocation struct {
	setUp  func(t *testing.T, h harness, ciba bool) harness
	revoke func(t *testing.T, h harness, ciba bool) harness
	// keepsA is whether resourceA is still allowed after revoke, so a
	// request narrowed to it succeeds.
	keepsA bool
}

// refusingPolicy is a ResourcePolicy that allows everything until refuse
// is set.
type refusingPolicy struct{ refuse error }

func (p *refusingPolicy) AllowResources(context.Context, storage.RegisteredClient, []string) error {
	return p.refuse
}

func resourceRevocations() map[string]resourceRevocation {
	both := []string{resourceA, resourceB}
	return map[string]resourceRevocation{
		"client AllowedResources": {
			setUp: func(t *testing.T, h harness, _ bool) harness { return withResources(t, h, both, nil) },
			revoke: func(t *testing.T, h harness, ciba bool) harness {
				registerClientResources(t, h, ciba, resourceA)
				return h
			},
			keepsA: true,
		},
		"Config.Resources": {
			setUp:  func(t *testing.T, h harness, _ bool) harness { return withResources(t, h, both, nil) },
			revoke: func(t *testing.T, h harness, _ bool) harness { return withResources(t, h, []string{resourceA}, nil) },
			keepsA: true,
		},
		"ResourcePolicy": {
			setUp: func(t *testing.T, h harness, _ bool) harness {
				return withResources(t, h, []string{resourceA}, &refusingPolicy{})
			},
			revoke: func(_ *testing.T, h harness, _ bool) harness {
				h.deps.ResourcePolicy.(*refusingPolicy).refuse = fmt.Errorf("no longer served: %w", server.ErrResourceNotAllowed)
				return h
			},
			keepsA: true,
		},
		"resource indicators turned off": {
			setUp:  func(t *testing.T, h harness, _ bool) harness { return withResources(t, h, both, nil) },
			revoke: func(t *testing.T, h harness, _ bool) harness { return withResources(t, h, nil, nil) },
		},
	}
}

// registerClientResources re-registers testClientID, as the code-flow
// or the CIBA harness registers it, with AllowedResources.
func registerClientResources(t *testing.T, h harness, ciba bool, allowed ...string) {
	t.Helper()
	cfg := storage.RegisteredClientConfig{
		ID:                       testClientID,
		RedirectURIs:             []fapi.RegisteredRedirectURI{testRedirectURI},
		ClientAssertionAlgorithm: fapi.ES256,
		AllowedScopes:            []string{"openid", "accounts", "offline_access"},
		AllowedResources:         allowed,
	}
	if ciba {
		cfg.BackchannelAuthenticationRequestAlgorithm = fapi.ES256
	} else {
		cfg.RequestObjectAlgorithm = fapi.ES256
	}
	client, err := storage.NewRegisteredClient(cfg)
	if err != nil {
		t.Fatalf("NewRegisteredClient: %v", err)
	}
	h.clients.clients[testClientID] = client
}

// wantRecheck checks a token request from a grant for resourceA and
// resourceB once resourceB is revoked: refused with invalid_target when
// it names no resource (so all of the grant's), and, when keepsA, a
// token for resourceA alone when it narrows to that.
func wantRecheck(t *testing.T, rv resourceRevocation, all func() (server.TokenResult, error), narrowedToA func() (server.TokenResult, error)) {
	t.Helper()
	_, err := all()
	wantErrorCode(t, err, server.ErrorInvalidTarget)
	narrowed, err := narrowedToA()
	if !rv.keepsA {
		wantErrorCode(t, err, server.ErrorInvalidTarget)
		return
	}
	if err != nil {
		t.Fatalf("narrowed to a still-allowed resource: %v", err)
	}
	wantAudience(t, narrowed, resourceA)
}

func TestResourceIndicatorsCodeExchangeRechecksGrantResources(t *testing.T) {
	for name, rv := range resourceRevocations() {
		t.Run(name, func(t *testing.T) {
			h := rv.setUp(t, newHarness(t, server.ProfileFAPISecurity, true), false)
			first := grantForResources(t, h, resourceA, resourceB)
			second := grantForResources(t, h, resourceA, resourceB)
			h = rv.revoke(t, h, false)
			wantRecheck(t, rv,
				func() (server.TokenResult, error) { return exchangeWithResources(t, h, first) },
				func() (server.TokenResult, error) { return exchangeWithResources(t, h, second, resourceA) })
		})
	}
}

func TestResourceIndicatorsRefreshRechecksGrantResources(t *testing.T) {
	for name, rv := range resourceRevocations() {
		t.Run(name, func(t *testing.T) {
			h := rv.setUp(t, newHarness(t, server.ProfileFAPISecurity, true), false)
			issued, err := exchangeWithResources(t, h, grantForResources(t, h, resourceA, resourceB))
			if err != nil {
				t.Fatalf("exchange: %v", err)
			}
			wantAudience(t, issued, []any{resourceA, resourceB})
			refreshToken := issued.RefreshToken.Reveal()
			h = rv.revoke(t, h, false)
			// Refresh tokens aren't single-use, so the same one is
			// refused for every resource and then used for resourceA.
			wantRecheck(t, rv,
				func() (server.TokenResult, error) { return refreshWithResources(t, h, refreshToken) },
				func() (server.TokenResult, error) { return refreshWithResources(t, h, refreshToken, resourceA) })
		})
	}
}

func TestResourceIndicatorsCIBARechecksGrantResources(t *testing.T) {
	for name, rv := range resourceRevocations() {
		t.Run(name, func(t *testing.T) {
			h := newHarnessWithBackchannelConfig(t, memstore.NewBackchannelAuthenticationStore(), nil)
			h = rv.setUp(t, h, true)
			first := cibaGrantForResources(t, h, resourceA, resourceB)
			second := cibaGrantForResources(t, h, resourceA, resourceB)
			h = rv.revoke(t, h, true)
			wantRecheck(t, rv,
				func() (server.TokenResult, error) { return cibaTokenWithResources(t, h, first) },
				func() (server.TokenResult, error) { return cibaTokenWithResources(t, h, second, resourceA) })
		})
	}
}

// A ResourcePolicy that can't decide at refresh is server_error, as
// when the grant was made: never read as the resource being refused.
func TestResourceIndicatorsRefreshPolicyFailureIsServerError(t *testing.T) {
	policy := &refusingPolicy{}
	h := withResources(t, newHarness(t, server.ProfileFAPISecurity, true), []string{resourceA}, policy)
	issued, err := exchangeWithResources(t, h, grantForResources(t, h, resourceA, resourceB))
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	policy.refuse = errors.New("policy store unavailable")
	_, err = refreshWithResources(t, h, issued.RefreshToken.Reveal())
	wantErrorCode(t, err, server.ErrorServerError)
	// resourceA is listed, so the policy isn't asked about it.
	narrowed, err := refreshWithResources(t, h, issued.RefreshToken.Reveal(), resourceA)
	if err != nil {
		t.Fatalf("refresh narrowed to a listed resource: %v", err)
	}
	wantAudience(t, narrowed, resourceA)
}

// cibaGrantForResources begins and approves a CIBA request naming
// resources, and returns its auth_req_id.
func cibaGrantForResources(t *testing.T, h harness, resources ...string) string {
	t.Helper()
	params := standardBackchannelParams(t)
	params["resource"] = jsonRaw(t, resources)
	action, err := h.server.BeginBackchannelAuthentication(context.Background(), server.BeginBackchannelAuthenticationRequest{
		HTTP: server.FormRequest{Parameters: backchannelFormParams(h.clientAssertion(t), h.backchannelRequestObject(t, params))},
	})
	if err != nil {
		t.Fatalf("BeginBackchannelAuthentication: %v", err)
	}
	required, ok := action.(server.BackchannelInteractionRequired)
	if !ok {
		t.Fatalf("action = %#v, want server.BackchannelInteractionRequired", action)
	}
	if err := h.server.CompleteBackchannelAuthentication(context.Background(), server.CompleteBackchannelAuthenticationRequest{
		Handle: required.Handle, Result: authorizedAs(t, h, "user-1"),
	}); err != nil {
		t.Fatalf("CompleteBackchannelAuthentication: %v", err)
	}
	return required.AuthReqID.String()
}

// cibaTokenWithResources polls for authReqID's tokens, naming resources.
func cibaTokenWithResources(t *testing.T, h harness, authReqID string, resources ...string) (server.TokenResult, error) {
	t.Helper()
	form := []server.FormParameter{
		formParam("client_assertion", h.clientAssertion(t)),
		formParam("client_assertion_type", clientassertion.AssertionType),
		formParam("grant_type", server.CIBAGrantType),
		formParam("auth_req_id", authReqID),
	}
	for _, r := range resources {
		form = append(form, formParam("resource", r))
	}
	return h.server.ExchangeBackchannelAuthentication(context.Background(), server.BackchannelTokenExchangeRequest{
		HTTP:       server.FormRequest{Parameters: form},
		DPoPProofs: []string{createDPoPProof(t, generateKey(t), h.now)},
	})
}
