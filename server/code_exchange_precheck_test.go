package server_test

import (
	"fmt"
	"testing"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
)

// TestCodeExchangeRefusedBeforeRedemptionKeepsTheCode covers a token
// request refused for something the code's record couldn't make
// acceptable: the client's registration, or a resource it may not
// request. It's refused before the store is asked to redeem the code,
// so the code stays unspent, and the client's own exchange, once the
// cause is gone, still succeeds.
func TestCodeExchangeRefusedBeforeRedemptionKeepsTheCode(t *testing.T) {
	for name, tc := range map[string]struct {
		reregister func(*testing.T, harness)
		want       server.ErrorCode
	}{
		"redirect_uri no longer registered": {func(t *testing.T, h harness) { reregisterRedirectURIs(t, h, "https://new-rp.example/cb") }, server.ErrorInvalidGrant},
		"no redirect URI registered":        {registerWithoutRedirectURIs, server.ErrorUnauthorizedClient},
	} {
		t.Run(name, func(t *testing.T) {
			h, grants := harnessCountingRedemptions(t)
			code := completeSuccessfulAuthorization(t, h, []string{"openid", "accounts"})
			tc.reregister(t, h)
			_, err := exchangeWithResources(t, h, code)
			wantErrorCode(t, err, tc.want)
			if calls := grants.redeemCalls(); calls != 0 {
				t.Fatalf("RedeemAuthorizationCode calls = %d, want none", calls)
			}
			reregisterRedirectURIs(t, h, testRedirectURI)
			if _, err := exchangeWithResources(t, h, code); err != nil {
				t.Fatalf("exchange once registered again: %v", err)
			}
		})
	}
}

// registerWithoutRedirectURIs re-registers testClientID for the client
// credentials grant only, so not for the authorization code grant.
func registerWithoutRedirectURIs(t *testing.T, h harness) {
	t.Helper()
	client, err := storage.NewRegisteredClient(storage.RegisteredClientConfig{
		ID: testClientID, ClientAssertionAlgorithm: fapi.ES256, RequestObjectAlgorithm: fapi.ES256,
		AllowedScopes: []string{"openid", "accounts"}, AllowsClientCredentialsGrant: true,
	})
	if err != nil {
		t.Fatalf("NewRegisteredClient: %v", err)
	}
	h.clients.clients[testClientID] = client
}

// TestCodeExchangeRefusedResourceKeepsTheCode covers a token request
// naming a resource this server doesn't serve: invalid_target before
// the code is redeemed, so an exchange naming the granted resource
// still succeeds.
func TestCodeExchangeRefusedResourceKeepsTheCode(t *testing.T) {
	h, grants := harnessCountingRedemptions(t)
	policy := &recordingResourcePolicy{}
	h = withResources(t, h, []string{resourceA}, policy)
	code := grantForResources(t, h, resourceA)
	policy.err = fmt.Errorf("not served: %w", server.ErrResourceNotAllowed)
	for name, resources := range map[string][]string{
		"not a URI":   {"not a uri"},
		"too many":    repeated(resourceA, 17),
		"not allowed": {resourceA, resourceC},
	} {
		_, err := exchangeWithResources(t, h, code, resources...)
		if serverErrorCode(t, err) != server.ErrorInvalidTarget {
			t.Fatalf("%s: %v, want invalid_target", name, err)
		}
	}
	if calls := grants.redeemCalls(); calls != 0 {
		t.Fatalf("RedeemAuthorizationCode calls = %d, want none", calls)
	}
	policy.err, policy.asked = nil, nil
	result, err := exchangeWithResources(t, h, code, resourceA)
	if err != nil {
		t.Fatalf("exchange naming the granted resource: %v", err)
	}
	wantAudience(t, result, resourceA)
	if len(policy.asked) != 0 {
		t.Fatalf("policy asked %v about a listed resource, want nothing", policy.asked)
	}
}

// TestCodeExchangeAsksResourcePolicyOnce covers a code exchange naming a
// resource only the ResourcePolicy accepts: the policy is asked once,
// before the code is redeemed, not again after.
func TestCodeExchangeAsksResourcePolicyOnce(t *testing.T) {
	policy := &recordingResourcePolicy{}
	h := withResources(t, newHarness(t, server.ProfileFAPISecurity, true), nil, policy)
	code := grantForResources(t, h, resourceB)
	policy.asked = nil
	result, err := exchangeWithResources(t, h, code, resourceB)
	if err != nil {
		t.Fatalf("ExchangeAuthorizationCode: %v", err)
	}
	wantAudience(t, result, resourceB)
	if len(policy.asked) != 1 {
		t.Fatalf("policy asked %v, want once", policy.asked)
	}
}
