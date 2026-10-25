package fapitest_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/idfoundry/fapigo/client"
	"github.com/idfoundry/fapigo/fapitest"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/serverresource"
)

// TestResourceIndicatorsAllowedResourcesDefault: a client confined by
// AllowedResources to one resource server that names no resource gets
// tokens for that resource, end to end, never ones addressed to the
// issuer, which another resource server migrating with
// AcceptIssuerAudience (or the issuer's own, UserInfo say) would accept.
func TestResourceIndicatorsAllowedResourcesDefault(t *testing.T) {
	for _, opaque := range []bool{false, true} {
		t.Run(fmt.Sprintf("opaque=%v", opaque), func(t *testing.T) {
			h := fapitest.New(t, fapitest.Config{
				Profile: server.ProfileFAPISecurity, Resources: servedResources,
				AllowedResources: []string{credentials}, OpaqueAccessTokens: opaque,
			})
			ctx := context.Background()
			_, err := h.RunAuthorizationCodeFlowWithRequest(ctx, client.BeginAuthorizationRequest{Scope: offlineScope, Resource: []string{payments}})
			wantServerError(t, "RunAuthorizationCodeFlow(payments)", err, "invalid_target")

			tokens, err := h.RunAuthorizationCodeFlow(ctx, offlineScope)
			if err != nil {
				t.Fatalf("RunAuthorizationCodeFlow: %v", err)
			}
			checkConfinedToCredentials(t, h, tokens, opaque)

			// A refresh naming no resource gets the grant's: the default.
			refreshed, err := h.Client.RefreshTokens(ctx, client.RefreshTokenRequest{Tokens: tokens})
			if err != nil {
				t.Fatalf("RefreshTokens: %v", err)
			}
			checkConfinedToCredentials(t, h, refreshed, opaque)
		})
	}
}

// TestResourceIndicatorsAllowedResourcesDefaultClientCredentials is
// TestResourceIndicatorsAllowedResourcesDefault with no user involved.
func TestResourceIndicatorsAllowedResourcesDefaultClientCredentials(t *testing.T) {
	h := fapitest.New(t, fapitest.Config{
		Profile: server.ProfileFAPISecurity, ClientCredentialsGrant: true,
		Resources: servedResources, AllowedResources: []string{credentials},
	})
	result, err := h.Client.RequestClientCredentialsToken(context.Background(), client.ClientCredentialsTokenRequest{Scope: []string{"accounts"}})
	if err != nil {
		t.Fatalf("RequestClientCredentialsToken: %v", err)
	}
	checkConfinedToCredentials(t, h, client.TokenSet{AccessToken: result.AccessToken}, false)
}

// TestResourceIndicatorsAllowedResourcesRequired: a client confined to
// several resource servers must name which a request is for.
func TestResourceIndicatorsAllowedResourcesRequired(t *testing.T) {
	h := fapitest.New(t, fapitest.Config{
		Profile: server.ProfileFAPISecurity, ClientCredentialsGrant: true,
		Resources: servedResources, AllowedResources: []string{credentials, payments},
	})
	ctx := context.Background()
	_, err := h.RunAuthorizationCodeFlow(ctx, offlineScope)
	wantServerError(t, "RunAuthorizationCodeFlow", err, "invalid_target")
	_, err = h.Client.RequestClientCredentialsToken(ctx, client.ClientCredentialsTokenRequest{Scope: []string{"accounts"}})
	wantServerError(t, "RequestClientCredentialsToken", err, "invalid_target")

	tokens, err := h.RunAuthorizationCodeFlowWithRequest(ctx, client.BeginAuthorizationRequest{Scope: offlineScope, Resource: []string{payments}})
	if err != nil {
		t.Fatalf("RunAuthorizationCodeFlow(payments): %v", err)
	}
	checkVerifierAudience(t, h, tokens, payments, []string{payments})
}

// checkConfinedToCredentials checks tokens are for credentials alone:
// accepted there, and refused by payments even while it accepts the
// issuer as an audience, and by the issuer's own resource server.
func checkConfinedToCredentials(t *testing.T, h *fapitest.Harness, tokens client.TokenSet, opaque bool) {
	t.Helper()
	if !opaque {
		checkJWTAudience(t, tokens, `"`+credentials+`"`)
	}
	checkVerifierAudience(t, h, tokens, credentials, []string{credentials})
	refuseAtResource(t, h, tokens, serverresource.Options{Resource: payments, AcceptIssuerAudience: true})
	refuseAt(t, h, h.Resource, tokens)
}
