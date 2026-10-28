package client_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/client"
)

// trustChainClient builds a Client from DiscoverViaFederation's
// metadata, with its clock at now relative to the Trust Chain's expiry.
func trustChainClient(t *testing.T, sinceExpiry time.Duration) (*client.Client, time.Time) {
	t.Helper()
	entityID, resolver := selfAnchoredOpenIDProvider(t, func(entityID string) map[string]json.RawMessage {
		return map[string]json.RawMessage{"openid_provider": mustMarshal(t, map[string]any{
			"issuer":                                entityID,
			"authorization_endpoint":                entityID + "/authorize",
			"pushed_authorization_request_endpoint": entityID + "/par",
			"token_endpoint":                        entityID + "/token",
			"jwks_uri":                              entityID + "/jwks",
			"id_token_signing_alg_values_supported": []string{"ES256"},
			"client_registration_types_supported":   []string{"automatic"},
		})}
	})
	discovered, err := client.DiscoverViaFederation(context.Background(), resolver, entityID)
	if err != nil {
		t.Fatalf("DiscoverViaFederation: %v", err)
	}
	resolved, _ := discovered.ResolvedEntity()
	cfg := validConfig(t)
	cfg.Issuer = discovered.Issuer()
	cfg.Algorithms.IDToken = fapi.ES256
	deps := validDependencies(t)
	deps.Clock = stoppedClock(resolved.ExpiresAt.Add(sinceExpiry))
	c, err := client.NewFromDiscovery(discovered, cfg, deps)
	if err != nil {
		t.Fatalf("NewFromDiscovery: %v", err)
	}
	return c, resolved.ExpiresAt
}

// TestClientRefusesUseAfterTrustChainExpiry covers OpenID Federation
// 1.0 §12.3: an RP "MUST NOT use it past the expiration of the Trust
// Chain". A Client built from DiscoverViaFederation's metadata refuses
// to start a flow, or refresh, once the chain has expired.
func TestClientRefusesUseAfterTrustChainExpiry(t *testing.T) {
	expired, expiresAt := trustChainClient(t, time.Second)
	if got, ok := expired.TrustChainExpiresAt(); !ok || !got.Equal(expiresAt) {
		t.Fatalf("TrustChainExpiresAt() = %v, %v, want %v, true", got, ok, expiresAt)
	}
	ctx := context.Background()
	_, beginErr := expired.BeginAuthorization(ctx, client.BeginAuthorizationRequest{Scope: []string{"openid"}})
	_, cibaErr := expired.BeginBackchannelAuthentication(ctx, client.BeginBackchannelAuthenticationRequest{Scope: []string{"openid"}})
	_, ccErr := expired.RequestClientCredentialsToken(ctx, client.ClientCredentialsTokenRequest{Scope: []string{"accounts"}})
	_, refreshErr := expired.RefreshTokens(ctx, client.RefreshTokenRequest{})
	for name, err := range map[string]error{"BeginAuthorization": beginErr, "BeginBackchannelAuthentication": cibaErr, "RequestClientCredentialsToken": ccErr, "RefreshTokens": refreshErr} {
		if !errors.Is(err, client.ErrTrustChainExpired) {
			t.Errorf("%s after expiry = %v, want ErrTrustChainExpired", name, err)
		}
	}

	fresh, _ := trustChainClient(t, -time.Minute)
	if _, err := fresh.RefreshTokens(ctx, client.RefreshTokenRequest{}); errors.Is(err, client.ErrTrustChainExpired) {
		t.Errorf("RefreshTokens before expiry = %v, want a different error", err)
	}
}

// TestClientWithoutTrustChainHasNoExpiry: a Client not built from
// federation metadata reports no Trust Chain expiry.
func TestClientWithoutTrustChainHasNoExpiry(t *testing.T) {
	c, err := client.New(validConfig(t), validDependencies(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, ok := c.TrustChainExpiresAt(); ok {
		t.Error("TrustChainExpiresAt() ok = true for a Client built with New")
	}
}
