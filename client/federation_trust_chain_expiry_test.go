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
	c, expiresAt, _ := trustChainClientCounting(t, sinceExpiry)
	return c, expiresAt
}

// trustChainClientCounting is trustChainClient, also returning the
// number of requests the Client has sent (see countingHTTP).
func trustChainClientCounting(t *testing.T, sinceExpiry time.Duration) (*client.Client, time.Time, *int) {
	t.Helper()
	entityID, resolver := selfAnchoredOpenIDProvider(t, func(entityID string) map[string]json.RawMessage {
		return map[string]json.RawMessage{"openid_provider": mustMarshal(t, map[string]any{
			"issuer":                                entityID,
			"authorization_endpoint":                entityID + "/authorize",
			"pushed_authorization_request_endpoint": entityID + "/par",
			"token_endpoint":                        entityID + "/token",
			"jwks_uri":                              entityID + "/jwks",
			"userinfo_endpoint":                     entityID + "/userinfo",
			"revocation_endpoint":                   entityID + "/revoke",
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
	cfg.Endpoints = client.Endpoints{} // taken from the discovered metadata
	cfg.Algorithms.IDToken = fapi.ES256
	deps := validDependencies(t)
	deps.Clock = stoppedClock(resolved.ExpiresAt.Add(sinceExpiry))
	sent := new(int)
	deps.HTTP = countingHTTP{calls: sent}
	c, err := client.NewFromDiscovery(discovered, cfg, deps)
	if err != nil {
		t.Fatalf("NewFromDiscovery: %v", err)
	}
	return c, resolved.ExpiresAt, sent
}

// TestClientRefusesUseAfterTrustChainExpiry covers OpenID Federation
// 1.0 §12.3: an RP "MUST NOT use it past the expiration of the Trust
// Chain". A Client built from DiscoverViaFederation's metadata refuses
// to start or continue a flow, refresh, call UserInfo, revoke, or trust
// what the OP signed once the chain has expired ("the trust in the OP
// MUST be successfully reevaluated before continuing to make requests to
// the OP"), and sends nothing.
func TestClientRefusesUseAfterTrustChainExpiry(t *testing.T) {
	expired, expiresAt, sent := trustChainClientCounting(t, time.Second)
	if got, ok := expired.TrustChainExpiresAt(); !ok || !got.Equal(expiresAt) {
		t.Fatalf("TrustChainExpiresAt() = %v, %v, want %v, true", got, ok, expiresAt)
	}
	for name, err := range trustChainGatedCalls(expired) {
		var cerr *client.Error
		if !errors.Is(err, client.ErrTrustChainExpired) || !errors.As(err, &cerr) || cerr.Code() != client.ErrorTrustChainExpired {
			t.Errorf("%s after expiry = %v, want a *client.Error %s wrapping ErrTrustChainExpired", name, err, client.ErrorTrustChainExpired)
		}
	}
	if n := *sent; n != 0 {
		t.Errorf("%d requests sent after expiry, want 0", n)
	}
	ctx := context.Background()

	fresh, _ := trustChainClient(t, -time.Minute)
	if _, err := fresh.RefreshTokens(ctx, client.RefreshTokenRequest{}); errors.Is(err, client.ErrTrustChainExpired) {
		t.Errorf("RefreshTokens before expiry = %v, want a different error", err)
	}
}

// trustChainGatedCalls calls every Client method that sends a request to
// the authorization server or trusts what it signed, with arguments
// valid enough for the Trust Chain check (which comes first) to decide.
func trustChainGatedCalls(c *client.Client) map[string]error {
	ctx := context.Background()
	tokens := client.TokenSet{
		AccessToken: fapi.NewSecret("at"), TokenType: "DPoP",
		HasIDToken: true, IDToken: fapi.NewSecret("x.y.z"), IDTokenClaims: client.IDTokenClaims{Subject: "alice"},
		HasRefreshToken: true, RefreshToken: fapi.NewSecret("rt"),
	}
	callback := client.AuthorizationCallback{RawQuery: "code=c&state=s", Session: client.SessionHandle{}}
	errs := map[string]error{}
	_, errs["BeginAuthorization"] = c.BeginAuthorization(ctx, client.BeginAuthorizationRequest{Scope: []string{"openid"}})
	_, errs["HandleAuthorizationResponse"] = c.HandleAuthorizationResponse(ctx, callback)
	_, errs["CompleteAuthorization"] = c.CompleteAuthorization(ctx, callback)
	_, errs["ExchangeCode"] = c.ExchangeCode(ctx, client.ValidatedAuthorizationResponse{})
	_, errs["BeginBackchannelAuthentication"] = c.BeginBackchannelAuthentication(ctx, client.BeginBackchannelAuthenticationRequest{Scope: []string{"openid"}})
	_, errs["PollBackchannelAuthentication"] = c.PollBackchannelAuthentication(ctx, client.BackchannelAuthenticationSession{})
	_, errs["RequestClientCredentialsToken"] = c.RequestClientCredentialsToken(ctx, client.ClientCredentialsTokenRequest{Scope: []string{"accounts"}})
	_, errs["RefreshTokens"] = c.RefreshTokens(ctx, client.RefreshTokenRequest{Tokens: tokens})
	_, errs["FetchUserInfo"] = c.FetchUserInfo(ctx, tokens)
	errs["RevokeToken"] = c.RevokeToken(ctx, tokens)
	_, errs["VerifyIssuerJWS"] = c.VerifyIssuerJWS(ctx, "x.y.z")
	_, _, errs["ClientAttestationHeaders"] = c.ClientAttestationHeaders(ctx)
	return errs
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
