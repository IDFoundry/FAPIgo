package server_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/clientassertion"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/resource"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage/memstore"
)

// TestRevokeTokenRevokesTheCIBAGrant: revoking a refresh token from the
// CIBA flow, with no GrantID, revokes the grant it came from too, as for
// the authorization code flow, so the access token issued with it stops
// working at a resource server that reads the revocation store (RFC 7009
// §2.1).
func TestRevokeTokenRevokesTheCIBAGrant(t *testing.T) {
	sink := &fakeRevocationSink{}
	var cfg server.Config
	var deps server.Dependencies
	h := newHarnessWithBackchannelOptions(t, memstore.NewBackchannelAuthenticationStore(), func(c *server.Config) {
		revocation, err := fapi.ParseEndpointURL(testRevocationEndpoint)
		if err != nil {
			t.Fatal(err)
		}
		c.Endpoints.Revocation = revocation
		cfg = *c
	}, func(d *server.Dependencies) {
		d.Revocation = sink
		deps = *d
	})

	params := standardBackchannelParams(t)
	params["scope"] = json.RawMessage(`"openid accounts offline_access"`)
	required := beginBackchannel(t, h, params)
	subject, err := server.NewSubjectID("user-1")
	if err != nil {
		t.Fatal(err)
	}
	authenticated, err := server.NewAuthenticatedSubject(subject)
	if err != nil {
		t.Fatal(err)
	}
	authCtx, err := server.NewAuthenticationContext(h.now, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.server.CompleteBackchannelAuthentication(context.Background(), server.CompleteBackchannelAuthenticationRequest{
		Handle: required.Handle,
		Result: server.Authorize(authenticated, authCtx, server.GrantedAuthorization{Scope: []string{"openid", "accounts", "offline_access"}}),
	}); err != nil {
		t.Fatalf("CompleteBackchannelAuthentication: %v", err)
	}
	dpopKey := generateKey(t)
	tokens, err := h.server.ExchangeBackchannelAuthentication(context.Background(), server.BackchannelTokenExchangeRequest{
		HTTP: server.FormRequest{Parameters: []server.FormParameter{
			formParam("client_assertion", h.clientAssertion(t)),
			formParam("client_assertion_type", clientassertion.AssertionType),
			formParam("grant_type", server.CIBAGrantType),
			formParam("auth_req_id", required.AuthReqID.String()),
		}},
		DPoPProofs: []string{createDPoPProof(t, dpopKey, h.now)},
	})
	if err != nil || !tokens.HasRefreshToken {
		t.Fatalf("ExchangeBackchannelAuthentication = %v (refresh token %v), want tokens with a refresh token", err, tokens.HasRefreshToken)
	}

	issuerKeys, err := keys.NewLocalIssuerKeys(cfg.Issuer, deps.Keys)
	if err != nil {
		t.Fatal(err)
	}
	jwt, err := resource.NewJWTAccessTokens(issuerKeys, cfg.Issuer, testIssuer, fapi.ES256, 10*time.Minute, 4)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := resource.NewVerifier(resource.Config{
		Limits:    resource.Limits{MaxDPoPProofAge: time.Minute, MaxClockSkew: 5 * time.Second},
		Assurance: resource.AssuranceDevelopment,
	}, resource.Dependencies{
		AccessTokens: jwt,
		Replay:       memstore.NewReplayStore(),
		Revocation:   revocationCheckerFromSink{sink: sink},
		Clock:        fixedClock{now: h.now},
	})
	if err != nil {
		t.Fatalf("resource.NewVerifier: %v", err)
	}
	accessToken := tokens.AccessToken.Reveal()
	if err := verifyWithDPoP(t, verifier, dpopKey, accessToken, h.now); err != nil {
		t.Fatalf("Verify(before revocation): %v", err)
	}

	res, err := h.server.RevokeToken(context.Background(), server.TokenRevocationRequest{
		HTTP: server.FormRequest{Parameters: []server.FormParameter{
			formParam("client_assertion", h.clientAssertion(t)),
			formParam("client_assertion_type", clientassertion.AssertionType),
			formParam("token", tokens.RefreshToken.Reveal()),
		}},
	})
	if err != nil || !res.Revoked {
		t.Fatalf("RevokeToken = %+v, %v; want it revoked", res, err)
	}
	requireInvalidToken(t, verifyWithDPoP(t, verifier, dpopKey, accessToken, h.now), "CIBA access token after its refresh token was revoked")
}
