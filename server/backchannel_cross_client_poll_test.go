package server_test

import (
	"context"
	"crypto"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/clientassertion"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
	"github.com/idfoundry/fapigo/storage/memstore"
)

// TestExchangeBackchannelAuthenticationByAnotherClientLeavesTheApproval
// covers a leaked auth_req_id presented by another registered CIBA
// client: it is refused, and the store (told the polling client) leaves
// the approval unspent, so the client it was issued to still collects
// its tokens.
func TestExchangeBackchannelAuthenticationByAnotherClientLeavesTheApproval(t *testing.T) {
	const otherClientID fapi.ClientID = "rp-other"
	otherKey := generateKey(t)
	h := newHarnessWithBackchannelOptions(t, memstore.NewBackchannelAuthenticationStore(), nil, func(d *server.Dependencies) {
		other, err := storage.NewRegisteredClient(storage.RegisteredClientConfig{
			ID:                       otherClientID,
			RedirectURIs:             []fapi.RegisteredRedirectURI{testRedirectURI},
			ClientAssertionAlgorithm: fapi.ES256,
			AllowedScopes:            []string{"openid", "accounts", "offline_access"},
			BackchannelAuthenticationRequestAlgorithm: fapi.ES256,
		})
		if err != nil {
			t.Fatalf("NewRegisteredClient: %v", err)
		}
		d.Clients.(*fakeClientRepository).clients[otherClientID] = other
		d.ClientKeys.(*fakeClientKeySource).keysByClient[otherClientID] = []keys.VerificationKey{{Algorithm: fapi.ES256, PublicKey: &otherKey.PublicKey}}
	})
	required := beginBackchannel(t, h, standardBackchannelParams(t))
	if err := h.server.CompleteBackchannelAuthentication(context.Background(), server.CompleteBackchannelAuthenticationRequest{
		Handle: required.Handle, Result: authorizeWithGrantID(t, h.now, ""),
	}); err != nil {
		t.Fatalf("CompleteBackchannelAuthentication: %v", err)
	}

	exchange := func(clientID fapi.ClientID, signer crypto.Signer) error {
		assertion, err := clientassertion.CreateAssertion(clientassertion.AssertionRequest{
			Signer: signer, Algorithm: fapi.ES256, ClientID: clientID.String(), Audience: testIssuer,
			Now: h.now, Lifetime: 30 * time.Second,
		})
		if err != nil {
			t.Fatalf("CreateAssertion: %v", err)
		}
		_, err = h.server.ExchangeBackchannelAuthentication(context.Background(), server.BackchannelTokenExchangeRequest{
			HTTP: server.FormRequest{Parameters: []server.FormParameter{
				formParam("client_assertion", assertion),
				formParam("client_assertion_type", clientassertion.AssertionType),
				formParam("grant_type", server.CIBAGrantType),
				formParam("auth_req_id", required.AuthReqID.String()),
			}},
			DPoPProofs: []string{createDPoPProof(t, generateKey(t), h.now)},
		})
		return err
	}
	if code := serverErrorCode(t, exchange(otherClientID, otherKey)); code != server.ErrorInvalidGrant {
		t.Fatalf("exchange by another client = code %q, want invalid_grant", code)
	}
	if err := exchange(testClientID, h.key); err != nil {
		t.Fatalf("exchange by the client it was issued to, after another client's attempt: %v, want tokens", err)
	}
}
