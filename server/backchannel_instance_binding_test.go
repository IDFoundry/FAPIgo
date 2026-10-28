package server_test

import (
	"context"
	"crypto/ecdsa"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
	"github.com/idfoundry/fapigo/storage/memstore"
)

// newBackchannelInstanceBindingHarness registers testClientID for CIBA,
// authenticating by private_key_jwt or Client Attestation: a wallet app
// whose every installation shares the client_id.
func newBackchannelInstanceBindingHarness(t *testing.T, attesterKey *ecdsa.PrivateKey) harness {
	t.Helper()
	return newHarnessWithBackchannelOptions(t, memstore.NewBackchannelAuthenticationStore(), func(cfg *server.Config) {
		cfg.AttestationBasedClientAuthentication = true
		cfg.Algorithms.ClientAttestation = server.AlgorithmSet{fapi.ES256}
		cfg.Algorithms.ClientAttestationPoP = server.AlgorithmSet{fapi.ES256}
		cfg.Limits.MaxClientAttestationLifetime = time.Hour
		cfg.Limits.MaxClientAttestationPoPAge = time.Minute
	}, func(deps *server.Dependencies) {
		client, err := storage.NewRegisteredClient(storage.RegisteredClientConfig{
			ID:                         testClientID,
			RedirectURIs:               []fapi.RegisteredRedirectURI{testRedirectURI},
			ClientAuthMethods:          []storage.ClientAuthMethod{storage.ClientAuthMethodPrivateKeyJWT, storage.ClientAuthMethodAttestation},
			ClientAssertionAlgorithm:   fapi.ES256,
			ExpectedAttesterIssuer:     testAttesterIssuer,
			ClientAttestationAlgorithm: fapi.ES256,
			AllowedScopes:              []string{"openid", "accounts", "offline_access"},
			BackchannelAuthenticationRequestAlgorithm: fapi.ES256,
		})
		if err != nil {
			t.Fatalf("NewRegisteredClient: %v", err)
		}
		deps.Clients.(*fakeClientRepository).clients[testClientID] = client
		deps.AttesterTrust = registeredAttesterTrust(fapi.ES256, &attesterKey.PublicKey)
	})
}

// beginBackchannel makes a CIBA request authenticated by i's
// attestation.
func (i *attestedInstance) beginBackchannel() server.BackchannelInteractionRequired {
	t := i.t
	t.Helper()
	params := standardBackchannelParams(t)
	params["scope"] = jsonRaw(t, "openid accounts offline_access")
	attestations, pops := i.headers()
	action, err := i.h.server.BeginBackchannelAuthentication(context.Background(), server.BeginBackchannelAuthenticationRequest{
		HTTP:               server.FormRequest{Parameters: []server.FormParameter{formParam("client_id", testClientID.String()), formParam("request", i.h.backchannelRequestObject(t, params))}},
		ClientAttestations: attestations, ClientAttestationPoPs: pops,
	})
	if err != nil {
		t.Fatalf("BeginBackchannelAuthentication: %v", err)
	}
	required, ok := action.(server.BackchannelInteractionRequired)
	if !ok {
		t.Fatalf("BeginBackchannelAuthentication = %T, want BackchannelInteractionRequired", action)
	}
	return required
}

// exchangeBackchannel polls authReqID authenticated by i's attestation,
// with a DPoP proof from dpopKey.
func (i *attestedInstance) exchangeBackchannel(authReqID string, dpopKey *ecdsa.PrivateKey) (server.TokenResult, error) {
	t := i.t
	t.Helper()
	attestations, pops := i.headers()
	return i.h.server.ExchangeBackchannelAuthentication(context.Background(), server.BackchannelTokenExchangeRequest{
		HTTP: server.FormRequest{Parameters: []server.FormParameter{
			formParam("client_id", testClientID.String()),
			formParam("grant_type", server.CIBAGrantType),
			formParam("auth_req_id", authReqID),
		}},
		DPoPProofs:         []string{createDPoPProof(t, dpopKey, i.h.now)},
		ClientAttestations: attestations, ClientAttestationPoPs: pops,
	})
}

// TestBackchannelAuthReqIDBoundToAttestedInstance: an auth_req_id issued
// to one installation of a wallet app, presented by another genuine
// installation of it (same client_id, its own instance key), is
// invalid_grant, before and after approval, and neither poll spends the
// approval: the installation that made the request still redeems it.
func TestBackchannelAuthReqIDBoundToAttestedInstance(t *testing.T) {
	attesterKey := generateKey(t)
	h := newBackchannelInstanceBindingHarness(t, attesterKey)
	requester := &attestedInstance{t: t, h: h, attesterKey: attesterKey, instanceKey: generateKey(t)}
	other := &attestedInstance{t: t, h: h, attesterKey: attesterKey, instanceKey: generateKey(t)}

	required := requester.beginBackchannel()
	authReqID := required.AuthReqID.String()
	requireInvalidGrant(t, ignoreResult(other.exchangeBackchannel(authReqID, generateKey(t))))
	approveBackchannel(t, h, required.Handle)
	requireInvalidGrant(t, ignoreResult(other.exchangeBackchannel(authReqID, generateKey(t))))

	result, err := requester.exchangeBackchannel(authReqID, generateKey(t))
	if err != nil {
		t.Fatalf("requesting instance's poll: %v", err)
	}
	if result.AccessToken.Reveal() == "" {
		t.Fatal("requesting instance's poll issued no access token")
	}
}

// TestBackchannelWrongDPoPKeyDoesNotSpendApproval: a poll with a DPoP
// key other than the request's dpop_jkt is invalid_grant and doesn't
// spend the approval: the poll with the bound key afterwards still
// issues tokens.
func TestBackchannelWrongDPoPKeyDoesNotSpendApproval(t *testing.T) {
	bound := generateKey(t)
	h := newHarnessWithBackchannelStore(t, memstore.NewBackchannelAuthenticationStore())
	params := standardBackchannelParams(t)
	params["dpop_jkt"] = jsonRaw(t, dpopThumbprint(t, bound))
	required := beginBackchannel(t, h, params)
	authReqID := required.AuthReqID.String()

	approveBackchannel(t, h, required.Handle)
	requireInvalidGrant(t, exchangeBackchannelWithKey(t, h, authReqID, generateKey(t)))
	if err := exchangeBackchannelWithKey(t, h, authReqID, bound); err != nil {
		t.Fatalf("bound-key poll after a wrong-key poll: %v", err)
	}
}

func ignoreResult(_ server.TokenResult, err error) error { return err }
