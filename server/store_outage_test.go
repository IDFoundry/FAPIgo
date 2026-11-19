package server_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/clientassertion"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
	"github.com/idfoundry/fapigo/storage/memstore"
)

// These tests cover a store that couldn't answer (an error wrapping
// storage.ErrStoreUnavailable) where the store's answer would be a
// client error: every such path answers 500 server_error, never the
// invalid_grant, invalid_request_uri, invalid_client or 200 that tells
// the client its refresh token, code, request_uri, credentials or
// revocation is settled. A client discards a refresh token answered
// invalid_grant (RFC 6749 §5.2).

var errStoreDown = fmt.Errorf("db: %w", storage.ErrStoreUnavailable)

// withDependencies is h with its server rebuilt over h's Config and
// Dependencies, changed by change: the same stores, so what h's server
// issued is still there for the rebuilt one to fail on.
func withDependencies(t *testing.T, h harness, change func(*server.Dependencies)) harness {
	t.Helper()
	return rebuilt(t, h, func(*server.Config) {}, change)
}

// rebuilt is h with its server rebuilt over h's Config and Dependencies,
// changed by changeConfig and changeDeps.
func rebuilt(t *testing.T, h harness, changeConfig func(*server.Config), changeDeps func(*server.Dependencies)) harness {
	t.Helper()
	cfg, deps := h.cfg, h.deps
	changeConfig(&cfg)
	changeDeps(&deps)
	srv, err := server.New(cfg, deps)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	h.server, h.cfg, h.deps = srv, cfg, deps
	return h
}

// downGrants is a GrantStore whose redemptions can't answer.
type downGrants struct{ storage.GrantStore }

func (downGrants) RedeemAuthorizationCode(context.Context, storage.AuthorizationCodeRedemption) (storage.RedeemedAuthorizationCode, error) {
	return storage.RedeemedAuthorizationCode{}, errStoreDown
}

func (downGrants) RedeemRefreshToken(context.Context, storage.RefreshTokenRedemption) (storage.RedeemedRefreshToken, error) {
	return storage.RedeemedRefreshToken{}, errStoreDown
}

// downTransactions is a TransactionStore whose redemptions can't answer.
type downTransactions struct{ storage.TransactionStore }

func (downTransactions) BeginAuthorization(context.Context, storage.BeginAuthorizationTransaction) (storage.PushedAuthorizationRequest, error) {
	return storage.PushedAuthorizationRequest{}, errStoreDown
}

func (downTransactions) CompleteAuthorization(context.Context, storage.CompleteAuthorizationTransaction) (storage.CompletedInteraction, error) {
	return storage.CompletedInteraction{}, errStoreDown
}

func TestStoreOutageAtRefreshKeepsTheRefreshToken(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	first, dpopKey := exchangeForTokensWithOfflineAccess(t, h)
	refresh := func(h harness) error {
		_, err := h.server.RefreshAccessToken(context.Background(), server.RefreshTokenRequest{
			HTTP:       server.FormRequest{Parameters: refreshFormParams(h.clientAssertion(t), first.RefreshToken.Reveal(), "")},
			DPoPProofs: []string{createDPoPProof(t, dpopKey, h.now)},
		})
		return err
	}
	down := withDependencies(t, h, func(d *server.Dependencies) { d.Grants = downGrants{d.Grants} })
	checkServerError(t, refresh(down), server.ErrorServerError, 500)
	if err := refresh(h); err != nil {
		t.Fatalf("RefreshAccessToken once the store answers: %v", err)
	}
}

func TestStoreOutageAtCodeExchangeKeepsTheCode(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	code := completeSuccessfulAuthorization(t, h, []string{"openid", "accounts"})
	exchange := func(h harness) error {
		_, err := h.server.ExchangeAuthorizationCode(context.Background(), server.AuthorizationCodeExchangeRequest{
			HTTP:       server.FormRequest{Parameters: exchangeFormParams(h.clientAssertion(t), code, testRedirectURI, testCodeVerifier)},
			DPoPProofs: []string{createDPoPProof(t, generateKey(t), h.now)},
		})
		return err
	}
	down := withDependencies(t, h, func(d *server.Dependencies) { d.Grants = downGrants{d.Grants} })
	checkServerError(t, exchange(down), server.ErrorServerError, 500)
	if err := exchange(h); err != nil {
		t.Fatalf("ExchangeAuthorizationCode once the store answers: %v", err)
	}
}

// TestStoreOutageAtRevocationIsNotRevoked: RFC 7009 §2.2's 200 tells the
// client the token was revoked, so a store that couldn't say whether
// the refresh token exists is a 500, and the token still works.
func TestStoreOutageAtRevocationIsNotRevoked(t *testing.T) {
	revocation, err := fapi.ParseEndpointURL(testRevocationEndpoint)
	if err != nil {
		t.Fatal(err)
	}
	h := rebuilt(t, newHarness(t, server.ProfileFAPISecurity, true), func(c *server.Config) { c.Endpoints.Revocation = revocation }, func(*server.Dependencies) {})
	tokens, dpopKey := exchangeForTokensWithOfflineAccess(t, h)
	down := withDependencies(t, h, func(d *server.Dependencies) { d.Grants = downGrants{d.Grants} })
	_, err = down.server.RevokeToken(context.Background(), server.TokenRevocationRequest{
		HTTP: server.FormRequest{Parameters: []server.FormParameter{
			formParam("client_assertion", h.clientAssertion(t)),
			formParam("client_assertion_type", clientassertion.AssertionType),
			formParam("token", tokens.RefreshToken.Reveal()),
		}},
	})
	checkServerError(t, err, server.ErrorServerError, 500)
	if _, err := h.server.RefreshAccessToken(context.Background(), server.RefreshTokenRequest{
		HTTP:       server.FormRequest{Parameters: refreshFormParams(h.clientAssertion(t), tokens.RefreshToken.Reveal(), "")},
		DPoPProofs: []string{createDPoPProof(t, dpopKey, h.now)},
	}); err != nil {
		t.Fatalf("RefreshAccessToken after the failed revocation: %v", err)
	}
}

func TestStoreOutageAtBeginAuthorization(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	pushed, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
		HTTP: server.FormRequest{Parameters: plainFormParameters(t, h.clientAssertion(t), nil)},
	})
	if err != nil {
		t.Fatalf("PushAuthorizationRequest: %v", err)
	}
	down := withDependencies(t, h, func(d *server.Dependencies) { d.Transactions = downTransactions{d.Transactions} })
	action, err := down.server.BeginAuthorization(context.Background(), server.BeginAuthorizationRequest{
		RequestURI: pushed.RequestURI.String(), ClientID: testClientID,
	})
	if err != nil {
		t.Fatalf("BeginAuthorization: %v", err)
	}
	local, ok := action.(server.LocalErrorResponse)
	if !ok {
		t.Fatalf("action = %T, want server.LocalErrorResponse", action)
	}
	checkServerError(t, local.Error, server.ErrorServerError, 500)
}

func TestStoreOutageAtCompleteAuthorization(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	handle := beginInteraction(t, h)
	down := withDependencies(t, h, func(d *server.Dependencies) { d.Transactions = downTransactions{d.Transactions} })
	result, err := down.server.CompleteAuthorization(context.Background(), server.CompleteAuthorizationRequest{
		Handle: handle, Result: authorizeResult(t),
	})
	if err != nil {
		t.Fatalf("CompleteAuthorization: %v", err)
	}
	local, ok := result.(server.AuthorizationLocalError)
	if !ok {
		t.Fatalf("result = %T, want server.AuthorizationLocalError", result)
	}
	checkServerError(t, local.Error, server.ErrorServerError, 500)
}

// downBackchannel is a memstore BackchannelAuthenticationStore whose
// lookups or decisions can't answer while lookup or decide is set, and
// whose next failPolls polls can't.
type downBackchannel struct {
	*memstore.BackchannelAuthenticationStore
	lookup, decide bool
	failPolls      int
}

func (d *downBackchannel) LookupBackchannelAuthentication(ctx context.Context, handleHash [32]byte) (storage.LookedUpBackchannelAuthentication, error) {
	if d.lookup {
		return storage.LookedUpBackchannelAuthentication{}, errStoreDown
	}
	return d.BackchannelAuthenticationStore.LookupBackchannelAuthentication(ctx, handleHash)
}

func (d *downBackchannel) DecideBackchannelAuthentication(ctx context.Context, decision storage.DecideBackchannelAuthentication) (storage.DecidedBackchannelAuthentication, error) {
	if d.decide {
		return storage.DecidedBackchannelAuthentication{}, errStoreDown
	}
	return d.BackchannelAuthenticationStore.DecideBackchannelAuthentication(ctx, decision)
}

func (d *downBackchannel) PollBackchannelAuthentication(ctx context.Context, poll storage.PollBackchannelAuthentication) (storage.PolledBackchannelAuthentication, error) {
	if d.failPolls > 0 {
		d.failPolls--
		return storage.PolledBackchannelAuthentication{}, errStoreDown
	}
	return d.BackchannelAuthenticationStore.PollBackchannelAuthentication(ctx, poll)
}

func TestStoreOutageAtCompleteBackchannelAuthentication(t *testing.T) {
	for name, store := range map[string]*downBackchannel{
		"lookup":   {lookup: true},
		"decision": {decide: true},
	} {
		t.Run(name, func(t *testing.T) {
			store.BackchannelAuthenticationStore = memstore.NewBackchannelAuthenticationStore()
			h := newHarnessWithBackchannelStore(t, store)
			_, err := completeBackchannelWithIDTokenScope(t, h)
			checkServerError(t, err, server.ErrorServerError, 500)
		})
	}
}

// TestStoreOutageAtBackchannelPollKeepsTheRequest: an auth_req_id bound
// to a DPoP key is polled under that key first. A store that couldn't
// answer that poll isn't polled again without the key, which, once it
// answers, would miss the request and call it unknown.
func TestStoreOutageAtBackchannelPollKeepsTheRequest(t *testing.T) {
	store := &downBackchannel{BackchannelAuthenticationStore: memstore.NewBackchannelAuthenticationStore()}
	h := newHarnessWithBackchannelStore(t, store)
	bound := generateKey(t)
	params := standardBackchannelParams(t)
	params["dpop_jkt"] = jsonRaw(t, dpopThumbprint(t, bound))
	required := beginBackchannel(t, h, params)
	approveBackchannel(t, h, required.Handle)

	store.failPolls = 1
	checkServerError(t, exchangeBackchannelWithKey(t, h, required.AuthReqID.String(), bound), server.ErrorServerError, 500)
	if err := exchangeBackchannelWithKey(t, h, required.AuthReqID.String(), bound); err != nil {
		t.Fatalf("ExchangeBackchannelAuthentication once the store answers: %v", err)
	}
}

// downReplay is a ReplayStore that can't answer for namespace once it has
// recorded after uses there.
type downReplay struct {
	storage.ReplayStore
	namespace storage.ReplayNamespace
	after     int
}

func (d *downReplay) UseOnce(ctx context.Context, use storage.ReplayUse) error {
	if use.Namespace == d.namespace {
		if d.after == 0 {
			return errStoreDown
		}
		d.after--
	}
	return d.ReplayStore.UseOnce(ctx, use)
}

// TestStoreOutageAtReplayCheck: a replay store that couldn't answer
// isn't a replayed DPoP proof, client assertion, request object or
// Client Attestation PoP.
func TestStoreOutageAtReplayCheck(t *testing.T) {
	const (
		clientSignedJWT storage.ReplayNamespace = "server:client-signed-jwt"
		dpopProof       storage.ReplayNamespace = "server:dpop"
		attestationPoP  storage.ReplayNamespace = "server:client-attestation-pop"
	)
	replayDown := func(namespace storage.ReplayNamespace, after int) func(*server.Dependencies) {
		return func(d *server.Dependencies) {
			d.Replay = &downReplay{ReplayStore: d.Replay, namespace: namespace, after: after}
		}
	}
	t.Run("DPoP proof", func(t *testing.T) {
		h := newHarness(t, server.ProfileFAPISecurity, true)
		first, dpopKey := exchangeForTokensWithOfflineAccess(t, h)
		down := withDependencies(t, h, replayDown(dpopProof, 0))
		_, err := down.server.RefreshAccessToken(context.Background(), server.RefreshTokenRequest{
			HTTP:       server.FormRequest{Parameters: refreshFormParams(h.clientAssertion(t), first.RefreshToken.Reveal(), "")},
			DPoPProofs: []string{createDPoPProof(t, dpopKey, h.now)},
		})
		checkServerError(t, err, server.ErrorServerError, 500)
	})
	t.Run("client assertion", func(t *testing.T) {
		h := withDependencies(t, newHarness(t, server.ProfileFAPISecurity, true), replayDown(clientSignedJWT, 0))
		_, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
			HTTP: server.FormRequest{Parameters: plainFormParameters(t, h.clientAssertion(t), nil)},
		})
		checkServerError(t, err, server.ErrorServerError, 500)
	})
	t.Run("request object", func(t *testing.T) {
		// The client assertion is recorded first.
		h := withDependencies(t, newHarness(t, server.ProfileFAPISecurity, true), replayDown(clientSignedJWT, 1))
		checkServerError(t, pushRequestObject(t, h, h.requestObject(t, standardAuthParams(t))), server.ErrorServerError, 500)
	})
	t.Run("backchannel authentication request", func(t *testing.T) {
		// The client assertion is recorded first.
		h := withDependencies(t, newHarnessWithBackchannelStore(t, memstore.NewBackchannelAuthenticationStore()), replayDown(clientSignedJWT, 1))
		action, err := h.server.BeginBackchannelAuthentication(context.Background(), server.BeginBackchannelAuthenticationRequest{
			HTTP: server.FormRequest{Parameters: backchannelFormParams(h.clientAssertion(t), h.backchannelRequestObject(t, standardBackchannelParams(t)))},
		})
		if err != nil {
			t.Fatalf("BeginBackchannelAuthentication: %v", err)
		}
		local, ok := action.(server.BackchannelAuthenticationLocalError)
		if !ok {
			t.Fatalf("action = %T, want server.BackchannelAuthenticationLocalError", action)
		}
		checkServerError(t, local.Error, server.ErrorServerError, 500)
	})
	t.Run("Client Attestation PoP", func(t *testing.T) {
		attesterKey := generateKey(t)
		instanceKey := generateKey(t)
		h := withDependencies(t, newHarnessWithAttestationClientCredentials(t, attesterKey), replayDown(attestationPoP, 0))
		_, err := h.server.RequestClientCredentialsToken(context.Background(), server.ClientCredentialsTokenRequest{
			HTTP:                  server.FormRequest{Parameters: attestationClientCredentialsFormParams("accounts")},
			ClientAttestations:    []string{createAttestationHeader(t, attesterKey, testClientID.String(), &instanceKey.PublicKey, h.now, time.Hour)},
			ClientAttestationPoPs: []string{createAttestationPoPHeader(t, instanceKey, testClientID.String(), testIssuer, "jti-1", h.now)},
			DPoPProofs:            []string{createDPoPProof(t, generateKey(t), h.now)},
		})
		checkServerError(t, err, server.ErrorServerError, 500)
	})
}
