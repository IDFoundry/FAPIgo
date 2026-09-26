package server_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/idfoundry/fapigo/internal/clientassertion"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
	"github.com/idfoundry/fapigo/storage/memstore"
)

// These tests cover a store handing back a Request or Grant server can't
// decode — corrupted at rest, truncated, or written by an incompatible
// version. Every path must fail closed with server_error rather than
// act on a partial record.

var corruptPayload = json.RawMessage(`{"v":1,`)

func (f *fakeTransactionStore) corruptAll() {
	f.mu.Lock()
	defer f.mu.Unlock()
	for ref, record := range f.byReference {
		record.Request = corruptPayload
		f.byReference[ref] = record
	}
	for handle, pending := range f.byHandle {
		pending.interaction.Request = corruptPayload
		f.byHandle[handle] = pending
	}
}

func (f *fakeGrantStore) corruptAll() {
	f.mu.Lock()
	defer f.mu.Unlock()
	for hash, code := range f.byHash {
		code.Grant = corruptPayload
		f.byHash[hash] = code
	}
	for hash, tok := range f.refreshByHash {
		tok.Grant = corruptPayload
		f.refreshByHash[hash] = tok
	}
}

func TestBeginAuthorizationFailsClosedOnCorruptStoredRequest(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	pushResult, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
		HTTP: server.FormRequest{Parameters: plainFormParameters(t, h.clientAssertion(t), nil)},
	})
	if err != nil {
		t.Fatalf("PushAuthorizationRequest: %v", err)
	}
	h.transactions.corruptAll()

	action, err := h.server.BeginAuthorization(context.Background(), server.BeginAuthorizationRequest{
		RequestURI: pushResult.RequestURI.String(), ClientID: testClientID,
	})
	if err != nil {
		t.Fatalf("BeginAuthorization: %v", err)
	}
	local, ok := action.(server.LocalErrorResponse)
	if !ok {
		t.Fatalf("action = %T, want server.LocalErrorResponse", action)
	}
	if local.Error.Code() != server.ErrorServerError {
		t.Fatalf("error code = %q, want %q", local.Error.Code(), server.ErrorServerError)
	}
}

func TestCompleteAuthorizationFailsClosedOnCorruptStoredRequest(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	handle := beginInteraction(t, h)
	h.transactions.corruptAll()

	result, err := h.server.CompleteAuthorization(context.Background(), server.CompleteAuthorizationRequest{
		Handle: handle, Result: authorizeResult(t),
	})
	if err != nil {
		t.Fatalf("CompleteAuthorization: %v", err)
	}
	local, ok := result.(server.AuthorizationLocalError)
	if !ok {
		t.Fatalf("result = %T, want server.AuthorizationLocalError", result)
	}
	if local.Error.Code() != server.ErrorServerError {
		t.Fatalf("error code = %q, want %q", local.Error.Code(), server.ErrorServerError)
	}
}

func TestExchangeAuthorizationCodeFailsClosedOnCorruptStoredGrant(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	code := completeSuccessfulAuthorization(t, h, []string{"openid", "accounts"})
	h.grants.corruptAll()

	_, err := h.server.ExchangeAuthorizationCode(context.Background(), server.AuthorizationCodeExchangeRequest{
		HTTP:       server.FormRequest{Parameters: exchangeFormParams(h.clientAssertion(t), code, testRedirectURI, testCodeVerifier)},
		DPoPProofs: []string{createDPoPProof(t, generateKey(t), h.now)},
	})
	if code := serverErrorCode(t, err); code != server.ErrorServerError {
		t.Fatalf("error code = %q, want %q", code, server.ErrorServerError)
	}
}

func TestRefreshAccessTokenFailsClosedOnCorruptStoredGrant(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	first, dpopKey := exchangeForTokensWithOfflineAccess(t, h)
	h.grants.corruptAll()

	_, err := h.server.RefreshAccessToken(context.Background(), server.RefreshTokenRequest{
		HTTP:       server.FormRequest{Parameters: refreshFormParams(h.clientAssertion(t), first.RefreshToken.Reveal(), "")},
		DPoPProofs: []string{createDPoPProof(t, dpopKey, h.now)},
	})
	if code := serverErrorCode(t, err); code != server.ErrorServerError {
		t.Fatalf("error code = %q, want %q", code, server.ErrorServerError)
	}
}

// corruptingBackchannelStore wraps memstore, replacing whichever opaque
// value corruptRequest/corruptGrant select on the way back out.
type corruptingBackchannelStore struct {
	*memstore.BackchannelAuthenticationStore
	corruptRequest bool
	corruptGrant   bool
}

func (c *corruptingBackchannelStore) LookupBackchannelAuthentication(ctx context.Context, handleHash [32]byte) (storage.LookedUpBackchannelAuthentication, error) {
	looked, err := c.BackchannelAuthenticationStore.LookupBackchannelAuthentication(ctx, handleHash)
	if c.corruptRequest {
		looked.Request = corruptPayload
	}
	return looked, err
}

func (c *corruptingBackchannelStore) PollBackchannelAuthentication(ctx context.Context, poll storage.PollBackchannelAuthentication) (storage.PolledBackchannelAuthentication, error) {
	polled, err := c.BackchannelAuthenticationStore.PollBackchannelAuthentication(ctx, poll)
	if c.corruptRequest {
		polled.Request = corruptPayload
	}
	if c.corruptGrant {
		polled.Grant = corruptPayload
	}
	return polled, err
}

func TestCompleteBackchannelAuthenticationFailsClosedOnCorruptStoredRequest(t *testing.T) {
	store := &corruptingBackchannelStore{BackchannelAuthenticationStore: memstore.NewBackchannelAuthenticationStore(), corruptRequest: true}
	h := newHarnessWithBackchannelStore(t, store)
	_, err := completeBackchannelWithIDTokenScope(t, h)
	if code := serverErrorCode(t, err); code != server.ErrorServerError {
		t.Fatalf("error code = %q, want %q", code, server.ErrorServerError)
	}
}

func TestExchangeBackchannelAuthenticationFailsClosedOnCorruptStoredRecord(t *testing.T) {
	for name, store := range map[string]*corruptingBackchannelStore{
		"request": {corruptRequest: true},
		"grant":   {corruptGrant: true},
	} {
		t.Run(name, func(t *testing.T) {
			store.BackchannelAuthenticationStore = memstore.NewBackchannelAuthenticationStore()
			corruptRequest := store.corruptRequest
			store.corruptRequest = false // let the decision itself be recorded
			h := newHarnessWithBackchannelStore(t, store)
			required, err := completeBackchannelWithIDTokenScope(t, h)
			if err != nil {
				t.Fatalf("CompleteBackchannelAuthentication: %v", err)
			}
			store.corruptRequest = corruptRequest

			_, err = h.server.ExchangeBackchannelAuthentication(context.Background(), server.BackchannelTokenExchangeRequest{
				HTTP: server.FormRequest{Parameters: []server.FormParameter{
					formParam("client_assertion", h.clientAssertion(t)),
					formParam("client_assertion_type", clientassertion.AssertionType),
					formParam("grant_type", server.CIBAGrantType),
					formParam("auth_req_id", required.AuthReqID.String()),
				}},
				DPoPProofs: []string{createDPoPProof(t, generateKey(t), h.now)},
			})
			if code := serverErrorCode(t, err); code != server.ErrorServerError {
				t.Fatalf("error code = %q, want %q", code, server.ErrorServerError)
			}
		})
	}
}

func completeBackchannelWithIDTokenScope(t *testing.T, h harness) (server.BackchannelInteractionRequired, error) {
	t.Helper()
	required := beginBackchannel(t, h, standardBackchannelParams(t))
	err := h.server.CompleteBackchannelAuthentication(context.Background(), server.CompleteBackchannelAuthenticationRequest{
		Handle: required.Handle, Result: authorizeResult(t),
	})
	return required, err
}

// failingIdentityClaims is an IdentityClaimsSource whose backend is
// unavailable.
type failingIdentityClaims struct{}

func (failingIdentityClaims) ResolveIdentityClaims(context.Context, string, []string) (map[string]json.RawMessage, error) {
	return nil, errors.New("identity backend unavailable")
}

func TestExchangeAuthorizationCodeFailsWhenIdentityClaimsSourceFails(t *testing.T) {
	h := newHarnessWithIdentityClaims(t, failingIdentityClaims{})
	code := completeAuthorizationWithClaims(t, h, `{"id_token":{"name":null}}`)

	_, err := h.server.ExchangeAuthorizationCode(context.Background(), server.AuthorizationCodeExchangeRequest{
		HTTP:       server.FormRequest{Parameters: exchangeFormParams(h.clientAssertion(t), code, testRedirectURI, testCodeVerifier)},
		DPoPProofs: []string{createDPoPProof(t, generateKey(t), h.now)},
	})
	if code := serverErrorCode(t, err); code != server.ErrorServerError {
		t.Fatalf("error code = %q, want %q", code, server.ErrorServerError)
	}
}
