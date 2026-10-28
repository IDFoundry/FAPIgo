package server_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/idfoundry/fapigo/internal/clientassertion"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
	"github.com/idfoundry/fapigo/storage/memstore"
)

// withoutIssuer is record as a server before v0.58.0 wrote it: without
// the "iss" every record now carries.
func withoutIssuer(t *testing.T, record json.RawMessage) json.RawMessage {
	t.Helper()
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(record, &fields); err != nil {
		t.Fatal(err)
	}
	if _, ok := fields["iss"]; !ok {
		t.Fatalf("record %s has no issuer to remove", record)
	}
	delete(fields, "iss")
	stripped, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	return stripped
}

// TestRecordsWithoutAnIssuerAreUnknown covers records written before
// records carried their server's issuer: no server can tell them from
// another issuer's, so each is refused as unknown — an authorization
// code, a refresh token (RevokeToken redeems one the same way), and a
// request_uri.
func TestRecordsWithoutAnIssuerAreUnknown(t *testing.T) {
	t.Run("authorization code", refuseCodeWithoutIssuer)
	t.Run("refresh token", refuseRefreshTokenWithoutIssuer)
	t.Run("request_uri", refuseRequestURIWithoutIssuer)
}

func refuseCodeWithoutIssuer(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, server.ProfileFAPISecurity, true)
	code := completeSuccessfulAuthorization(t, h, []string{"openid", "accounts"})
	h.grants.mu.Lock()
	for hash, rec := range h.grants.byHash {
		rec.Grant = withoutIssuer(t, rec.Grant)
		h.grants.byHash[hash] = rec
	}
	h.grants.mu.Unlock()
	_, err := h.server.ExchangeAuthorizationCode(ctx, server.AuthorizationCodeExchangeRequest{
		HTTP:       server.FormRequest{Parameters: exchangeFormParams(h.clientAssertion(t), code, testRedirectURI, testCodeVerifier)},
		DPoPProofs: []string{createDPoPProof(t, generateKey(t), h.now)},
	})
	if code := serverErrorCode(t, err); code != server.ErrorInvalidGrant {
		t.Fatalf("redeeming a code without an issuer: error code %q, want %q", code, server.ErrorInvalidGrant)
	}
}

func refuseRefreshTokenWithoutIssuer(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, server.ProfileFAPISecurity, true)
	code := completeSuccessfulAuthorization(t, h, []string{"openid", "accounts", "offline_access"})
	tokens, err := h.server.ExchangeAuthorizationCode(ctx, server.AuthorizationCodeExchangeRequest{
		HTTP:       server.FormRequest{Parameters: exchangeFormParams(h.clientAssertion(t), code, testRedirectURI, testCodeVerifier)},
		DPoPProofs: []string{createDPoPProof(t, generateKey(t), h.now)},
	})
	if err != nil || !tokens.HasRefreshToken {
		t.Fatalf("ExchangeAuthorizationCode = %v (refresh token %v)", err, tokens.HasRefreshToken)
	}
	h.grants.mu.Lock()
	for hash, rec := range h.grants.refreshByHash {
		rec.Grant = withoutIssuer(t, rec.Grant)
		h.grants.refreshByHash[hash] = rec
	}
	h.grants.mu.Unlock()
	_, err = h.server.RefreshAccessToken(ctx, server.RefreshTokenRequest{
		HTTP:       server.FormRequest{Parameters: refreshFormParams(h.clientAssertion(t), tokens.RefreshToken.Reveal(), "")},
		DPoPProofs: []string{createDPoPProof(t, generateKey(t), h.now)},
	})
	if code := serverErrorCode(t, err); code != server.ErrorInvalidGrant {
		t.Fatalf("refreshing a refresh token without an issuer: error code %q, want %q", code, server.ErrorInvalidGrant)
	}
}

// withoutKind is record as a server wrote it before records carried
// their kind.
func withoutKind(t *testing.T, record json.RawMessage) json.RawMessage {
	t.Helper()
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(record, &fields); err != nil {
		t.Fatal(err)
	}
	if _, ok := fields["kind"]; !ok {
		t.Fatalf("record %s has no kind to remove", record)
	}
	delete(fields, "kind")
	stripped, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	return stripped
}

// TestRefreshTokenWithoutAKindStillRefreshes covers a refresh token
// stored before records carried their kind: it carries none of an
// authorization code's fields, so it is still redeemed as a refresh
// token, rather than every live refresh token being orphaned on upgrade.
func TestRefreshTokenWithoutAKindStillRefreshes(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	tokens, _ := exchangeForTokensWithOfflineAccess(t, h)
	h.grants.mu.Lock()
	for hash, rec := range h.grants.refreshByHash {
		rec.Grant = withoutKind(t, rec.Grant)
		h.grants.refreshByHash[hash] = rec
	}
	h.grants.mu.Unlock()
	if _, err := refreshWith(t, h, tokens.RefreshToken.Reveal(), ""); err != nil {
		t.Fatalf("refreshing a refresh token without a kind: %v", err)
	}
}

func refuseRequestURIWithoutIssuer(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, server.ProfileFAPISecurity, true)
	pushed, err := h.server.PushAuthorizationRequest(ctx, server.PushAuthorizationRequest{
		HTTP: server.FormRequest{Parameters: plainFormParameters(t, h.clientAssertion(t), nil)},
	})
	if err != nil {
		t.Fatalf("PushAuthorizationRequest: %v", err)
	}
	h.transactions.mu.Lock()
	for ref, rec := range h.transactions.byReference {
		rec.Request = withoutIssuer(t, rec.Request)
		h.transactions.byReference[ref] = rec
	}
	h.transactions.mu.Unlock()
	action, err := h.server.BeginAuthorization(ctx, server.BeginAuthorizationRequest{
		RequestURI: pushed.RequestURI.String(), ClientID: testClientID,
	})
	if err != nil {
		t.Fatalf("BeginAuthorization: %v", err)
	}
	local, ok := action.(server.LocalErrorResponse)
	if !ok || local.Error.Code() != server.ErrorInvalidRequestURI {
		t.Fatalf("beginning a request_uri without an issuer = %#v, want a local invalid_request_uri", action)
	}
}

// legacyGrantStore answers every poll with the approved grant as a
// server before v0.58.0 recorded it, without an issuer.
type legacyGrantStore struct {
	*memstore.BackchannelAuthenticationStore
	t *testing.T
}

func (s legacyGrantStore) PollBackchannelAuthentication(ctx context.Context, poll storage.PollBackchannelAuthentication) (storage.PolledBackchannelAuthentication, error) {
	polled, err := s.BackchannelAuthenticationStore.PollBackchannelAuthentication(ctx, poll)
	if err == nil && polled.Grant != nil {
		polled.Grant = withoutIssuer(s.t, polled.Grant)
	}
	return polled, err
}

// TestBackchannelGrantWithoutAnIssuerIsUnknown covers a CIBA decision
// recorded before records carried their server's issuer: its
// auth_req_id is refused as unknown.
func TestBackchannelGrantWithoutAnIssuerIsUnknown(t *testing.T) {
	h := newHarnessWithBackchannelStore(t, legacyGrantStore{memstore.NewBackchannelAuthenticationStore(), t})
	required := beginBackchannel(t, h, standardBackchannelParams(t))
	approveBackchannel(t, h, required.Handle)
	_, err := h.server.ExchangeBackchannelAuthentication(context.Background(), server.BackchannelTokenExchangeRequest{
		HTTP: server.FormRequest{Parameters: []server.FormParameter{
			formParam("client_assertion", h.clientAssertion(t)),
			formParam("client_assertion_type", clientassertion.AssertionType),
			formParam("grant_type", server.CIBAGrantType),
			formParam("auth_req_id", required.AuthReqID.String()),
		}},
		DPoPProofs: []string{createDPoPProof(t, generateKey(t), h.now)},
	})
	if code := serverErrorCode(t, err); code != server.ErrorInvalidGrant {
		t.Fatalf("redeeming a backchannel grant without an issuer: error code %q, want %q", code, server.ErrorInvalidGrant)
	}
}
