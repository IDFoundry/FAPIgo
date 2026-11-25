package server_test

import (
	"context"
	"errors"
	"testing"

	"github.com/idfoundry/fapigo/internal/clientassertion"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
)

// foundGrantStore is a GrantStore that counts the codes and refresh
// tokens it found (redeemed, or reported reused) for one server.
type foundGrantStore struct {
	storage.GrantStore
	codes, refreshTokens int
}

func (s *foundGrantStore) RedeemAuthorizationCode(ctx context.Context, r storage.AuthorizationCodeRedemption) (storage.RedeemedAuthorizationCode, error) {
	redeemed, err := s.GrantStore.RedeemAuthorizationCode(ctx, r)
	var reused *storage.AuthorizationCodeAlreadyRedeemedError
	if err == nil || errors.As(err, &reused) {
		s.codes++
	}
	return redeemed, err
}

func (s *foundGrantStore) RedeemRefreshToken(ctx context.Context, r storage.RefreshTokenRedemption) (storage.RedeemedRefreshToken, error) {
	redeemed, err := s.GrantStore.RedeemRefreshToken(ctx, r)
	if err == nil {
		s.refreshTokens++
	}
	return redeemed, err
}

// otherTenantSeeing is otherTenant whose GrantStore, the same one h
// uses, counts what tenant B finds in it.
func otherTenantSeeing(t *testing.T, h harness) (*server.Server, func() string, *foundGrantStore) {
	t.Helper()
	found := &foundGrantStore{GrantStore: h.deps.Grants}
	h.deps.Grants = found
	srv, assertion := otherTenant(t, h)
	return srv, assertion, found
}

// TestAnotherIssuersCodeIsLeftUnspent: a code presented to a server of
// another issuer over the same store isn't found there, so isn't spent:
// the server that issued it still exchanges it.
func TestAnotherIssuersCodeIsLeftUnspent(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	tenantB, assertionB, found := otherTenantSeeing(t, h)
	code := completeSuccessfulAuthorization(t, h, []string{"openid", "accounts"})
	_, err := tenantB.ExchangeAuthorizationCode(context.Background(), server.AuthorizationCodeExchangeRequest{
		HTTP:       server.FormRequest{Parameters: exchangeFormParams(assertionB(), code, testRedirectURI, testCodeVerifier)},
		DPoPProofs: []string{createDPoPProof(t, generateKey(t), h.now)},
	})
	if code := serverErrorCode(t, err); code != server.ErrorInvalidGrant {
		t.Fatalf("tenant B redeeming tenant A's code: error code %q, want %q", code, server.ErrorInvalidGrant)
	}
	if found.codes != 0 {
		t.Fatalf("tenant B's exchange found tenant A's code in the store %d times, want none", found.codes)
	}
	if _, err := exchangeCode(t, h, code, generateKey(t)); err != nil {
		t.Fatalf("tenant A exchanging its own code afterwards: %v, want tokens", err)
	}
}

// TestAnotherIssuersRefreshTokenIsNotFound: a refresh token presented
// to a server of another issuer over the same store isn't found there,
// by a refresh or a revocation, and still works at the server that
// issued it.
func TestAnotherIssuersRefreshTokenIsNotFound(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, server.ProfileFAPISecurity, true)
	tenantB, assertionB, found := otherTenantSeeing(t, h)
	code := completeSuccessfulAuthorization(t, h, []string{"openid", "accounts", "offline_access"})
	tokens, err := exchangeCode(t, h, code, generateKey(t))
	if err != nil || !tokens.HasRefreshToken {
		t.Fatalf("ExchangeAuthorizationCode = %v (refresh token %v)", err, tokens.HasRefreshToken)
	}
	refreshToken := tokens.RefreshToken.Reveal()
	_, err = tenantB.RefreshAccessToken(ctx, server.RefreshTokenRequest{
		HTTP:       server.FormRequest{Parameters: refreshFormParams(assertionB(), refreshToken, "")},
		DPoPProofs: []string{createDPoPProof(t, generateKey(t), h.now)},
	})
	if code := serverErrorCode(t, err); code != server.ErrorInvalidGrant {
		t.Fatalf("tenant B refreshing tenant A's refresh token: error code %q, want %q", code, server.ErrorInvalidGrant)
	}
	if found.refreshTokens != 0 {
		t.Fatalf("tenant B's refresh found tenant A's refresh token in the store %d times, want none", found.refreshTokens)
	}
	if _, err := h.server.RefreshAccessToken(ctx, server.RefreshTokenRequest{
		HTTP:       server.FormRequest{Parameters: refreshFormParams(h.clientAssertion(t), refreshToken, "")},
		DPoPProofs: []string{createDPoPProof(t, generateKey(t), h.now)},
	}); err != nil {
		t.Fatalf("tenant A refreshing its own refresh token afterwards: %v", err)
	}
}

// TestAnotherIssuersAuthReqIDIsLeftUnspent: an auth_req_id polled at a
// server of another issuer over the same store isn't found there, so
// neither counts as a poll of the pending request nor spends its
// approval: the server that issued it still answers its own client's
// polls as if tenant B's never happened.
func TestAnotherIssuersAuthReqIDIsLeftUnspent(t *testing.T) {
	h, _ := newHarnessWithBackchannel(t)
	tenantB, assertionB := otherTenant(t, h)
	pollB := func(authReqID server.AuthReqID) error {
		_, err := tenantB.ExchangeBackchannelAuthentication(context.Background(), server.BackchannelTokenExchangeRequest{
			HTTP: server.FormRequest{Parameters: []server.FormParameter{
				formParam("client_assertion", assertionB()),
				formParam("client_assertion_type", clientassertion.AssertionType),
				formParam("grant_type", server.CIBAGrantType),
				formParam("auth_req_id", authReqID.String()),
			}},
			DPoPProofs: []string{createDPoPProof(t, generateKey(t), h.now)},
		})
		return err
	}

	pending := beginBackchannel(t, h, standardBackchannelParams(t))
	if code := serverErrorCode(t, pollB(pending.AuthReqID)); code != server.ErrorInvalidGrant {
		t.Fatalf("tenant B polling tenant A's pending auth_req_id: error code %q, want %q", code, server.ErrorInvalidGrant)
	}
	if code := serverErrorCode(t, exchangeBackchannelWithKey(t, h, pending.AuthReqID.String(), generateKey(t))); code != server.ErrorAuthorizationPending {
		t.Fatalf("tenant A's first poll after tenant B's: %q, want %q, not slow_down", code, server.ErrorAuthorizationPending)
	}

	approved := beginBackchannel(t, h, standardBackchannelParams(t))
	approveBackchannel(t, h, approved.Handle)
	if code := serverErrorCode(t, pollB(approved.AuthReqID)); code != server.ErrorInvalidGrant {
		t.Fatalf("tenant B redeeming tenant A's approved auth_req_id: error code %q, want %q", code, server.ErrorInvalidGrant)
	}
	if err := exchangeBackchannelWithKey(t, h, approved.AuthReqID.String(), generateKey(t)); err != nil {
		t.Fatalf("tenant A redeeming its own approved auth_req_id afterwards: %v, want tokens", err)
	}
}
