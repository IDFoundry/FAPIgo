package server_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"net/url"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/dpop"
	"github.com/idfoundry/fapigo/internal/grantrevocation"
	"github.com/idfoundry/fapigo/resource"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage/memstore"
)

// TestCodeReuseRevokesAccessTokensFromItsRefreshToken: an access token
// the client minted from the code's refresh token, after the exchange, is
// revoked too when the code is reused (RFC 6749 §4.1.2's "all tokens
// previously issued based on that authorization code"), not only the
// first access token the store recorded — and the refresh token itself
// can't be redeemed again.
func TestCodeReuseRevokesAccessTokensFromItsRefreshToken(t *testing.T) {
	h, store := newHarnessWithOpaqueAccessTokens(t, server.ProfileFAPISecurity, true)
	code := completeSuccessfulAuthorization(t, h, []string{"openid", "accounts", "offline_access"})
	dpopKey := generateKey(t)
	first, err := h.server.ExchangeAuthorizationCode(context.Background(), server.AuthorizationCodeExchangeRequest{
		HTTP:       server.FormRequest{Parameters: exchangeFormParams(h.clientAssertion(t), code, testRedirectURI, testCodeVerifier)},
		DPoPProofs: []string{createDPoPProof(t, dpopKey, h.now)},
	})
	if err != nil {
		t.Fatalf("ExchangeAuthorizationCode: %v", err)
	}
	refreshed, err := h.server.RefreshAccessToken(context.Background(), server.RefreshTokenRequest{
		HTTP:       server.FormRequest{Parameters: refreshFormParams(h.clientAssertion(t), first.RefreshToken.Reveal(), "")},
		DPoPProofs: []string{createDPoPProof(t, dpopKey, h.now)},
	})
	if err != nil {
		t.Fatalf("RefreshAccessToken: %v", err)
	}

	verifier, err := resource.NewVerifier(resource.Config{
		Limits:    resource.Limits{MaxDPoPProofAge: time.Minute, MaxClockSkew: 5 * time.Second},
		Assurance: resource.AssuranceDevelopment,
	}, resource.Dependencies{
		AccessTokens: resource.OpaqueAccessTokens{Store: store},
		Replay:       memstore.NewReplayStore(),
		Revocation:   revocationCheckerFromSink{sink: h.revocation},
		Clock:        fixedClock{now: h.now},
	})
	if err != nil {
		t.Fatalf("resource.NewVerifier: %v", err)
	}
	accessToken2 := refreshed.AccessToken.Reveal()
	if err := verifyWithDPoP(t, verifier, dpopKey, accessToken2, h.now); err != nil {
		t.Fatalf("Verify(refreshed access token, before reuse): %v", err)
	}

	if _, err := h.server.ExchangeAuthorizationCode(context.Background(), server.AuthorizationCodeExchangeRequest{
		HTTP:       server.FormRequest{Parameters: exchangeFormParams(h.clientAssertion(t), code, testRedirectURI, testCodeVerifier)},
		DPoPProofs: []string{createDPoPProof(t, dpopKey, h.now)},
	}); err == nil {
		t.Fatal("second ExchangeAuthorizationCode (reused code) = nil error, want error")
	}

	err = verifyWithDPoP(t, verifier, dpopKey, accessToken2, h.now)
	var rerr *resource.Error
	if !errors.As(err, &rerr) || rerr.Code() != resource.ErrorInvalidToken {
		t.Fatalf("Verify(refreshed access token, after reuse) = %v, want invalid_token", err)
	}

	if _, err := h.server.RefreshAccessToken(context.Background(), server.RefreshTokenRequest{
		HTTP:       server.FormRequest{Parameters: refreshFormParams(h.clientAssertion(t), first.RefreshToken.Reveal(), "")},
		DPoPProofs: []string{createDPoPProof(t, dpopKey, h.now)},
	}); err == nil {
		t.Fatal("RefreshAccessToken after the code was reused = nil error, want the grant refused")
	}
}

func verifyWithDPoP(t *testing.T, verifier *resource.Verifier, key *ecdsa.PrivateKey, accessToken string, now time.Time) error {
	t.Helper()
	target, err := url.Parse("https://rs.example.com/accounts")
	if err != nil {
		t.Fatalf("parse target url: %v", err)
	}
	proof, err := dpop.CreateProof(dpop.ProofRequest{
		Signer: key, Algorithm: fapi.ES256, Method: "GET", URL: target,
		AccessToken: accessToken, Now: now, Random: rand.Reader,
	})
	if err != nil {
		t.Fatalf("create dpop proof: %v", err)
	}
	_, err = verifier.Verify(context.Background(), resource.VerifyRequest{
		Method: "GET", URL: target, Authorization: "DPoP " + accessToken, DPoPProofs: []string{proof},
	})
	return err
}

// TestRefreshRefusesARevokedCodeGrant: the refresh token's own grant
// record carries the code grant, so a refresh is refused once that grant
// is revoked, even where the store doesn't revoke the refresh token
// itself (a custom store's RevokeRefreshToken that failed, say).
func TestRefreshRefusesARevokedCodeGrant(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	code := completeSuccessfulAuthorization(t, h, []string{"openid", "accounts", "offline_access"})
	dpopKey := generateKey(t)
	first, err := h.server.ExchangeAuthorizationCode(context.Background(), server.AuthorizationCodeExchangeRequest{
		HTTP:       server.FormRequest{Parameters: exchangeFormParams(h.clientAssertion(t), code, testRedirectURI, testCodeVerifier)},
		DPoPProofs: []string{createDPoPProof(t, dpopKey, h.now)},
	})
	if err != nil {
		t.Fatalf("ExchangeAuthorizationCode: %v", err)
	}
	refresh := func() error {
		_, err := h.server.RefreshAccessToken(context.Background(), server.RefreshTokenRequest{
			HTTP:       server.FormRequest{Parameters: refreshFormParams(h.clientAssertion(t), first.RefreshToken.Reveal(), "")},
			DPoPProofs: []string{createDPoPProof(t, dpopKey, h.now)},
		})
		return err
	}
	if err := refresh(); err != nil {
		t.Fatalf("RefreshAccessToken before revocation: %v", err)
	}
	codeHash := sha256.Sum256([]byte(code))
	if err := h.revocation.Revoke(context.Background(), grantrevocation.CodeKey(grantrevocation.CodeGrantID(codeHash)), h.now.Add(time.Hour)); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if err := refresh(); err == nil {
		t.Fatal("RefreshAccessToken with its code grant revoked = nil error, want invalid_grant")
	}
}
