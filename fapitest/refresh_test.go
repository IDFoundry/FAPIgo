package fapitest_test

import (
	"context"
	"errors"
	"net/url"
	"testing"
	"time"

	"github.com/idfoundry/fapigo/client"
	"github.com/idfoundry/fapigo/fapitest"
	"github.com/idfoundry/fapigo/resource"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
)

var offlineScope = []string{"openid", "accounts", "offline_access"}

// TestRefreshTokens drives client.Client.RefreshTokens against a real
// server.Server: a new access token, bound and accepted like the first,
// the same refresh token back (FAPI 2.0 doesn't rotate them), and a
// refreshed ID token for the same subject.
func TestRefreshTokens(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  fapitest.Config
	}{
		{"DPoP", fapitest.Config{Profile: server.ProfileFAPISecurity}},
		{"mTLS", fapitest.Config{Profile: server.ProfileFAPISecurity, SenderConstrain: storage.SenderConstrainMTLS}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := fapitest.New(t, tc.cfg)
			ctx := context.Background()
			first, err := h.RunAuthorizationCodeFlow(ctx, offlineScope)
			if err != nil {
				t.Fatalf("RunAuthorizationCodeFlow: %v", err)
			}
			h.Clock.Advance(time.Minute)

			refreshed, err := h.Client.RefreshTokens(ctx, client.RefreshTokenRequest{Tokens: first})
			if err != nil {
				t.Fatalf("RefreshTokens: %v", err)
			}
			if refreshed.AccessToken.Reveal() == "" || refreshed.AccessToken.Reveal() == first.AccessToken.Reveal() {
				t.Error("RefreshTokens didn't return a new access token")
			}
			if !refreshed.HasRefreshToken || refreshed.RefreshToken.Reveal() != first.RefreshToken.Reveal() {
				t.Error("RefreshTokens didn't return the same refresh token")
			}
			if !refreshed.HasIDToken || refreshed.Subject != first.Subject {
				t.Errorf("refreshed ID token: HasIDToken %v, subject %q; want an ID token for %q", refreshed.HasIDToken, refreshed.Subject, first.Subject)
			}
			if !refreshed.IDTokenClaims.AuthTime.Equal(first.IDTokenClaims.AuthTime) {
				t.Errorf("refreshed auth_time %v, want the original authentication's %v", refreshed.IDTokenClaims.AuthTime, first.IDTokenClaims.AuthTime)
			}
			verifyBoundAccessToken(t, h, refreshed)

			// And again, from the refreshed set: the refresh token keeps
			// working.
			if _, err := h.Client.RefreshTokens(ctx, client.RefreshTokenRequest{Tokens: refreshed}); err != nil {
				t.Fatalf("second RefreshTokens: %v", err)
			}
		})
	}
}

// verifyBoundAccessToken is verifyAccessToken for either sender
// constraint: a DPoP proof, or the harness's client certificate.
func verifyBoundAccessToken(t *testing.T, h *fapitest.Harness, tokens client.TokenSet) {
	t.Helper()
	ctx := context.Background()
	target, err := url.Parse("https://rs.fapitest.internal/accounts")
	if err != nil {
		t.Fatal(err)
	}
	req := resource.VerifyRequest{Method: "GET", URL: target}
	if h.MTLSCertificate != nil {
		req.Authorization, req.PeerCertificate = "Bearer "+tokens.AccessToken.Reveal(), h.MTLSCertificate
	} else {
		proof, err := h.NewResourceRequestDPoPProof(ctx, "GET", target, tokens.AccessToken.Reveal())
		if err != nil {
			t.Fatalf("NewResourceRequestDPoPProof: %v", err)
		}
		req.Authorization, req.DPoPProofs = "DPoP "+tokens.AccessToken.Reveal(), []string{proof}
	}
	if _, err := h.Resource.Verify(ctx, req); err != nil {
		t.Fatalf("resource.Verify(refreshed access token): %v", err)
	}
}

func TestRefreshTokensNarrowsButNeverWidensScope(t *testing.T) {
	h := fapitest.New(t, fapitest.Config{Profile: server.ProfileFAPISecurity})
	ctx := context.Background()
	first, err := h.RunAuthorizationCodeFlow(ctx, offlineScope)
	if err != nil {
		t.Fatalf("RunAuthorizationCodeFlow: %v", err)
	}
	narrowed, err := h.Client.RefreshTokens(ctx, client.RefreshTokenRequest{Tokens: first, Scope: []string{"accounts"}})
	if err != nil {
		t.Fatalf("RefreshTokens(narrower scope): %v", err)
	}
	if narrowed.Scope != "accounts" {
		t.Errorf("Scope = %q, want accounts", narrowed.Scope)
	}
	if _, err := h.Client.RefreshTokens(ctx, client.RefreshTokenRequest{Tokens: first, Scope: []string{"accounts", "payments"}}); err == nil {
		t.Error("RefreshTokens(wider scope) = nil error, want the server's refusal")
	}
}

func TestRefreshTokensAfterExpiry(t *testing.T) {
	h := fapitest.New(t, fapitest.Config{Profile: server.ProfileFAPISecurity})
	ctx := context.Background()
	first, err := h.RunAuthorizationCodeFlow(ctx, offlineScope)
	if err != nil {
		t.Fatalf("RunAuthorizationCodeFlow: %v", err)
	}
	h.Clock.Advance(6 * time.Minute) // past the harness's 5-minute refresh token lifetime
	_, err = h.Client.RefreshTokens(ctx, client.RefreshTokenRequest{Tokens: first})
	var cerr *client.Error
	if !errors.As(err, &cerr) {
		t.Fatalf("RefreshTokens(expired) = %v, want a *client.Error", err)
	}
	if resp, ok := cerr.ServerResponse(); !ok || resp.Code != "invalid_grant" {
		t.Errorf("RefreshTokens(expired) server error = %+v, want invalid_grant", resp)
	}
}

func TestRefreshTokensWithoutRefreshToken(t *testing.T) {
	h := fapitest.New(t, fapitest.Config{Profile: server.ProfileFAPISecurity})
	ctx := context.Background()
	tokens, err := h.RunAuthorizationCodeFlow(ctx, []string{"openid", "accounts"})
	if err != nil {
		t.Fatalf("RunAuthorizationCodeFlow: %v", err)
	}
	_, err = h.Client.RefreshTokens(ctx, client.RefreshTokenRequest{Tokens: tokens})
	var cerr *client.Error
	if !errors.As(err, &cerr) || cerr.Code() != client.ErrorInvalidRequest {
		t.Fatalf("RefreshTokens(no refresh token) = %v, want invalid_request", err)
	}
}
