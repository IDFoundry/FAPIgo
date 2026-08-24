package fapitest_test

import (
	"context"
	"testing"
	"time"

	"github.com/idfoundry/fapigo/fapitest"
	"github.com/idfoundry/fapigo/server"
)

// TestFetchUserInfoOverRealHTTP proves client.FetchUserInfo's produced
// Authorization header and DPoP proof pass real, independent
// verification (resource.Verifier, over an actual HTTP round trip) —
// exactly the class of wire-format bug FetchUserInfo's own unit tests
// (client/userinfo_test.go, which never verify the proof at all) cannot
// see. See harness_test.go's own verifyAccessToken for the same
// end-to-end reasoning applied to a hand-built resource request.
func TestFetchUserInfoOverRealHTTP(t *testing.T) {
	h := fapitest.New(t, fapitest.Config{Profile: server.ProfileFAPISecurity})
	ctx := context.Background()

	tokens, err := h.RunAuthorizationCodeFlow(ctx, []string{"openid", "accounts"})
	if err != nil {
		t.Fatalf("RunAuthorizationCodeFlow: %v", err)
	}

	info, err := h.Client.FetchUserInfo(ctx, tokens)
	if err != nil {
		t.Fatalf("FetchUserInfo: %v", err)
	}
	if info.Subject != fapitest.Subject {
		t.Errorf("Subject = %q, want %q", info.Subject, fapitest.Subject)
	}
}

// TestFetchUserInfoOverRealHTTPRejectsExpiredAccessToken mirrors
// TestAuthorizationCodeFlowAccessTokenExpires: the harness's shared
// Clock genuinely drives expiry enforcement on the UserInfo path too,
// not just the hand-built resource.Verify path that test already
// covers.
func TestFetchUserInfoOverRealHTTPRejectsExpiredAccessToken(t *testing.T) {
	h := fapitest.New(t, fapitest.Config{Profile: server.ProfileFAPISecurity})
	ctx := context.Background()

	tokens, err := h.RunAuthorizationCodeFlow(ctx, []string{"openid", "accounts"})
	if err != nil {
		t.Fatalf("RunAuthorizationCodeFlow: %v", err)
	}

	h.Clock.Advance(6 * time.Minute) // past the harness's 5-minute access token lifetime

	if _, err := h.Client.FetchUserInfo(ctx, tokens); err == nil {
		t.Fatalf("FetchUserInfo(expired access token) = nil error, want error")
	}
}
