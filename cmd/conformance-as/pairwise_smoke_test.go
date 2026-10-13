package main

import (
	"context"
	"strings"
	"testing"

	"github.com/idfoundry/fapigo/client"
)

// TestSmokePairwiseSubjects drives the full code flow under
// -pairwise-subjects, with JWT and opaque access tokens: the ID token's
// sub is a pairwise one (not the internal subject), UserInfo returns the
// same sub (OpenID Connect Core §5.3.2), and a refreshed ID token keeps
// it (§12.2) — what the OIDF suite's pairwise leg relies on.
func TestSmokePairwiseSubjects(t *testing.T) {
	for _, format := range []AccessTokenFormat{AccessTokenFormatJWT, AccessTokenFormatOpaque} {
		t.Run(string(format), func(t *testing.T) {
			h := newSmokeHarnessWithOptions(t, format, false, false, false, "", func(r *ResolvedConfig) {
				r.PairwiseSubjects = true
			})
			ctx := context.Background()
			scope := []string{"openid", "accounts", "offline_access"}

			handle := h.runToConsent(ctx, scope)
			rawQuery := h.submitDecision(ctx, handle, "approve", scope)
			result, err := h.client.CompleteAuthorization(ctx, client.AuthorizationCallback{RawQuery: rawQuery, Session: h.session})
			if err != nil {
				t.Fatalf("CompleteAuthorization: %v", err)
			}
			success, ok := result.(client.CompletionSuccess)
			if !ok {
				t.Fatalf("CompleteAuthorization result = %T, want client.CompletionSuccess", result)
			}
			sub := success.Tokens.Subject
			if !strings.HasPrefix(sub, pairwisePrefix) || sub == smokeSubject {
				t.Fatalf("ID token sub = %q, want a %q-prefixed pairwise sub, not the internal subject", sub, pairwisePrefix)
			}

			info, err := h.client.FetchUserInfo(ctx, success.Tokens)
			if err != nil {
				t.Fatalf("FetchUserInfo: %v", err)
			}
			if info.Subject != sub {
				t.Fatalf("UserInfo sub = %q, want the ID token's %q", info.Subject, sub)
			}

			refreshed, err := h.client.RefreshTokens(ctx, client.RefreshTokenRequest{Tokens: success.Tokens})
			if err != nil {
				t.Fatalf("RefreshTokens: %v", err)
			}
			if refreshed.HasIDToken && refreshed.Subject != sub {
				t.Fatalf("refreshed ID token sub = %q, want %q", refreshed.Subject, sub)
			}
			if _, err := h.client.FetchUserInfo(ctx, refreshed); err != nil {
				t.Fatalf("FetchUserInfo with the refreshed access token: %v", err)
			}
		})
	}
}
