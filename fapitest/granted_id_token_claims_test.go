package fapitest_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/idfoundry/fapigo/fapitest"
	"github.com/idfoundry/fapigo/server"
)

// TestAuthorizationCodeFlowGrantedIDTokenClaims covers
// server.GrantedAuthorization.IDTokenClaims end to end: claims the
// application grants at login reach the client's validated ID token —
// plain and encrypted — and never the access token.
func TestAuthorizationCodeFlowGrantedIDTokenClaims(t *testing.T) {
	claims := map[string]json.RawMessage{
		"sub_type": json.RawMessage(`"user"`),
		"act":      json.RawMessage(`{"sub":"delegate-1"}`),
	}
	cases := map[string]fapitest.Config{
		"plain":     {Profile: server.ProfileFAPISecurity, IDTokenClaims: claims},
		"encrypted": {Profile: server.ProfileFAPISecurity, IDTokenClaims: claims, EncryptIDTokens: true},
		"message-signing": {
			Profile: server.ProfileFAPISecurityWithMessageSigning, IDTokenClaims: claims,
		},
	}
	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) {
			h := fapitest.New(t, cfg)
			tokens, err := h.RunAuthorizationCodeFlow(context.Background(), []string{"openid", "accounts"})
			if err != nil {
				t.Fatalf("RunAuthorizationCodeFlow: %v", err)
			}
			if !tokens.HasIDToken {
				t.Fatalf("HasIDToken = false, want true")
			}
			if got := string(tokens.IDTokenClaims.Parameters["sub_type"]); got != `"user"` {
				t.Errorf("ID token sub_type = %s, want %q", got, `"user"`)
			}
			var act struct {
				Sub string `json:"sub"`
			}
			if err := json.Unmarshal(tokens.IDTokenClaims.Parameters["act"], &act); err != nil || act.Sub != "delegate-1" {
				t.Errorf("ID token act = %s (%v), want sub delegate-1", tokens.IDTokenClaims.Parameters["act"], err)
			}

			authz := verifyAccessToken(t, h, tokens)
			for name := range claims {
				if _, ok := authz.Claims[name]; ok {
					t.Errorf("access token carries ID-token-only claim %q", name)
				}
			}
		})
	}
}
