package server_test

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/server"
)

// TestTokenResultWriteJSONMinimal covers WriteJSON's own RFC 6749 §5.1
// wire format for a bare access-token-only result: Cache-Control,
// Content-Type, and the required members present with none of the
// conditional ones.
func TestTokenResultWriteJSONMinimal(t *testing.T) {
	result := server.TokenResult{
		AccessToken: fapi.NewSecret("at-value"),
		TokenType:   "DPoP",
		ExpiresIn:   300 * time.Second,
		Scope:       "openid",
	}

	rec := httptest.NewRecorder()
	result.WriteJSON(rec)

	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want %q", got, "no-store")
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type = %q, want %q", got, "application/json")
	}
	if rec.Header().Get("DPoP-Nonce") != "" {
		t.Fatalf("DPoP-Nonce = %q, want none when NextDPoPNonce is empty", rec.Header().Get("DPoP-Nonce"))
	}

	var body map[string]json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal body: %v (body: %s)", err, rec.Body.Bytes())
	}
	for _, absent := range []string{"id_token", "refresh_token", "authorization_details"} {
		if _, ok := body[absent]; ok {
			t.Fatalf("body = %s, want no %q member", rec.Body.Bytes(), absent)
		}
	}

	var got struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int64  `json:"expires_in"`
		Scope       string `json:"scope"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal body: %v", err)
	}
	if got.AccessToken != "at-value" || got.TokenType != "DPoP" || got.ExpiresIn != 300 || got.Scope != "openid" {
		t.Fatalf("body = %+v, want access_token=at-value token_type=DPoP expires_in=300 scope=openid", got)
	}
}

// TestTokenResultWriteJSONIncludesOptionalMembers covers WriteJSON's
// conditional members: id_token, refresh_token, authorization_details,
// and the DPoP-Nonce header, all present only when their governing
// field says to include them.
func TestTokenResultWriteJSONIncludesOptionalMembers(t *testing.T) {
	result := server.TokenResult{
		AccessToken:          fapi.NewSecret("at-value"),
		TokenType:            "DPoP",
		ExpiresIn:            60 * time.Second,
		Scope:                "openid offline_access",
		IDToken:              fapi.NewSecret("id-token-value"),
		HasIDToken:           true,
		RefreshToken:         fapi.NewSecret("rt-value"),
		HasRefreshToken:      true,
		AuthorizationDetails: json.RawMessage(`[{"type":"payment"}]`),
		NextDPoPNonce:        "next-nonce",
	}

	rec := httptest.NewRecorder()
	result.WriteJSON(rec)

	if got := rec.Header().Get("DPoP-Nonce"); got != "next-nonce" {
		t.Fatalf("DPoP-Nonce = %q, want %q", got, "next-nonce")
	}

	var got struct {
		IDToken              string          `json:"id_token"`
		RefreshToken         string          `json:"refresh_token"`
		AuthorizationDetails json.RawMessage `json:"authorization_details"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal body: %v", err)
	}
	if got.IDToken != "id-token-value" {
		t.Fatalf("id_token = %q, want %q", got.IDToken, "id-token-value")
	}
	if got.RefreshToken != "rt-value" {
		t.Fatalf("refresh_token = %q, want %q", got.RefreshToken, "rt-value")
	}
	if string(got.AuthorizationDetails) != `[{"type":"payment"}]` {
		t.Fatalf("authorization_details = %s, want %s", got.AuthorizationDetails, `[{"type":"payment"}]`)
	}
}
