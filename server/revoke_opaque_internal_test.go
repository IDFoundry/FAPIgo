package server

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/token"
	"github.com/idfoundry/fapigo/storage"
	"github.com/idfoundry/fapigo/storage/memstore"
)

// TestIsOwnOpaqueAccessToken: RevokeToken answers a client's own opaque
// access token unsupported_token_type (RFC 7009 §2.2.1), which this
// server can't revoke, rather than the 200 that says it did; another
// client's, another issuer's, one recorded without an issuer, an
// unknown one, and any under JWT access tokens aren't reported.
func TestIsOwnOpaqueAccessToken(t *testing.T) {
	issuer, err := fapi.ParseIssuerURL("https://as.example.com")
	if err != nil {
		t.Fatal(err)
	}
	store := memstore.NewAccessTokenStore()
	for raw, iss := range map[string]string{
		"opaque-at":    `"https://as.example.com"`,
		"other-issuer": `"https://tenant-b.example.com"`,
		"no-issuer":    "",
	} {
		var claims map[string]json.RawMessage
		if iss != "" {
			claims = map[string]json.RawMessage{token.IssuerRecordClaim: json.RawMessage(iss)}
		}
		if err := store.CreateAccessToken(context.Background(), storage.NewAccessToken{
			TokenHash: sha256.Sum256([]byte(raw)), ClientID: "client-1", Subject: "user-1",
			Claims: claims, ExpiresAt: time.Now().Add(time.Minute),
		}); err != nil {
			t.Fatal(err)
		}
	}
	opaque := &Server{cfg: Config{Issuer: issuer}, deps: Dependencies{AccessTokens: OpaqueAccessTokens{Store: store}}}
	for _, tc := range []struct {
		client fapi.ClientID
		token  string
		want   bool
	}{
		{"client-1", "opaque-at", true},
		{"client-2", "opaque-at", false},
		{"client-1", "unknown", false},
		{"client-1", "other-issuer", false},
		{"client-1", "no-issuer", false},
	} {
		if got := opaque.isOwnOpaqueAccessToken(context.Background(), tc.client, tc.token); got != tc.want {
			t.Errorf("isOwnOpaqueAccessToken(%s, %q) = %v, want %v", tc.client, tc.token, got, tc.want)
		}
	}
	pointer := &Server{cfg: Config{Issuer: issuer}, deps: Dependencies{AccessTokens: &OpaqueAccessTokens{Store: store}}}
	if !pointer.isOwnOpaqueAccessToken(context.Background(), "client-1", "opaque-at") {
		t.Error("isOwnOpaqueAccessToken under *OpaqueAccessTokens = false, want true")
	}
	jwt := &Server{deps: Dependencies{AccessTokens: JWTAccessTokens{}}}
	if jwt.isOwnOpaqueAccessToken(context.Background(), "client-1", "opaque-at") {
		t.Error("isOwnOpaqueAccessToken under JWT access tokens = true, want false")
	}
}
