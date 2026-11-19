package server

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
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
		if got, err := opaque.isOwnOpaqueAccessToken(context.Background(), tc.client, tc.token); got != tc.want || err != nil {
			t.Errorf("isOwnOpaqueAccessToken(%s, %q) = %v, %v, want %v", tc.client, tc.token, got, err, tc.want)
		}
	}
	pointer := &Server{cfg: Config{Issuer: issuer}, deps: Dependencies{AccessTokens: &OpaqueAccessTokens{Store: store}}}
	if got, err := pointer.isOwnOpaqueAccessToken(context.Background(), "client-1", "opaque-at"); !got || err != nil {
		t.Errorf("isOwnOpaqueAccessToken under *OpaqueAccessTokens = %v, %v, want true", got, err)
	}
	jwt := &Server{deps: Dependencies{AccessTokens: JWTAccessTokens{}}}
	if got, err := jwt.isOwnOpaqueAccessToken(context.Background(), "client-1", "opaque-at"); got || err != nil {
		t.Errorf("isOwnOpaqueAccessToken under JWT access tokens = %v, %v, want false", got, err)
	}
	// A store that couldn't answer isn't a no: RevokeToken's 200 would
	// tell the client the token was revoked.
	down := &Server{cfg: Config{Issuer: issuer}, deps: Dependencies{AccessTokens: OpaqueAccessTokens{Store: unavailableAccessTokens{}}}}
	if got, err := down.isOwnOpaqueAccessToken(context.Background(), "client-1", "opaque-at"); got || err == nil || err.Code() != ErrorServerError {
		t.Errorf("isOwnOpaqueAccessToken with the store down = %v, %v, want false and server_error", got, err)
	}
}

// unavailableAccessTokens is an AccessTokenStore that can't answer.
type unavailableAccessTokens struct{ storage.AccessTokenStore }

func (unavailableAccessTokens) LookupAccessToken(context.Context, storage.AccessTokenLookup) (storage.LookedUpAccessToken, error) {
	return storage.LookedUpAccessToken{}, fmt.Errorf("db: %w", storage.ErrStoreUnavailable)
}
