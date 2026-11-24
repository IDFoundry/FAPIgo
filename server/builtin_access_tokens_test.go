package server_test

import (
	"strings"
	"testing"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage/memstore"
)

// TestNewRefusesBuiltInAccessTokensWithoutTheirDependencies: a
// JWTAccessTokens without a key manager (or with a nil one behind the
// interface) or a valid algorithm, or an OpaqueAccessTokens without a
// store (or with a nil one behind the interface), is refused by New at
// either assurance level, by value or pointer, instead of failing at
// its first token request. A complete one of each is accepted.
func TestNewRefusesBuiltInAccessTokensWithoutTheirDependencies(t *testing.T) {
	var nilKeys *fakeKeyManager
	var nilStore *memstore.AccessTokenStore
	for name, tc := range map[string]struct {
		issuer server.AccessTokenIssuer
		want   string // "" when accepted
	}{
		"JWT without keys":            {server.JWTAccessTokens{Algorithm: fapi.ES256}, "JWTAccessTokens.Keys is required"},
		"JWT with nil keys":           {server.JWTAccessTokens{Keys: nilKeys, Algorithm: fapi.ES256}, "JWTAccessTokens.Keys is a nil *server_test.fakeKeyManager"},
		"JWT without an algorithm":    {server.JWTAccessTokens{Keys: newTestKeyManager()}, "JWTAccessTokens.Algorithm is invalid"},
		"pointer to JWT without keys": {&server.JWTAccessTokens{Algorithm: fapi.ES256}, "JWTAccessTokens.Keys is required"},
		"opaque without a store":      {server.OpaqueAccessTokens{}, "OpaqueAccessTokens.Store is required"},
		"opaque with a nil store":     {server.OpaqueAccessTokens{Store: nilStore}, "OpaqueAccessTokens.Store is a nil *memstore.AccessTokenStore"},
		"pointer to opaque, no store": {&server.OpaqueAccessTokens{}, "OpaqueAccessTokens.Store is required"},
		"complete JWT":                {server.JWTAccessTokens{Keys: newTestKeyManager(), Algorithm: fapi.ES256}, ""},
		"complete opaque":             {server.OpaqueAccessTokens{Store: memstore.NewAccessTokenStore()}, ""},
	} {
		t.Run(name, func(t *testing.T) {
			cfg, deps := validConfig(t), validDependencies()
			deps.AccessTokens = tc.issuer
			assertNewOutcome(t, "development", cfg, deps, tc.want)
			if tc.want != "" {
				cfg, deps = productionConfigAndDeps(t)
				deps.AccessTokens = tc.issuer
				assertNewOutcome(t, "production", cfg, deps, tc.want)
			}
		})
	}
}

// assertNewOutcome checks New(cfg, deps) succeeds when want is empty,
// and otherwise fails with an error containing want.
func assertNewOutcome(t *testing.T, level string, cfg server.Config, deps server.Dependencies, want string) {
	t.Helper()
	_, err := server.New(cfg, deps)
	switch {
	case want == "" && err != nil:
		t.Fatalf("New(%s) = %v, want it accepted", level, err)
	case want != "" && (err == nil || !strings.Contains(err.Error(), want)):
		t.Fatalf("New(%s) = %v, want %q", level, err, want)
	}
}
