package serverresource

import (
	"testing"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/keys/ephemeral"
	"github.com/idfoundry/fapigo/resource"
	"github.com/idfoundry/fapigo/server"
)

// TestJWTAccessTokensInheritsMaxTokenBytes: the verifier for a server's
// JWT access tokens accepts every token that server issues, however far
// its Limits.MaxAccessTokenClaimsBytes is raised.
func TestJWTAccessTokensInheritsMaxTokenBytes(t *testing.T) {
	km, err := ephemeral.NewKeyManager(map[keys.SigningPurpose]fapi.SignatureAlgorithm{keys.AccessTokenSigning: fapi.ES256})
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := fapi.ParseIssuerURL("https://as.example.com")
	if err != nil {
		t.Fatal(err)
	}
	for _, claimsBytes := range []int{server.RecommendedLimits().MaxAccessTokenClaimsBytes, 64 << 10} {
		cfg := server.Config{Issuer: issuer, Limits: server.RecommendedLimits()}
		cfg.Limits.MaxAccessTokenClaimsBytes = claimsBytes
		resolver, err := jwtAccessTokens(cfg, server.JWTAccessTokens{Keys: km, Algorithm: fapi.ES256}, audience{primary: issuer.String()})
		if err != nil {
			t.Fatal(err)
		}
		got := resolver.(resource.JWTAccessTokens).MaxTokenBytes
		if want := cfg.Limits.MaxAccessTokenBytes(); got != want {
			t.Errorf("claims budget %d: MaxTokenBytes = %d, want %d", claimsBytes, got, want)
		}
	}
}
