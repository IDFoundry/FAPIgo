package resource_test

import (
	"strings"
	"testing"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/resource"
	"github.com/idfoundry/fapigo/storage/memstore"
)

// TestNewVerifierRefusesIncompleteBundledResolvers: a JWTAccessTokens
// or OpaqueAccessTokens literal missing a field — passed by value or by
// pointer — is refused by NewVerifier, rather than failing every
// request or, for a nil key source or store, panicking on it.
func TestNewVerifierRefusesIncompleteBundledResolvers(t *testing.T) {
	valid := validAccessTokens(t).(resource.JWTAccessTokens)
	jwtCases := map[string]func(*resource.JWTAccessTokens){
		"issuer keys is required":             func(j *resource.JWTAccessTokens) { j.IssuerKeys = nil },
		"issuer is required":                  func(j *resource.JWTAccessTokens) { j.Issuer = fapi.URL{} },
		"audience is required":                func(j *resource.JWTAccessTokens) { j.Audience = "" },
		"algorithm is invalid":                func(j *resource.JWTAccessTokens) { j.Algorithm = 0 },
		"max token lifetime must be positive": func(j *resource.JWTAccessTokens) { j.MaxTokenLifetime = 0 },
		"max key candidates must be positive": func(j *resource.JWTAccessTokens) { j.MaxKeyCandidates = 0 },
	}
	for want, mutate := range jwtCases {
		j := valid
		mutate(&j)
		for form, resolver := range map[string]resource.AccessTokenResolver{"value": j, "pointer": &j} {
			t.Run("JWTAccessTokens "+form+" "+want, func(t *testing.T) {
				deps := validDependencies(t)
				deps.AccessTokens = resolver
				_, err := resource.NewVerifier(validConfig(t), deps)
				if err == nil || !strings.Contains(err.Error(), "access_tokens (JWTAccessTokens): "+want) {
					t.Fatalf("NewVerifier = %v, want %q", err, want)
				}
			})
		}
	}

	for form, resolver := range map[string]resource.AccessTokenResolver{
		"value":   resource.OpaqueAccessTokens{},
		"pointer": &resource.OpaqueAccessTokens{},
	} {
		t.Run("OpaqueAccessTokens "+form+" without a store", func(t *testing.T) {
			deps := validDependencies(t)
			deps.AccessTokens = resolver
			_, err := resource.NewVerifier(validConfig(t), deps)
			if err == nil || !strings.Contains(err.Error(), "access_tokens (OpaqueAccessTokens): store is required") {
				t.Fatalf("NewVerifier = %v, want the store required", err)
			}
		})
	}

	for name, resolver := range map[string]resource.AccessTokenResolver{
		"nil *JWTAccessTokens":    (*resource.JWTAccessTokens)(nil),
		"nil *OpaqueAccessTokens": (*resource.OpaqueAccessTokens)(nil),
	} {
		t.Run(name, func(t *testing.T) {
			deps := validDependencies(t)
			deps.AccessTokens = resolver
			if _, err := resource.NewVerifier(validConfig(t), deps); err == nil || !strings.Contains(err.Error(), "is a "+name) {
				t.Fatalf("NewVerifier = %v, want %s refused", err, name)
			}
		})
	}

	t.Run("complete literals are accepted", func(t *testing.T) {
		for name, resolver := range map[string]resource.AccessTokenResolver{
			"JWTAccessTokens":     valid,
			"*JWTAccessTokens":    &valid,
			"OpaqueAccessTokens":  resource.OpaqueAccessTokens{Store: memstore.NewAccessTokenStore()},
			"*OpaqueAccessTokens": &resource.OpaqueAccessTokens{Store: memstore.NewAccessTokenStore()},
		} {
			deps := validDependencies(t)
			deps.AccessTokens = resolver
			if _, err := resource.NewVerifier(validConfig(t), deps); err != nil {
				t.Errorf("NewVerifier(%s): %v", name, err)
			}
		}
	})
}
