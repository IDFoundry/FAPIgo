package resource_test

import (
	"strings"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/resource"
	"github.com/idfoundry/fapigo/storage/memstore"
)

// TestAccessTokensRefuseTypedNilFields covers a nil pointer in
// JWTAccessTokens.IssuerKeys, OpaqueAccessTokens.Store and a custom
// resolver's AccessTokenAssurance: each is refused at construction,
// naming the field, rather than passing its nil check and panicking on
// the first request (or in the production capability check).
func TestAccessTokensRefuseTypedNilFields(t *testing.T) {
	issuer, err := fapi.ParseIssuerURL(testIssuer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := resource.NewJWTAccessTokens((*keys.JWKSIssuerKeySource)(nil), issuer, testIssuer, fapi.ES256, 5*time.Minute, 8); err == nil || !strings.Contains(err.Error(), "issuer keys is a nil *keys.JWKSIssuerKeySource") {
		t.Errorf("NewJWTAccessTokens(nil *JWKSIssuerKeySource) error = %v", err)
	}
	if _, err := resource.NewOpaqueAccessTokens((*memstore.AccessTokenStore)(nil), issuer); err == nil || !strings.Contains(err.Error(), "store is a nil *memstore.AccessTokenStore") {
		t.Errorf("NewOpaqueAccessTokens(nil *AccessTokenStore) error = %v", err)
	}

	for name, tc := range map[string]struct {
		production bool
		resolver   resource.AccessTokenResolver
		want       string
	}{
		"jwt literal": {false, resource.JWTAccessTokens{
			IssuerKeys: (*keys.JWKSIssuerKeySource)(nil), Issuer: issuer, Audience: testIssuer,
			Algorithm: fapi.ES256, MaxTokenLifetime: 5 * time.Minute, MaxKeyCandidates: 8,
		}, "access_tokens (JWTAccessTokens): issuer keys is a nil *keys.JWKSIssuerKeySource"},
		"opaque literal by pointer": {false, &resource.OpaqueAccessTokens{
			Store: (*memstore.AccessTokenStore)(nil), Issuer: issuer,
		}, "access_tokens (OpaqueAccessTokens): store is a nil *memstore.AccessTokenStore"},
		"declared issuer keys": {true, declaringResolver{declared: resource.AccessTokenAssurance{
			IssuerKeys: (*declaredKeys)(nil),
		}}, "AccessTokenAssurance.IssuerKeys is a nil *resource_test.declaredKeys"},
		"declared store": {true, declaringResolver{declared: resource.AccessTokenAssurance{
			Store: (*memstore.AccessTokenStore)(nil),
		}}, "AccessTokenAssurance.Store is a nil *memstore.AccessTokenStore"},
	} {
		t.Run(name, func(t *testing.T) {
			cfg, deps := validConfig(t), validDependencies(t)
			if tc.production {
				cfg, deps = productionSetup(t)
			}
			deps.AccessTokens = tc.resolver
			if _, err := resource.NewVerifier(cfg, deps); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("NewVerifier error = %v, want it to contain %q", err, tc.want)
			}
		})
	}
}
