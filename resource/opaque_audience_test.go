package resource_test

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/idfoundry/fapigo/resource"
	"github.com/idfoundry/fapigo/storage"
	"github.com/idfoundry/fapigo/storage/memstore"
)

// opaqueTokenRecordedFor stores an opaque access token whose record
// holds claims, and returns its raw value.
func opaqueTokenRecordedFor(t *testing.T, store *memstore.AccessTokenStore, claims map[string]json.RawMessage) string {
	t.Helper()
	raw := "token-" + t.Name()
	if err := store.CreateAccessToken(context.Background(), storage.NewAccessToken{
		TokenHash: sha256.Sum256([]byte(raw)), ClientID: "client-1", Subject: "user-1",
		Claims: claims, ExpiresAt: time.Now().Add(time.Minute),
	}); err != nil {
		t.Fatalf("CreateAccessToken: %v", err)
	}
	return raw
}

func TestOpaqueAccessTokensAudience(t *testing.T) {
	const (
		rsA    = "https://a.example.com"
		rsB    = "https://b.example.com"
		issuer = "https://as.example.com"
	)
	recorded := func(aud ...string) map[string]json.RawMessage {
		raw, _ := json.Marshal(aud)
		return map[string]json.RawMessage{"iss": json.RawMessage(`"` + testIssuer + `"`), "aud": raw, "custom": json.RawMessage(`"x"`)}
	}
	without := func(claims map[string]json.RawMessage, name string) map[string]json.RawMessage {
		delete(claims, name)
		return claims
	}
	withIssuer := func(claims map[string]json.RawMessage, iss string) map[string]json.RawMessage {
		claims["iss"] = json.RawMessage(iss)
		return claims
	}
	for name, tc := range map[string]struct {
		claims     map[string]json.RawMessage
		audience   string
		additional []string
		wantCode   resource.ErrorCode
		wantAud    []string
	}{
		"no check":                   {claims: recorded(rsA), wantAud: []string{rsA}},
		"own":                        {claims: recorded(rsA), audience: rsA, wantAud: []string{rsA}},
		"one of several":             {claims: recorded(rsB, rsA), audience: rsA, wantAud: []string{rsB, rsA}},
		"another's":                  {claims: recorded(rsA), audience: rsB, wantCode: resource.ErrorInvalidToken},
		"issuer token":               {claims: recorded(issuer), audience: rsB, wantCode: resource.ErrorInvalidToken},
		"issuer token while moving":  {claims: recorded(issuer), audience: rsB, additional: []string{issuer}, wantAud: []string{issuer}},
		"another's while moving":     {claims: recorded(rsA), audience: rsB, additional: []string{issuer}, wantCode: resource.ErrorInvalidToken},
		"record without an audience": {claims: without(recorded(), "aud"), audience: rsB, wantCode: resource.ErrorInvalidToken},
		"no audience, no check":      {claims: without(recorded(), "aud")},
		"malformed record":           {claims: withIssuer(map[string]json.RawMessage{"aud": json.RawMessage(`"` + rsB + `"`)}, `"`+testIssuer+`"`), audience: rsB, wantCode: resource.ErrorServerError},
		"empty record":               {claims: withIssuer(map[string]json.RawMessage{"aud": json.RawMessage(`[]`)}, `"`+testIssuer+`"`), wantCode: resource.ErrorServerError},
		"another issuer's":           {claims: withIssuer(recorded(rsA), `"https://other.example.com"`), audience: rsA, wantCode: resource.ErrorInvalidToken},
		"another issuer's, no check": {claims: withIssuer(recorded(rsA), `"https://other.example.com"`), wantCode: resource.ErrorInvalidToken},
		"record without an issuer":   {claims: without(recorded(rsA), "iss"), audience: rsA, wantCode: resource.ErrorInvalidToken},
		"record without any":         {claims: map[string]json.RawMessage{"custom": json.RawMessage(`"x"`)}, wantCode: resource.ErrorInvalidToken},
		"malformed issuer":           {claims: withIssuer(recorded(rsA), `42`), audience: rsA, wantCode: resource.ErrorServerError},
		"empty issuer":               {claims: withIssuer(recorded(rsA), `""`), audience: rsA, wantCode: resource.ErrorServerError},
	} {
		t.Run(name, func(t *testing.T) {
			store := memstore.NewAccessTokenStore()
			raw := opaqueTokenRecordedFor(t, store, tc.claims)
			resolver := resource.OpaqueAccessTokens{Issuer: testIssuerURL, Store: store, Audience: tc.audience, AdditionalAudiences: tc.additional}
			resolved, err := resolver.ResolveAccessToken(context.Background(), resource.ResolveAccessTokenRequest{Raw: raw, Now: time.Now()})
			if tc.wantCode != "" {
				var rerr *resource.Error
				if !errors.As(err, &rerr) || rerr.Code() != tc.wantCode {
					t.Fatalf("ResolveAccessToken = %v, want %q", err, tc.wantCode)
				}
				return
			}
			if err != nil {
				t.Fatalf("ResolveAccessToken: %v", err)
			}
			checkResolvedOpaqueAudience(t, resolved, tc.wantAud)
		})
	}
}

// checkResolvedOpaqueAudience checks resolved has testIssuer as its
// Issuer and wantAud as its Audience, both kept out of its claims, and
// the record's other claim kept.
func checkResolvedOpaqueAudience(t *testing.T, resolved resource.ResolvedAccessToken, wantAud []string) {
	t.Helper()
	if resolved.Issuer != testIssuer {
		t.Errorf("Issuer = %q, want %q", resolved.Issuer, testIssuer)
	}
	if !reflect.DeepEqual(resolved.Audience, wantAud) {
		t.Errorf("Audience = %v, want %v", resolved.Audience, wantAud)
	}
	for _, name := range []string{"iss", "aud"} {
		if _, ok := resolved.Claims[name]; ok {
			t.Errorf("Claims has %q, want it only as Issuer or Audience", name)
		}
	}
	if string(resolved.Claims["custom"]) != `"x"` {
		t.Errorf("Claims = %v, want custom kept", resolved.Claims)
	}
}

func TestOpaqueAccessTokensAudienceOnlyClaimLeavesNoClaims(t *testing.T) {
	store := memstore.NewAccessTokenStore()
	raw := opaqueTokenRecordedFor(t, store, map[string]json.RawMessage{"iss": json.RawMessage(`"` + testIssuer + `"`), "aud": json.RawMessage(`["https://a.example.com"]`)})
	resolved, err := resource.OpaqueAccessTokens{Issuer: testIssuerURL, Store: store}.ResolveAccessToken(context.Background(), resource.ResolveAccessTokenRequest{Raw: raw, Now: time.Now()})
	if err != nil {
		t.Fatalf("ResolveAccessToken: %v", err)
	}
	if resolved.Claims != nil {
		t.Errorf("Claims = %v, want nil", resolved.Claims)
	}
}

func TestOpaqueAccessTokensAudienceValidation(t *testing.T) {
	store := memstore.NewAccessTokenStore()
	for name, o := range map[string]resource.OpaqueAccessTokens{
		"no issuer":                   {Store: store},
		"additional without audience": {Issuer: testIssuerURL, Store: store, AdditionalAudiences: []string{"https://as.example.com"}},
		"empty additional":            {Issuer: testIssuerURL, Store: store, Audience: "https://a.example.com", AdditionalAudiences: []string{""}},
	} {
		t.Run(name, func(t *testing.T) {
			deps := validDependencies(t)
			deps.AccessTokens = o
			if _, err := resource.NewVerifier(validConfig(t), deps); err == nil {
				t.Fatal("NewVerifier accepted an invalid OpaqueAccessTokens")
			}
		})
	}
}

func TestJWTAccessTokensRejectsEmptyAdditionalAudience(t *testing.T) {
	deps := validDependencies(t)
	jwt, ok := deps.AccessTokens.(resource.JWTAccessTokens)
	if !ok {
		t.Fatalf("validDependencies AccessTokens = %T", deps.AccessTokens)
	}
	jwt.AdditionalAudiences = []string{""}
	deps.AccessTokens = jwt
	if _, err := resource.NewVerifier(validConfig(t), deps); err == nil {
		t.Fatal("NewVerifier accepted an empty additional audience")
	}
}
