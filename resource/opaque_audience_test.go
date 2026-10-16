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
		return map[string]json.RawMessage{"aud": raw, "custom": json.RawMessage(`"x"`)}
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
		"record without an audience": {claims: map[string]json.RawMessage{"custom": json.RawMessage(`"x"`)}, audience: rsB},
		"malformed record":           {claims: map[string]json.RawMessage{"aud": json.RawMessage(`"` + rsB + `"`)}, audience: rsB, wantCode: resource.ErrorServerError},
		"empty record":               {claims: map[string]json.RawMessage{"aud": json.RawMessage(`[]`)}, wantCode: resource.ErrorServerError},
	} {
		t.Run(name, func(t *testing.T) {
			store := memstore.NewAccessTokenStore()
			raw := opaqueTokenRecordedFor(t, store, tc.claims)
			resolver := resource.OpaqueAccessTokens{Store: store, Audience: tc.audience, AdditionalAudiences: tc.additional}
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

// checkResolvedOpaqueAudience checks resolved has wantAud as its
// Audience, kept out of its claims, and the record's other claim kept.
func checkResolvedOpaqueAudience(t *testing.T, resolved resource.ResolvedAccessToken, wantAud []string) {
	t.Helper()
	if !reflect.DeepEqual(resolved.Audience, wantAud) {
		t.Errorf("Audience = %v, want %v", resolved.Audience, wantAud)
	}
	if _, ok := resolved.Claims["aud"]; ok {
		t.Error(`Claims has "aud", want it only as Audience`)
	}
	if string(resolved.Claims["custom"]) != `"x"` {
		t.Errorf("Claims = %v, want custom kept", resolved.Claims)
	}
}

func TestOpaqueAccessTokensAudienceOnlyClaimLeavesNoClaims(t *testing.T) {
	store := memstore.NewAccessTokenStore()
	raw := opaqueTokenRecordedFor(t, store, map[string]json.RawMessage{"aud": json.RawMessage(`["https://a.example.com"]`)})
	resolved, err := resource.OpaqueAccessTokens{Store: store}.ResolveAccessToken(context.Background(), resource.ResolveAccessTokenRequest{Raw: raw, Now: time.Now()})
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
		"additional without audience": {Store: store, AdditionalAudiences: []string{"https://as.example.com"}},
		"empty additional":            {Store: store, Audience: "https://a.example.com", AdditionalAudiences: []string{""}},
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
