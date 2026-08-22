package memstore

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/idfoundry/fapigo/storage"
)

// TestTransactionStoreDoesNotAliasCallerOrInternalState covers both
// directions of M-5: mutating the caller's own record after CreatePAR
// must not reach what's stored, and mutating a returned
// PushedAuthorizationRequest must not corrupt what CompleteAuthorization
// later returns for the same handle.
func TestTransactionStoreDoesNotAliasCallerOrInternalState(t *testing.T) {
	s := NewTransactionStore()
	ctx := context.Background()
	expires := time.Now().Add(time.Hour)

	record := storage.NewPARRecord{
		Reference:   "ref-1",
		ClientID:    "client-1",
		Parameters:  map[string]json.RawMessage{"scope": json.RawMessage(`"openid"`)},
		TokenClaims: map[string]json.RawMessage{"acr": json.RawMessage(`"urn:acr:1"`)},
		ExpiresAt:   expires,
	}
	if err := s.CreatePAR(ctx, record); err != nil {
		t.Fatalf("CreatePAR: %v", err)
	}
	record.Parameters["scope"] = json.RawMessage(`"tampered-by-caller-after-create"`)

	par, err := s.BeginAuthorization(ctx, storage.BeginAuthorizationTransaction{
		Reference: "ref-1", Handle: "handle-1", HandleExpiresAt: expires,
	})
	if err != nil {
		t.Fatalf("BeginAuthorization: %v", err)
	}
	if got := string(par.Parameters["scope"]); got != `"openid"` {
		t.Fatalf("Parameters[scope] = %s, want %q (CreatePAR aliased the caller's map)", got, `"openid"`)
	}

	par.Parameters["scope"] = json.RawMessage(`"tampered-by-caller-after-begin"`)

	completed, err := s.CompleteAuthorization(ctx, storage.CompleteAuthorizationTransaction{Handle: "handle-1"})
	if err != nil {
		t.Fatalf("CompleteAuthorization: %v", err)
	}
	if got := string(completed.Parameters["scope"]); got != `"openid"` {
		t.Fatalf("CompletedInteraction.Parameters[scope] = %s, want %q (BeginAuthorization aliased its return value to internal state)", got, `"openid"`)
	}
}

// TestBeginAuthorizationReturnsIndependentCopyPerCall covers the
// documented multi-call case (BeginAuthorization may be called more
// than once per Reference): mutating one call's return value must not
// affect another's.
func TestBeginAuthorizationReturnsIndependentCopyPerCall(t *testing.T) {
	s := NewTransactionStore()
	ctx := context.Background()
	expires := time.Now().Add(time.Hour)

	record := storage.NewPARRecord{
		Reference:  "ref-2",
		ClientID:   "client-1",
		Parameters: map[string]json.RawMessage{"scope": json.RawMessage(`"openid"`)},
		ExpiresAt:  expires,
	}
	if err := s.CreatePAR(ctx, record); err != nil {
		t.Fatalf("CreatePAR: %v", err)
	}

	first, err := s.BeginAuthorization(ctx, storage.BeginAuthorizationTransaction{
		Reference: "ref-2", Handle: "handle-a", HandleExpiresAt: expires,
	})
	if err != nil {
		t.Fatalf("BeginAuthorization(handle-a): %v", err)
	}
	first.Parameters["scope"] = json.RawMessage(`"tampered"`)

	second, err := s.BeginAuthorization(ctx, storage.BeginAuthorizationTransaction{
		Reference: "ref-2", Handle: "handle-b", HandleExpiresAt: expires,
	})
	if err != nil {
		t.Fatalf("BeginAuthorization(handle-b): %v", err)
	}
	if got := string(second.Parameters["scope"]); got != `"openid"` {
		t.Fatalf("Parameters[scope] = %s, want %q (BeginAuthorization calls shared an aliased map)", got, `"openid"`)
	}
}

// TestCreateAuthorizationCodeDoesNotAliasCallerSlices covers the
// write-side of M-5 for GrantStore: mutating the caller's own slice
// after CreateAuthorizationCode must not reach the stored code.
func TestCreateAuthorizationCodeDoesNotAliasCallerSlices(t *testing.T) {
	s := NewGrantStore()
	ctx := context.Background()

	scope := []string{"openid", "profile"}
	code := storage.NewAuthorizationCode{
		CodeHash: [32]byte{1}, ClientID: "client-1", RedirectURI: "https://cb.example/callback",
		CodeChallenge: "challenge", CodeChallengeMethod: "S256", Subject: "sub-1",
		Scope: scope, AuthTime: time.Now(), ExpiresAt: time.Now().Add(time.Minute),
	}
	if err := s.CreateAuthorizationCode(ctx, code); err != nil {
		t.Fatalf("CreateAuthorizationCode: %v", err)
	}
	scope[0] = "tampered"

	redeemed, err := s.RedeemAuthorizationCode(ctx, storage.AuthorizationCodeRedemption{CodeHash: [32]byte{1}})
	if err != nil {
		t.Fatalf("RedeemAuthorizationCode: %v", err)
	}
	if redeemed.Scope[0] != "openid" {
		t.Fatalf("Scope[0] = %q, want %q (CreateAuthorizationCode aliased the caller's slice)", redeemed.Scope[0], "openid")
	}
}

// TestRedeemRefreshTokenReturnsIndependentCopyEachTime covers the
// live-est case: RedeemRefreshToken is explicitly not single-use, so a
// caller mutating one redemption's returned Scope must not corrupt the
// next redemption of the same token.
func TestRedeemRefreshTokenReturnsIndependentCopyEachTime(t *testing.T) {
	s := NewGrantStore()
	ctx := context.Background()

	token := storage.NewRefreshToken{
		TokenHash: [32]byte{2}, ClientID: "client-1", Subject: "sub-1",
		Scope: []string{"openid", "offline_access"}, ExpiresAt: time.Now().Add(time.Hour),
	}
	if err := s.CreateRefreshToken(ctx, token); err != nil {
		t.Fatalf("CreateRefreshToken: %v", err)
	}

	first, err := s.RedeemRefreshToken(ctx, storage.RefreshTokenRedemption{TokenHash: [32]byte{2}})
	if err != nil {
		t.Fatalf("RedeemRefreshToken (first): %v", err)
	}
	first.Scope[0] = "tampered"

	second, err := s.RedeemRefreshToken(ctx, storage.RefreshTokenRedemption{TokenHash: [32]byte{2}})
	if err != nil {
		t.Fatalf("RedeemRefreshToken (second): %v", err)
	}
	if second.Scope[0] != "openid" {
		t.Fatalf("Scope[0] = %q, want %q (RedeemRefreshToken calls shared an aliased slice)", second.Scope[0], "openid")
	}
}

// TestLookupAccessTokenReturnsIndependentCopyEachTime covers both
// directions for AccessTokenStore in one pass: a write-side mutation of
// the caller's slice after CreateAccessToken, and a read-side mutation
// of one LookupAccessToken call's return value, must neither reach a
// later lookup.
func TestLookupAccessTokenReturnsIndependentCopyEachTime(t *testing.T) {
	s := NewAccessTokenStore()
	ctx := context.Background()

	tok := storage.NewAccessToken{
		TokenHash: [32]byte{3}, ClientID: "client-1", Subject: "sub-1",
		Scope: []string{"openid"}, Claims: map[string]json.RawMessage{"acr": json.RawMessage(`"urn:acr:1"`)},
		ExpiresAt: time.Now().Add(time.Hour),
	}
	if err := s.CreateAccessToken(ctx, tok); err != nil {
		t.Fatalf("CreateAccessToken: %v", err)
	}
	tok.Scope[0] = "tampered-input"

	first, err := s.LookupAccessToken(ctx, storage.AccessTokenLookup{TokenHash: [32]byte{3}})
	if err != nil {
		t.Fatalf("LookupAccessToken (first): %v", err)
	}
	if first.Scope[0] != "openid" {
		t.Fatalf("Scope[0] = %q, want %q (CreateAccessToken aliased the caller's slice)", first.Scope[0], "openid")
	}
	first.Claims["acr"] = json.RawMessage(`"tampered"`)

	second, err := s.LookupAccessToken(ctx, storage.AccessTokenLookup{TokenHash: [32]byte{3}})
	if err != nil {
		t.Fatalf("LookupAccessToken (second): %v", err)
	}
	if got := string(second.Claims["acr"]); got != `"urn:acr:1"` {
		t.Fatalf("Claims[acr] = %s, want %q (LookupAccessToken calls shared an aliased map)", got, `"urn:acr:1"`)
	}
}

// TestConcurrentLookupAccessTokenNoRace runs many concurrent lookups of
// the same token, each mutating its own returned value — under -race,
// this fails if any two calls actually share the same backing map or
// slice.
func TestConcurrentLookupAccessTokenNoRace(t *testing.T) {
	s := NewAccessTokenStore()
	ctx := context.Background()
	tok := storage.NewAccessToken{
		TokenHash: [32]byte{4}, ClientID: "client-1", Subject: "sub-1",
		Scope: []string{"openid"}, Claims: map[string]json.RawMessage{"acr": json.RawMessage(`"urn:acr:1"`)},
		ExpiresAt: time.Now().Add(time.Hour),
	}
	if err := s.CreateAccessToken(ctx, tok); err != nil {
		t.Fatalf("CreateAccessToken: %v", err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, err := s.LookupAccessToken(ctx, storage.AccessTokenLookup{TokenHash: [32]byte{4}})
			if err != nil {
				t.Errorf("LookupAccessToken: %v", err)
				return
			}
			got.Scope[0] = "mutated"
			got.Claims["acr"] = json.RawMessage(`"mutated"`)
		}()
	}
	wg.Wait()
}

// TestConcurrentRedeemRefreshTokenNoRace is TestConcurrentLookupAccessTokenNoRace's
// counterpart for RedeemRefreshToken, the other repeatable-read path.
func TestConcurrentRedeemRefreshTokenNoRace(t *testing.T) {
	s := NewGrantStore()
	ctx := context.Background()
	token := storage.NewRefreshToken{
		TokenHash: [32]byte{5}, ClientID: "client-1", Subject: "sub-1",
		Scope: []string{"openid", "offline_access"}, ExpiresAt: time.Now().Add(time.Hour),
	}
	if err := s.CreateRefreshToken(ctx, token); err != nil {
		t.Fatalf("CreateRefreshToken: %v", err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, err := s.RedeemRefreshToken(ctx, storage.RefreshTokenRedemption{TokenHash: [32]byte{5}})
			if err != nil {
				t.Errorf("RedeemRefreshToken: %v", err)
				return
			}
			got.Scope[0] = "mutated"
		}()
	}
	wg.Wait()
}
