package memstore

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/idfoundry/fapigo/storage"
)

// testPayload is a stand-in for server's opaque Request/Grant values.
const testPayload = `{"v":1,"scope":"openid"}`

// tamper overwrites raw's first byte in place, the way a caller that
// kept (or received) a reference to a stored slice could.
func tamper(raw json.RawMessage) { raw[0] = 'X' }

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
		Reference: "ref-1",
		ClientID:  "client-1",
		Request:   json.RawMessage(testPayload),
		ExpiresAt: expires,
	}
	if err := s.CreatePAR(ctx, record); err != nil {
		t.Fatalf("CreatePAR: %v", err)
	}
	tamper(record.Request)

	par, err := s.BeginAuthorization(ctx, storage.BeginAuthorizationTransaction{
		Reference: "ref-1", Handle: "handle-1", HandleExpiresAt: expires,
	})
	if err != nil {
		t.Fatalf("BeginAuthorization: %v", err)
	}
	if got := string(par.Request); got != testPayload {
		t.Fatalf("Request = %s, want %s (CreatePAR aliased the caller's slice)", got, testPayload)
	}

	tamper(par.Request)

	completed, err := s.CompleteAuthorization(ctx, storage.CompleteAuthorizationTransaction{Handle: "handle-1"})
	if err != nil {
		t.Fatalf("CompleteAuthorization: %v", err)
	}
	if got := string(completed.Request); got != testPayload {
		t.Fatalf("CompletedInteraction.Request = %s, want %s (BeginAuthorization aliased its return value to internal state)", got, testPayload)
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
		Reference: "ref-2",
		ClientID:  "client-1",
		Request:   json.RawMessage(testPayload),
		ExpiresAt: expires,
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
	tamper(first.Request)

	second, err := s.BeginAuthorization(ctx, storage.BeginAuthorizationTransaction{
		Reference: "ref-2", Handle: "handle-b", HandleExpiresAt: expires,
	})
	if err != nil {
		t.Fatalf("BeginAuthorization(handle-b): %v", err)
	}
	if got := string(second.Request); got != testPayload {
		t.Fatalf("Request = %s, want %s (BeginAuthorization calls shared an aliased slice)", got, testPayload)
	}
}

// TestCreateAuthorizationCodeDoesNotAliasCallerSlices covers the
// write-side of M-5 for GrantStore: mutating the caller's own slice
// after CreateAuthorizationCode must not reach the stored code.
func TestCreateAuthorizationCodeDoesNotAliasCallerSlices(t *testing.T) {
	s := NewGrantStore()
	ctx := context.Background()

	code := storage.NewAuthorizationCode{
		CodeHash: [32]byte{1}, ClientID: "client-1",
		Grant: json.RawMessage(testPayload), ExpiresAt: time.Now().Add(time.Minute),
	}
	if err := s.CreateAuthorizationCode(ctx, code); err != nil {
		t.Fatalf("CreateAuthorizationCode: %v", err)
	}
	tamper(code.Grant)

	redeemed, err := s.RedeemAuthorizationCode(ctx, storage.AuthorizationCodeRedemption{CodeHash: [32]byte{1}})
	if err != nil {
		t.Fatalf("RedeemAuthorizationCode: %v", err)
	}
	if got := string(redeemed.Grant); got != testPayload {
		t.Fatalf("Grant = %s, want %s (CreateAuthorizationCode aliased the caller's slice)", got, testPayload)
	}
}

// TestRedeemRefreshTokenReturnsIndependentCopyEachTime covers the
// live-est case: RedeemRefreshToken is explicitly not single-use, so a
// caller mutating one redemption's returned Grant must not corrupt the
// next redemption of the same token.
func TestRedeemRefreshTokenReturnsIndependentCopyEachTime(t *testing.T) {
	s := NewGrantStore()
	ctx := context.Background()

	token := storage.NewRefreshToken{
		TokenHash: [32]byte{2}, ClientID: "client-1",
		Grant: json.RawMessage(testPayload), ExpiresAt: time.Now().Add(time.Hour),
	}
	if err := s.CreateRefreshToken(ctx, token); err != nil {
		t.Fatalf("CreateRefreshToken: %v", err)
	}

	first, err := s.RedeemRefreshToken(ctx, storage.RefreshTokenRedemption{TokenHash: [32]byte{2}})
	if err != nil {
		t.Fatalf("RedeemRefreshToken (first): %v", err)
	}
	tamper(first.Grant)

	second, err := s.RedeemRefreshToken(ctx, storage.RefreshTokenRedemption{TokenHash: [32]byte{2}})
	if err != nil {
		t.Fatalf("RedeemRefreshToken (second): %v", err)
	}
	if got := string(second.Grant); got != testPayload {
		t.Fatalf("Grant = %s, want %s (RedeemRefreshToken calls shared an aliased slice)", got, testPayload)
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
		TokenHash: [32]byte{5}, ClientID: "client-1",
		Grant: json.RawMessage(testPayload), ExpiresAt: time.Now().Add(time.Hour),
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
			tamper(got.Grant)
		}()
	}
	wg.Wait()
}
