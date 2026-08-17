package storage

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"
)

// This file is a reusable contract test suite, not a _test.go file,
// specifically so a downstream (or first-party) storage implementation
// can import it and run it against its own factory — see
// ARCHITECTURE.md design rule 13 and StoreAssurance's doc comment for
// what these functions do and don't verify.

const contractConcurrentAttempts = 20

// runConcurrently calls fn attempts times in parallel and returns how
// many calls returned true.
func runConcurrently(attempts int, fn func() bool) int {
	var wg sync.WaitGroup
	var mu sync.Mutex
	successes := 0
	wg.Add(attempts)
	for i := 0; i < attempts; i++ {
		go func() {
			defer wg.Done()
			if fn() {
				mu.Lock()
				successes++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	return successes
}

// TestGrantStoreContract exercises factory()'s behavior against the
// guarantees GrantStore's documentation promises: atomic single-use
// redemption of authorization codes and refresh tokens, faithful
// round-tripping of stored fields, and exactly one winner under
// concurrent redemption of the same code or token. factory must return
// a fresh, empty GrantStore each call — its subtests share nothing
// between them.
func TestGrantStoreContract(t *testing.T, factory func() GrantStore) {
	t.Helper()

	t.Run("CreateAndRedeemAuthorizationCode", func(t *testing.T) {
		store := factory()
		ctx := context.Background()
		hash := sha256.Sum256([]byte("test-code"))
		want := NewAuthorizationCode{
			CodeHash: hash, ClientID: "client-1", RedirectURI: "https://rp.example/cb",
			CodeChallenge: "challenge", CodeChallengeMethod: "S256",
			DPoPJKT: "jkt-1",
			Subject: "user-1", Scope: []string{"openid", "accounts"},
			Nonce: "nonce-1", AuthTime: time.Now().Truncate(time.Second),
			ACR: "acr-1", AMR: []string{"pwd"},
			RequestedIDTokenClaims: []string{"name"}, RequestedUserinfoClaims: []string{"email"},
			ExpiresAt: time.Now().Add(time.Minute),
		}
		if err := store.CreateAuthorizationCode(ctx, want); err != nil {
			t.Fatalf("CreateAuthorizationCode: %v", err)
		}
		got, err := store.RedeemAuthorizationCode(ctx, AuthorizationCodeRedemption{CodeHash: hash})
		if err != nil {
			t.Fatalf("RedeemAuthorizationCode: %v", err)
		}
		if got.ClientID != want.ClientID || got.RedirectURI != want.RedirectURI ||
			got.CodeChallenge != want.CodeChallenge || got.CodeChallengeMethod != want.CodeChallengeMethod ||
			got.DPoPJKT != want.DPoPJKT ||
			got.Subject != want.Subject || got.Nonce != want.Nonce ||
			!got.AuthTime.Equal(want.AuthTime) || got.ACR != want.ACR ||
			!got.ExpiresAt.Equal(want.ExpiresAt) || len(got.Scope) != len(want.Scope) ||
			len(got.RequestedIDTokenClaims) != len(want.RequestedIDTokenClaims) ||
			len(got.RequestedUserinfoClaims) != len(want.RequestedUserinfoClaims) {
			t.Fatalf("RedeemAuthorizationCode returned %+v, want fields matching %+v", got, want)
		}
	})

	t.Run("RedeemAuthorizationCodeIsSingleUse", func(t *testing.T) {
		store := factory()
		ctx := context.Background()
		hash := sha256.Sum256([]byte("single-use-code"))
		if err := store.CreateAuthorizationCode(ctx, NewAuthorizationCode{
			CodeHash: hash, ClientID: "client-1", ExpiresAt: time.Now().Add(time.Minute),
		}); err != nil {
			t.Fatalf("CreateAuthorizationCode: %v", err)
		}
		if _, err := store.RedeemAuthorizationCode(ctx, AuthorizationCodeRedemption{CodeHash: hash}); err != nil {
			t.Fatalf("first RedeemAuthorizationCode: %v", err)
		}
		if _, err := store.RedeemAuthorizationCode(ctx, AuthorizationCodeRedemption{CodeHash: hash}); err == nil {
			t.Fatalf("second RedeemAuthorizationCode = nil error, want error")
		}
	})

	t.Run("RedeemUnknownAuthorizationCodeFails", func(t *testing.T) {
		store := factory()
		hash := sha256.Sum256([]byte("never-created"))
		if _, err := store.RedeemAuthorizationCode(context.Background(), AuthorizationCodeRedemption{CodeHash: hash}); err == nil {
			t.Fatalf("RedeemAuthorizationCode(unknown) = nil error, want error")
		}
	})

	t.Run("ConcurrentRedeemAuthorizationCodeHasExactlyOneWinner", func(t *testing.T) {
		store := factory()
		ctx := context.Background()
		hash := sha256.Sum256([]byte("concurrent-code"))
		if err := store.CreateAuthorizationCode(ctx, NewAuthorizationCode{
			CodeHash: hash, ClientID: "client-1", ExpiresAt: time.Now().Add(time.Minute),
		}); err != nil {
			t.Fatalf("CreateAuthorizationCode: %v", err)
		}
		successes := runConcurrently(contractConcurrentAttempts, func() bool {
			_, err := store.RedeemAuthorizationCode(ctx, AuthorizationCodeRedemption{CodeHash: hash})
			return err == nil
		})
		if successes != 1 {
			t.Fatalf("concurrent RedeemAuthorizationCode succeeded %d times, want exactly 1", successes)
		}
	})

	t.Run("CreateAndRedeemRefreshToken", func(t *testing.T) {
		store := factory()
		ctx := context.Background()
		hash := sha256.Sum256([]byte("test-refresh"))
		want := NewRefreshToken{
			TokenHash: hash, ClientID: "client-1", Subject: "user-1",
			Scope: []string{"openid", "offline_access"}, Thumbprint: "thumb-1",
			AuthTime: time.Now().Truncate(time.Second), ACR: "acr-1", AMR: []string{"pwd"},
			RequestedIDTokenClaims: []string{"name"}, RequestedUserinfoClaims: []string{"email"},
			ExpiresAt: time.Now().Add(time.Hour),
		}
		if err := store.CreateRefreshToken(ctx, want); err != nil {
			t.Fatalf("CreateRefreshToken: %v", err)
		}
		got, err := store.RedeemRefreshToken(ctx, RefreshTokenRedemption{TokenHash: hash})
		if err != nil {
			t.Fatalf("RedeemRefreshToken: %v", err)
		}
		if got.ClientID != want.ClientID || got.Subject != want.Subject ||
			got.Thumbprint != want.Thumbprint || got.ACR != want.ACR ||
			!got.AuthTime.Equal(want.AuthTime) || !got.ExpiresAt.Equal(want.ExpiresAt) ||
			len(got.RequestedIDTokenClaims) != len(want.RequestedIDTokenClaims) ||
			len(got.RequestedUserinfoClaims) != len(want.RequestedUserinfoClaims) {
			t.Fatalf("RedeemRefreshToken returned %+v, want fields matching %+v", got, want)
		}
	})

	// Deliberately not single-use — see GrantStore.RedeemRefreshToken's
	// doc comment (FAPI2-SP-FINAL 5.3.2.1-9): a refresh token stays
	// valid for repeated use until it expires, unlike an authorization
	// code. Contrast with RedeemAuthorizationCodeIsSingleUse above.
	t.Run("RedeemRefreshTokenIsReusable", func(t *testing.T) {
		store := factory()
		ctx := context.Background()
		hash := sha256.Sum256([]byte("reusable-refresh"))
		if err := store.CreateRefreshToken(ctx, NewRefreshToken{
			TokenHash: hash, ClientID: "client-1", ExpiresAt: time.Now().Add(time.Hour),
		}); err != nil {
			t.Fatalf("CreateRefreshToken: %v", err)
		}
		if _, err := store.RedeemRefreshToken(ctx, RefreshTokenRedemption{TokenHash: hash}); err != nil {
			t.Fatalf("first RedeemRefreshToken: %v", err)
		}
		if _, err := store.RedeemRefreshToken(ctx, RefreshTokenRedemption{TokenHash: hash}); err != nil {
			t.Fatalf("second RedeemRefreshToken: %v, want success (refresh tokens are not single-use)", err)
		}
	})

	t.Run("RedeemUnknownRefreshTokenFails", func(t *testing.T) {
		store := factory()
		hash := sha256.Sum256([]byte("never-created-refresh"))
		if _, err := store.RedeemRefreshToken(context.Background(), RefreshTokenRedemption{TokenHash: hash}); err == nil {
			t.Fatalf("RedeemRefreshToken(unknown) = nil error, want error")
		}
	})

	t.Run("ConcurrentRedeemRefreshTokenAllSucceed", func(t *testing.T) {
		store := factory()
		ctx := context.Background()
		hash := sha256.Sum256([]byte("concurrent-refresh"))
		if err := store.CreateRefreshToken(ctx, NewRefreshToken{
			TokenHash: hash, ClientID: "client-1", ExpiresAt: time.Now().Add(time.Hour),
		}); err != nil {
			t.Fatalf("CreateRefreshToken: %v", err)
		}
		successes := runConcurrently(contractConcurrentAttempts, func() bool {
			_, err := store.RedeemRefreshToken(ctx, RefreshTokenRedemption{TokenHash: hash})
			return err == nil
		})
		if successes != contractConcurrentAttempts {
			t.Fatalf("concurrent RedeemRefreshToken succeeded %d/%d times, want all of them (not single-use)", successes, contractConcurrentAttempts)
		}
	})
}

// TestTransactionStoreContract exercises factory()'s behavior against
// the guarantees TransactionStore's documentation promises: a pushed
// request_uri and an interaction handle are each atomically single-use,
// and stored fields round-trip faithfully. factory must return a fresh,
// empty TransactionStore each call.
func TestTransactionStoreContract(t *testing.T, factory func() TransactionStore) {
	t.Helper()

	t.Run("CreatePARAndBeginAuthorization", func(t *testing.T) {
		store := factory()
		ctx := context.Background()
		params := map[string]json.RawMessage{"scope": json.RawMessage(`"openid"`)}
		if err := store.CreatePAR(ctx, NewPARRecord{
			Reference: "ref-1", ClientID: "client-1", Parameters: params,
			ExpiresAt: time.Now().Add(time.Minute),
		}); err != nil {
			t.Fatalf("CreatePAR: %v", err)
		}
		got, err := store.BeginAuthorization(ctx, BeginAuthorizationTransaction{
			Reference: "ref-1", Handle: "handle-1", HandleExpiresAt: time.Now().Add(time.Minute),
		})
		if err != nil {
			t.Fatalf("BeginAuthorization: %v", err)
		}
		if got.ClientID != "client-1" {
			t.Fatalf("ClientID = %q, want client-1", got.ClientID)
		}
		if string(got.Parameters["scope"]) != `"openid"` {
			t.Fatalf("Parameters[scope] = %s, want \"openid\"", got.Parameters["scope"])
		}
	})

	t.Run("BeginAuthorizationIsSingleUse", func(t *testing.T) {
		store := factory()
		ctx := context.Background()
		if err := store.CreatePAR(ctx, NewPARRecord{
			Reference: "ref-2", ClientID: "client-1", ExpiresAt: time.Now().Add(time.Minute),
		}); err != nil {
			t.Fatalf("CreatePAR: %v", err)
		}
		if _, err := store.BeginAuthorization(ctx, BeginAuthorizationTransaction{
			Reference: "ref-2", Handle: "handle-2a", HandleExpiresAt: time.Now().Add(time.Minute),
		}); err != nil {
			t.Fatalf("first BeginAuthorization: %v", err)
		}
		if _, err := store.BeginAuthorization(ctx, BeginAuthorizationTransaction{
			Reference: "ref-2", Handle: "handle-2b", HandleExpiresAt: time.Now().Add(time.Minute),
		}); err == nil {
			t.Fatalf("second BeginAuthorization = nil error, want error")
		}
	})

	t.Run("BeginAuthorizationUnknownReferenceFails", func(t *testing.T) {
		store := factory()
		if _, err := store.BeginAuthorization(context.Background(), BeginAuthorizationTransaction{
			Reference: "never-created", Handle: "handle-x", HandleExpiresAt: time.Now().Add(time.Minute),
		}); err == nil {
			t.Fatalf("BeginAuthorization(unknown reference) = nil error, want error")
		}
	})

	t.Run("ConcurrentBeginAuthorizationHasExactlyOneWinner", func(t *testing.T) {
		store := factory()
		ctx := context.Background()
		if err := store.CreatePAR(ctx, NewPARRecord{
			Reference: "ref-3", ClientID: "client-1", ExpiresAt: time.Now().Add(time.Minute),
		}); err != nil {
			t.Fatalf("CreatePAR: %v", err)
		}
		var counterMu sync.Mutex
		counter := 0
		successes := runConcurrently(contractConcurrentAttempts, func() bool {
			counterMu.Lock()
			counter++
			handle := fmt.Sprintf("handle-3-%d", counter)
			counterMu.Unlock()
			_, err := store.BeginAuthorization(ctx, BeginAuthorizationTransaction{
				Reference: "ref-3", Handle: handle, HandleExpiresAt: time.Now().Add(time.Minute),
			})
			return err == nil
		})
		if successes != 1 {
			t.Fatalf("concurrent BeginAuthorization succeeded %d times, want exactly 1", successes)
		}
	})

	t.Run("CompleteAuthorizationAndIsSingleUse", func(t *testing.T) {
		store := factory()
		ctx := context.Background()
		if err := store.CreatePAR(ctx, NewPARRecord{
			Reference: "ref-4", ClientID: "client-1", ExpiresAt: time.Now().Add(time.Minute),
		}); err != nil {
			t.Fatalf("CreatePAR: %v", err)
		}
		if _, err := store.BeginAuthorization(ctx, BeginAuthorizationTransaction{
			Reference: "ref-4", Handle: "handle-4", HandleExpiresAt: time.Now().Add(time.Minute),
		}); err != nil {
			t.Fatalf("BeginAuthorization: %v", err)
		}
		completed, err := store.CompleteAuthorization(ctx, CompleteAuthorizationTransaction{Handle: "handle-4"})
		if err != nil {
			t.Fatalf("first CompleteAuthorization: %v", err)
		}
		if completed.ClientID != "client-1" {
			t.Fatalf("ClientID = %q, want client-1", completed.ClientID)
		}
		if _, err := store.CompleteAuthorization(ctx, CompleteAuthorizationTransaction{Handle: "handle-4"}); err == nil {
			t.Fatalf("second CompleteAuthorization = nil error, want error")
		}
	})

	t.Run("CompleteAuthorizationUnknownHandleFails", func(t *testing.T) {
		store := factory()
		if _, err := store.CompleteAuthorization(context.Background(), CompleteAuthorizationTransaction{Handle: "never-began"}); err == nil {
			t.Fatalf("CompleteAuthorization(unknown handle) = nil error, want error")
		}
	})

	t.Run("ConcurrentCompleteAuthorizationHasExactlyOneWinner", func(t *testing.T) {
		store := factory()
		ctx := context.Background()
		if err := store.CreatePAR(ctx, NewPARRecord{
			Reference: "ref-5", ClientID: "client-1", ExpiresAt: time.Now().Add(time.Minute),
		}); err != nil {
			t.Fatalf("CreatePAR: %v", err)
		}
		if _, err := store.BeginAuthorization(ctx, BeginAuthorizationTransaction{
			Reference: "ref-5", Handle: "handle-5", HandleExpiresAt: time.Now().Add(time.Minute),
		}); err != nil {
			t.Fatalf("BeginAuthorization: %v", err)
		}
		successes := runConcurrently(contractConcurrentAttempts, func() bool {
			_, err := store.CompleteAuthorization(ctx, CompleteAuthorizationTransaction{Handle: "handle-5"})
			return err == nil
		})
		if successes != 1 {
			t.Fatalf("concurrent CompleteAuthorization succeeded %d times, want exactly 1", successes)
		}
	})
}

// TestReplayStoreContract exercises factory()'s behavior against the
// guarantees ReplayStore's documentation promises: a digest is single-use
// within its namespace, the same digest in a different namespace never
// collides, and concurrent uses of the same digest have exactly one
// winner. factory must return a fresh, empty ReplayStore each call.
func TestReplayStoreContract(t *testing.T, factory func() ReplayStore) {
	t.Helper()

	t.Run("FirstUseSucceeds", func(t *testing.T) {
		store := factory()
		digest := sha256.Sum256([]byte("jti-1"))
		if err := store.UseOnce(context.Background(), ReplayUse{
			Namespace: "test:ns", Digest: digest, ExpiresAt: time.Now().Add(time.Minute),
		}); err != nil {
			t.Fatalf("UseOnce: %v", err)
		}
	})

	t.Run("SecondUseInSameNamespaceFails", func(t *testing.T) {
		store := factory()
		ctx := context.Background()
		digest := sha256.Sum256([]byte("jti-2"))
		use := ReplayUse{Namespace: "test:ns", Digest: digest, ExpiresAt: time.Now().Add(time.Minute)}
		if err := store.UseOnce(ctx, use); err != nil {
			t.Fatalf("first UseOnce: %v", err)
		}
		if err := store.UseOnce(ctx, use); err == nil {
			t.Fatalf("second UseOnce = nil error, want error")
		}
	})

	t.Run("SameDigestInDifferentNamespaceSucceeds", func(t *testing.T) {
		store := factory()
		ctx := context.Background()
		digest := sha256.Sum256([]byte("jti-3"))
		if err := store.UseOnce(ctx, ReplayUse{Namespace: "test:ns-a", Digest: digest, ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
			t.Fatalf("UseOnce(ns-a): %v", err)
		}
		if err := store.UseOnce(ctx, ReplayUse{Namespace: "test:ns-b", Digest: digest, ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
			t.Fatalf("UseOnce(ns-b) = %v, want nil (different namespace must not collide)", err)
		}
	})

	t.Run("ConcurrentUseOnceHasExactlyOneWinner", func(t *testing.T) {
		store := factory()
		ctx := context.Background()
		digest := sha256.Sum256([]byte("jti-4"))
		successes := runConcurrently(contractConcurrentAttempts, func() bool {
			err := store.UseOnce(ctx, ReplayUse{Namespace: "test:concurrent", Digest: digest, ExpiresAt: time.Now().Add(time.Minute)})
			return err == nil
		})
		if successes != 1 {
			t.Fatalf("concurrent UseOnce succeeded %d times, want exactly 1", successes)
		}
	})
}

// TestSessionStoreContract exercises factory()'s behavior against the
// guarantees SessionStore's documentation promises: a session is
// atomically single-use by State, stored fields round-trip faithfully,
// and concurrent consumption of the same State has exactly one winner.
// factory must return a fresh, empty SessionStore each call.
func TestSessionStoreContract(t *testing.T, factory func() SessionStore) {
	t.Helper()

	t.Run("CreateAndConsume", func(t *testing.T) {
		store := factory()
		ctx := context.Background()
		want := NewSession{
			State: "state-1", Nonce: "nonce-1", PKCEVerifier: "verifier-1",
			ExpectedIssuer: "https://as.example", ExpectedRedirectURI: "https://rp.example/cb",
			ExpectedResponseMode: "plain", ExpiresAt: time.Now().Add(time.Minute),
		}
		if err := store.Create(ctx, want); err != nil {
			t.Fatalf("Create: %v", err)
		}
		got, err := store.Consume(ctx, SessionConsumption{State: "state-1"})
		if err != nil {
			t.Fatalf("Consume: %v", err)
		}
		if got.Nonce != want.Nonce || got.PKCEVerifier != want.PKCEVerifier ||
			got.ExpectedIssuer != want.ExpectedIssuer || got.ExpectedRedirectURI != want.ExpectedRedirectURI ||
			got.ExpectedResponseMode != want.ExpectedResponseMode || !got.ExpiresAt.Equal(want.ExpiresAt) {
			t.Fatalf("Consume returned %+v, want fields matching %+v", got, want)
		}
	})

	t.Run("ConsumeIsSingleUse", func(t *testing.T) {
		store := factory()
		ctx := context.Background()
		if err := store.Create(ctx, NewSession{State: "state-2", ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
			t.Fatalf("Create: %v", err)
		}
		if _, err := store.Consume(ctx, SessionConsumption{State: "state-2"}); err != nil {
			t.Fatalf("first Consume: %v", err)
		}
		if _, err := store.Consume(ctx, SessionConsumption{State: "state-2"}); err == nil {
			t.Fatalf("second Consume = nil error, want error")
		}
	})

	t.Run("ConsumeUnknownStateFails", func(t *testing.T) {
		store := factory()
		if _, err := store.Consume(context.Background(), SessionConsumption{State: "never-created"}); err == nil {
			t.Fatalf("Consume(unknown state) = nil error, want error")
		}
	})

	t.Run("ConcurrentConsumeHasExactlyOneWinner", func(t *testing.T) {
		store := factory()
		ctx := context.Background()
		if err := store.Create(ctx, NewSession{State: "state-3", ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
			t.Fatalf("Create: %v", err)
		}
		successes := runConcurrently(contractConcurrentAttempts, func() bool {
			_, err := store.Consume(ctx, SessionConsumption{State: "state-3"})
			return err == nil
		})
		if successes != 1 {
			t.Fatalf("concurrent Consume succeeded %d times, want exactly 1", successes)
		}
	})
}
