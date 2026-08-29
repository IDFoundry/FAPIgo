package storage

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
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

	// RFC 6749 §4.1.2: on a reuse, the store must report what the
	// original redemption issued (via errors.As into
	// *AuthorizationCodeAlreadyRedeemedError) so the caller can revoke
	// it — see RecordIssuedAccessToken/RecordIssuedRefreshToken's own
	// doc comments.
	t.Run("RedeemAuthorizationCodeReuseReportsIssuedTokens", func(t *testing.T) {
		store := factory()
		ctx := context.Background()
		hash := sha256.Sum256([]byte("reuse-reports-code"))
		if err := store.CreateAuthorizationCode(ctx, NewAuthorizationCode{
			CodeHash: hash, ClientID: "client-1", ExpiresAt: time.Now().Add(time.Minute),
		}); err != nil {
			t.Fatalf("CreateAuthorizationCode: %v", err)
		}
		if _, err := store.RedeemAuthorizationCode(ctx, AuthorizationCodeRedemption{CodeHash: hash}); err != nil {
			t.Fatalf("first RedeemAuthorizationCode: %v", err)
		}
		refreshHash := sha256.Sum256([]byte("reuse-reports-refresh"))
		if err := store.RecordIssuedAccessToken(ctx, hash, "jti-1", time.Now().Add(time.Minute)); err != nil {
			t.Fatalf("RecordIssuedAccessToken: %v", err)
		}
		if err := store.RecordIssuedRefreshToken(ctx, hash, refreshHash, time.Now().Add(time.Hour)); err != nil {
			t.Fatalf("RecordIssuedRefreshToken: %v", err)
		}

		_, err := store.RedeemAuthorizationCode(ctx, AuthorizationCodeRedemption{CodeHash: hash})
		if err == nil {
			t.Fatal("second RedeemAuthorizationCode = nil error, want error")
		}
		var alreadyRedeemed *AuthorizationCodeAlreadyRedeemedError
		if !errors.As(err, &alreadyRedeemed) {
			t.Fatalf("second RedeemAuthorizationCode error = %v, want errors.As into *AuthorizationCodeAlreadyRedeemedError", err)
		}
		if alreadyRedeemed.IssuedAccessTokenKey != "jti-1" {
			t.Fatalf("IssuedAccessTokenKey = %q, want %q", alreadyRedeemed.IssuedAccessTokenKey, "jti-1")
		}
		if alreadyRedeemed.IssuedRefreshTokenHash == nil || *alreadyRedeemed.IssuedRefreshTokenHash != refreshHash {
			t.Fatalf("IssuedRefreshTokenHash = %v, want %v", alreadyRedeemed.IssuedRefreshTokenHash, refreshHash)
		}
	})

	// Graceful degradation: a deployment that never calls
	// RecordIssuedAccessToken/RecordIssuedRefreshToken (no-op
	// implementation, or simply never invoked) still gets a normal
	// reuse rejection — the error just carries nothing to revoke.
	t.Run("RedeemAuthorizationCodeReuseWithoutRecordingReportsEmpty", func(t *testing.T) {
		store := factory()
		ctx := context.Background()
		hash := sha256.Sum256([]byte("reuse-no-recording-code"))
		if err := store.CreateAuthorizationCode(ctx, NewAuthorizationCode{
			CodeHash: hash, ClientID: "client-1", ExpiresAt: time.Now().Add(time.Minute),
		}); err != nil {
			t.Fatalf("CreateAuthorizationCode: %v", err)
		}
		if _, err := store.RedeemAuthorizationCode(ctx, AuthorizationCodeRedemption{CodeHash: hash}); err != nil {
			t.Fatalf("first RedeemAuthorizationCode: %v", err)
		}

		_, err := store.RedeemAuthorizationCode(ctx, AuthorizationCodeRedemption{CodeHash: hash})
		if err == nil {
			t.Fatal("second RedeemAuthorizationCode = nil error, want error")
		}
		var alreadyRedeemed *AuthorizationCodeAlreadyRedeemedError
		if errors.As(err, &alreadyRedeemed) {
			if alreadyRedeemed.IssuedAccessTokenKey != "" {
				t.Fatalf("IssuedAccessTokenKey = %q, want \"\" (never recorded)", alreadyRedeemed.IssuedAccessTokenKey)
			}
			if alreadyRedeemed.IssuedRefreshTokenHash != nil {
				t.Fatalf("IssuedRefreshTokenHash = %v, want nil (never recorded)", alreadyRedeemed.IssuedRefreshTokenHash)
			}
		}
		// Not requiring errors.As to succeed here at all: an
		// implementation is free to return a plain error for this case
		// too, as long as *if* it returns the typed error, the payload
		// is empty rather than stale/wrong.
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

	// RFC 6749 §4.1.2: a specific refresh token can be revoked (e.g.
	// because its originating authorization code was reused) even
	// though refresh tokens aren't single-use in the ordinary case.
	t.Run("RevokeRefreshTokenPreventsRedemption", func(t *testing.T) {
		store := factory()
		ctx := context.Background()
		hash := sha256.Sum256([]byte("revoked-refresh"))
		if err := store.CreateRefreshToken(ctx, NewRefreshToken{
			TokenHash: hash, ClientID: "client-1", ExpiresAt: time.Now().Add(time.Hour),
		}); err != nil {
			t.Fatalf("CreateRefreshToken: %v", err)
		}
		if _, err := store.RedeemRefreshToken(ctx, RefreshTokenRedemption{TokenHash: hash}); err != nil {
			t.Fatalf("RedeemRefreshToken before revocation: %v", err)
		}
		if err := store.RevokeRefreshToken(ctx, hash); err != nil {
			t.Fatalf("RevokeRefreshToken: %v", err)
		}
		if _, err := store.RedeemRefreshToken(ctx, RefreshTokenRedemption{TokenHash: hash}); err == nil {
			t.Fatal("RedeemRefreshToken after revocation = nil error, want error")
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

	t.Run("CreatePARAndBeginAuthorization", func(t *testing.T) { testTransactionStoreCreatePARAndBeginAuthorization(t, factory) })
	t.Run("BeginAuthorizationRepeatsUntilCompleted", func(t *testing.T) { testTransactionStoreBeginAuthorizationRepeatsUntilCompleted(t, factory) })
	t.Run("BeginAuthorizationFailsAfterCompletion", func(t *testing.T) { testTransactionStoreBeginAuthorizationFailsAfterCompletion(t, factory) })
	t.Run("BeginAuthorizationUnknownReferenceFails", func(t *testing.T) { testTransactionStoreBeginAuthorizationUnknownReferenceFails(t, factory) })
	t.Run("ConcurrentBeginAuthorizationAllSucceedBeforeCompletion", func(t *testing.T) {
		testTransactionStoreConcurrentBeginAuthorizationAllSucceedBeforeCompletion(t, factory)
	})
	t.Run("CompleteAuthorizationAndIsSingleUse", func(t *testing.T) { testTransactionStoreCompleteAuthorizationAndIsSingleUse(t, factory) })
	t.Run("CompleteAuthorizationUnknownHandleFails", func(t *testing.T) { testTransactionStoreCompleteAuthorizationUnknownHandleFails(t, factory) })
	t.Run("ConcurrentCompleteAuthorizationHasExactlyOneWinner", func(t *testing.T) {
		testTransactionStoreConcurrentCompleteAuthorizationHasExactlyOneWinner(t, factory)
	})
	t.Run("ConcurrentCompleteAuthorizationAcrossHandlesForSameReferenceHasExactlyOneWinner", func(t *testing.T) {
		testTransactionStoreConcurrentCompleteAuthorizationAcrossHandlesForSameReferenceHasExactlyOneWinner(t, factory)
	})
}

func testTransactionStoreCreatePARAndBeginAuthorization(t *testing.T, factory func() TransactionStore) {
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
}

// testTransactionStoreBeginAuthorizationRepeatsUntilCompleted covers
// FAPI 2.0 Security Profile 5.3.2.2 Note 3: one-time use of request_uri
// must be enforced at the point of authorization, not at the point of
// visiting the authorization endpoint — so revisiting the authorization
// endpoint before ever completing the interaction (e.g. the browser
// reloading, or being sent back before authenticating) must be allowed
// to mint a fresh Handle for the same Reference, not fail outright.
func testTransactionStoreBeginAuthorizationRepeatsUntilCompleted(t *testing.T, factory func() TransactionStore) {
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
	}); err != nil {
		t.Fatalf("second BeginAuthorization (before completion) = %v, want success", err)
	}
}

func testTransactionStoreBeginAuthorizationFailsAfterCompletion(t *testing.T, factory func() TransactionStore) {
	store := factory()
	ctx := context.Background()
	if err := store.CreatePAR(ctx, NewPARRecord{
		Reference: "ref-2c", ClientID: "client-1", ExpiresAt: time.Now().Add(time.Minute),
	}); err != nil {
		t.Fatalf("CreatePAR: %v", err)
	}
	if _, err := store.BeginAuthorization(ctx, BeginAuthorizationTransaction{
		Reference: "ref-2c", Handle: "handle-2c", HandleExpiresAt: time.Now().Add(time.Minute),
	}); err != nil {
		t.Fatalf("BeginAuthorization: %v", err)
	}
	if _, err := store.CompleteAuthorization(ctx, CompleteAuthorizationTransaction{Handle: "handle-2c"}); err != nil {
		t.Fatalf("CompleteAuthorization: %v", err)
	}
	if _, err := store.BeginAuthorization(ctx, BeginAuthorizationTransaction{
		Reference: "ref-2c", Handle: "handle-2d", HandleExpiresAt: time.Now().Add(time.Minute),
	}); err == nil {
		t.Fatalf("BeginAuthorization after completion = nil error, want error")
	}
}

func testTransactionStoreBeginAuthorizationUnknownReferenceFails(t *testing.T, factory func() TransactionStore) {
	store := factory()
	if _, err := store.BeginAuthorization(context.Background(), BeginAuthorizationTransaction{
		Reference: "never-created", Handle: "handle-x", HandleExpiresAt: time.Now().Add(time.Minute),
	}); err == nil {
		t.Fatalf("BeginAuthorization(unknown reference) = nil error, want error")
	}
}

// testTransactionStoreConcurrentBeginAuthorizationAllSucceedBeforeCompletion:
// each concurrent Begin mints its own Handle for the same Reference;
// none of them has completed anything yet, so none should be rejected —
// see testTransactionStoreBeginAuthorizationRepeatsUntilCompleted.
func testTransactionStoreConcurrentBeginAuthorizationAllSucceedBeforeCompletion(t *testing.T, factory func() TransactionStore) {
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
	if successes != contractConcurrentAttempts {
		t.Fatalf("concurrent BeginAuthorization succeeded %d times, want all %d", successes, contractConcurrentAttempts)
	}
}

func testTransactionStoreCompleteAuthorizationAndIsSingleUse(t *testing.T, factory func() TransactionStore) {
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
}

func testTransactionStoreCompleteAuthorizationUnknownHandleFails(t *testing.T, factory func() TransactionStore) {
	store := factory()
	if _, err := store.CompleteAuthorization(context.Background(), CompleteAuthorizationTransaction{Handle: "never-began"}); err == nil {
		t.Fatalf("CompleteAuthorization(unknown handle) = nil error, want error")
	}
}

func testTransactionStoreConcurrentCompleteAuthorizationHasExactlyOneWinner(t *testing.T, factory func() TransactionStore) {
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
}

// testTransactionStoreConcurrentCompleteAuthorizationAcrossHandlesForSameReferenceHasExactlyOneWinner:
// multiple Handles minted from the same Reference (e.g. several browser
// visits before authentication) must still yield exactly one completed
// interaction between them — the single-use guarantee is on the
// Reference, not any individual Handle.
func testTransactionStoreConcurrentCompleteAuthorizationAcrossHandlesForSameReferenceHasExactlyOneWinner(t *testing.T, factory func() TransactionStore) {
	store := factory()
	ctx := context.Background()
	if err := store.CreatePAR(ctx, NewPARRecord{
		Reference: "ref-6", ClientID: "client-1", ExpiresAt: time.Now().Add(time.Minute),
	}); err != nil {
		t.Fatalf("CreatePAR: %v", err)
	}
	handles := make([]string, contractConcurrentAttempts)
	for i := range handles {
		handles[i] = fmt.Sprintf("handle-6-%d", i)
		if _, err := store.BeginAuthorization(ctx, BeginAuthorizationTransaction{
			Reference: "ref-6", Handle: handles[i], HandleExpiresAt: time.Now().Add(time.Minute),
		}); err != nil {
			t.Fatalf("BeginAuthorization(%s): %v", handles[i], err)
		}
	}
	var indexMu sync.Mutex
	next := 0
	successes := runConcurrently(len(handles), func() bool {
		indexMu.Lock()
		handle := handles[next]
		next++
		indexMu.Unlock()
		_, err := store.CompleteAuthorization(ctx, CompleteAuthorizationTransaction{Handle: handle})
		return err == nil
	})
	if successes != 1 {
		t.Fatalf("concurrent CompleteAuthorization across handles for one reference succeeded %d times, want exactly 1", successes)
	}
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

	t.Run("CreateAndConsume", func(t *testing.T) { testSessionStoreCreateAndConsume(t, factory) })
	t.Run("ConsumeIsSingleUse", func(t *testing.T) { testSessionStoreConsumeIsSingleUse(t, factory) })
	t.Run("ConsumeUnknownStateFails", func(t *testing.T) { testSessionStoreConsumeUnknownStateFails(t, factory) })
	t.Run("ConcurrentConsumeHasExactlyOneWinner", func(t *testing.T) { testSessionStoreConcurrentConsumeHasExactlyOneWinner(t, factory) })
}

func testSessionStoreCreateAndConsume(t *testing.T, factory func() SessionStore) {
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
}

func testSessionStoreConsumeIsSingleUse(t *testing.T, factory func() SessionStore) {
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
}

func testSessionStoreConsumeUnknownStateFails(t *testing.T, factory func() SessionStore) {
	store := factory()
	if _, err := store.Consume(context.Background(), SessionConsumption{State: "never-created"}); err == nil {
		t.Fatalf("Consume(unknown state) = nil error, want error")
	}
}

func testSessionStoreConcurrentConsumeHasExactlyOneWinner(t *testing.T, factory func() SessionStore) {
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
}

// TestNonceStoreContract exercises factory()'s behavior against the
// guarantees NonceStore's documentation promises: an issued nonce is
// atomically single-use, an unknown nonce is rejected, and concurrent
// consumption of the same nonce has exactly one winner. factory must
// return a fresh, empty NonceStore each call.
func TestNonceStoreContract(t *testing.T, factory func() NonceStore) {
	t.Helper()

	t.Run("IssueThenConsumeRoundTripsExpiry", func(t *testing.T) { testNonceStoreIssueThenConsumeRoundTripsExpiry(t, factory) })
	t.Run("ConsumeIsSingleUse", func(t *testing.T) { testNonceStoreConsumeIsSingleUse(t, factory) })
	t.Run("ConsumeUnknownNonceFails", func(t *testing.T) { testNonceStoreConsumeUnknownNonceFails(t, factory) })
	t.Run("ConcurrentConsumeHasExactlyOneWinner", func(t *testing.T) { testNonceStoreConcurrentConsumeHasExactlyOneWinner(t, factory) })
}

func testNonceStoreIssueThenConsumeRoundTripsExpiry(t *testing.T, factory func() NonceStore) {
	store := factory()
	ctx := context.Background()
	expiresAt := time.Now().Add(time.Minute).Truncate(time.Second)
	if err := store.Issue(ctx, NonceIssuance{Nonce: "nonce-1", ExpiresAt: expiresAt}); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	got, err := store.Consume(ctx, NonceConsumption{Nonce: "nonce-1"})
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if !got.ExpiresAt.Equal(expiresAt) {
		t.Fatalf("Consume returned ExpiresAt %v, want %v", got.ExpiresAt, expiresAt)
	}
}

func testNonceStoreConsumeIsSingleUse(t *testing.T, factory func() NonceStore) {
	store := factory()
	ctx := context.Background()
	if err := store.Issue(ctx, NonceIssuance{Nonce: "nonce-2", ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if _, err := store.Consume(ctx, NonceConsumption{Nonce: "nonce-2"}); err != nil {
		t.Fatalf("first Consume: %v", err)
	}
	if _, err := store.Consume(ctx, NonceConsumption{Nonce: "nonce-2"}); err == nil {
		t.Fatalf("second Consume = nil error, want error")
	}
}

func testNonceStoreConsumeUnknownNonceFails(t *testing.T, factory func() NonceStore) {
	store := factory()
	if _, err := store.Consume(context.Background(), NonceConsumption{Nonce: "never-issued"}); err == nil {
		t.Fatalf("Consume(unknown nonce) = nil error, want error")
	}
}

func testNonceStoreConcurrentConsumeHasExactlyOneWinner(t *testing.T, factory func() NonceStore) {
	store := factory()
	ctx := context.Background()
	if err := store.Issue(ctx, NonceIssuance{Nonce: "nonce-3", ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	successes := runConcurrently(contractConcurrentAttempts, func() bool {
		_, err := store.Consume(ctx, NonceConsumption{Nonce: "nonce-3"})
		return err == nil
	})
	if successes != 1 {
		t.Fatalf("concurrent Consume succeeded %d times, want exactly 1", successes)
	}
}

// TestAccessTokenStoreContract exercises factory()'s behavior against
// the guarantees AccessTokenStore's documentation promises: a created
// token's fields round-trip faithfully through LookupAccessToken, and
// an unknown hash is rejected. factory must return a fresh, empty
// AccessTokenStore each call.
func TestAccessTokenStoreContract(t *testing.T, factory func() AccessTokenStore) {
	t.Helper()

	t.Run("CreateThenLookupRoundTripsFields", func(t *testing.T) {
		store := factory()
		ctx := context.Background()
		hash := sha256.Sum256([]byte("access-token-1"))
		expiresAt := time.Now().Add(5 * time.Minute).Truncate(time.Second)
		claims := map[string]json.RawMessage{"custom_claim": json.RawMessage(`"value"`)}
		if err := store.CreateAccessToken(ctx, NewAccessToken{
			TokenHash:       hash,
			ClientID:        "client-1",
			Subject:         "user-1",
			Scope:           []string{"openid", "accounts"},
			Thumbprint:      "thumbprint-1",
			SenderConstrain: SenderConstrainMTLS,
			Claims:          claims,
			ExpiresAt:       expiresAt,
		}); err != nil {
			t.Fatalf("CreateAccessToken: %v", err)
		}

		looked, err := store.LookupAccessToken(ctx, AccessTokenLookup{TokenHash: hash})
		if err != nil {
			t.Fatalf("LookupAccessToken: %v", err)
		}
		if looked.ClientID != "client-1" {
			t.Errorf("ClientID = %q, want %q", looked.ClientID, "client-1")
		}
		if looked.Subject != "user-1" {
			t.Errorf("Subject = %q, want %q", looked.Subject, "user-1")
		}
		if len(looked.Scope) != 2 || looked.Scope[0] != "openid" || looked.Scope[1] != "accounts" {
			t.Errorf("Scope = %v, want [openid accounts]", looked.Scope)
		}
		if looked.Thumbprint != "thumbprint-1" {
			t.Errorf("Thumbprint = %q, want %q", looked.Thumbprint, "thumbprint-1")
		}
		// SenderConstrain round-trips as a real, independent value —
		// not just whatever the zero value happens to be — proving a
		// store that special-cased or ignored it (e.g. only persisting
		// SenderConstrainDPoP) would be caught here.
		if looked.SenderConstrain != SenderConstrainMTLS {
			t.Errorf("SenderConstrain = %v, want SenderConstrainMTLS", looked.SenderConstrain)
		}
		if string(looked.Claims["custom_claim"]) != `"value"` {
			t.Errorf("Claims[custom_claim] = %s, want %q", looked.Claims["custom_claim"], "value")
		}
		if !looked.ExpiresAt.Equal(expiresAt) {
			t.Errorf("ExpiresAt = %v, want %v", looked.ExpiresAt, expiresAt)
		}
	})

	// TestAccessTokenStoreContract's own round-trip case above sets
	// SenderConstrainMTLS explicitly (a non-zero value) so a store that
	// silently ignored the field would still be caught; this case
	// separately confirms the zero value (SenderConstrainDPoP) itself
	// round-trips too, rather than being conflated with "field absent".
	t.Run("SenderConstrainDPoPZeroValueRoundTrips", func(t *testing.T) {
		store := factory()
		ctx := context.Background()
		hash := sha256.Sum256([]byte("access-token-dpop"))
		if err := store.CreateAccessToken(ctx, NewAccessToken{
			TokenHash: hash, ClientID: "client-1", Subject: "user-1",
			Thumbprint: "thumbprint-1", SenderConstrain: SenderConstrainDPoP,
			ExpiresAt: time.Now().Add(5 * time.Minute),
		}); err != nil {
			t.Fatalf("CreateAccessToken: %v", err)
		}
		looked, err := store.LookupAccessToken(ctx, AccessTokenLookup{TokenHash: hash})
		if err != nil {
			t.Fatalf("LookupAccessToken: %v", err)
		}
		if looked.SenderConstrain != SenderConstrainDPoP {
			t.Errorf("SenderConstrain = %v, want SenderConstrainDPoP", looked.SenderConstrain)
		}
	})

	t.Run("LookupUnknownTokenFails", func(t *testing.T) {
		store := factory()
		hash := sha256.Sum256([]byte("never-created"))
		if _, err := store.LookupAccessToken(context.Background(), AccessTokenLookup{TokenHash: hash}); err == nil {
			t.Fatalf("LookupAccessToken(unknown) = nil error, want error")
		}
	})

	t.Run("LookupExpiredTokenStillReturnsIt", func(t *testing.T) {
		// AccessTokenStore doesn't self-expire (see its own doc
		// comment) — the caller checks ExpiresAt itself, the same way
		// every other *Redeemed/LookedUp* type in this package is
		// checked by its caller.
		store := factory()
		ctx := context.Background()
		hash := sha256.Sum256([]byte("expired-token"))
		expiresAt := time.Now().Add(-time.Minute)
		if err := store.CreateAccessToken(ctx, NewAccessToken{
			TokenHash: hash, ClientID: "client-1", Subject: "user-1",
			ExpiresAt: expiresAt,
		}); err != nil {
			t.Fatalf("CreateAccessToken: %v", err)
		}
		looked, err := store.LookupAccessToken(ctx, AccessTokenLookup{TokenHash: hash})
		if err != nil {
			t.Fatalf("LookupAccessToken: %v", err)
		}
		if !looked.ExpiresAt.Equal(expiresAt) {
			t.Errorf("ExpiresAt = %v, want %v", looked.ExpiresAt, expiresAt)
		}
	})
}

// TestBackchannelAuthenticationStoreContract exercises factory()'s
// behavior against the guarantees BackchannelAuthenticationStore's
// documentation promises: DecideBackchannelAuthentication is single-use;
// PollBackchannelAuthentication is reusable for Pending/Denied/AuthenticationFailed
// but single-use for the first Approved observation (mirroring
// RedeemRefreshToken's and RedeemAuthorizationCode's contracts
// respectively, layered on one interface); expiry and slow-down are
// enforced. factory must return a fresh, empty
// BackchannelAuthenticationStore each call.
func TestBackchannelAuthenticationStoreContract(t *testing.T, factory func() BackchannelAuthenticationStore) {
	t.Helper()

	newRecord := func(authReqID, handle string) NewBackchannelAuthentication {
		return NewBackchannelAuthentication{
			AuthReqIDHash: sha256.Sum256([]byte(authReqID)),
			HandleHash:    sha256.Sum256([]byte(handle)),
			ClientID:      "client-1",
			Parameters:    map[string]json.RawMessage{"scope": json.RawMessage(`"openid"`)},
			TokenClaims:   map[string]json.RawMessage{"custom_claim": json.RawMessage(`"value"`)},
			DeliveryMode:  "poll",
			DPoPJKT:       "jkt-1",
			PollInterval:  time.Millisecond,
			ExpiresAt:     time.Now().Add(time.Minute),
		}
	}

	t.Run("CreateThenPollReturnsPending", func(t *testing.T) {
		store := factory()
		ctx := context.Background()
		want := newRecord("auth-req-1", "handle-1")
		if err := store.CreateBackchannelAuthentication(ctx, want); err != nil {
			t.Fatalf("CreateBackchannelAuthentication: %v", err)
		}
		got, err := store.PollBackchannelAuthentication(ctx, PollBackchannelAuthentication{
			AuthReqIDHash: want.AuthReqIDHash, Now: time.Now(),
		})
		if err != nil {
			t.Fatalf("PollBackchannelAuthentication: %v", err)
		}
		if got.Status != BackchannelAuthenticationPending {
			t.Fatalf("Status = %v, want Pending", got.Status)
		}
		if got.ClientID != want.ClientID {
			t.Fatalf("ClientID = %q, want %q", got.ClientID, want.ClientID)
		}
	})

	t.Run("DecideThenPollReturnsApprovedFieldsRoundTripped", func(t *testing.T) {
		store := factory()
		ctx := context.Background()
		record := newRecord("auth-req-2", "handle-2")
		if err := store.CreateBackchannelAuthentication(ctx, record); err != nil {
			t.Fatalf("CreateBackchannelAuthentication: %v", err)
		}
		authTime := time.Now().Truncate(time.Second)
		if _, err := store.DecideBackchannelAuthentication(ctx, DecideBackchannelAuthentication{
			HandleHash: record.HandleHash, Status: BackchannelAuthenticationApproved,
			Subject: "user-1", Scope: []string{"openid", "accounts"},
			AuthTime: authTime, ACR: "acr-1", AMR: []string{"pwd"},
		}); err != nil {
			t.Fatalf("DecideBackchannelAuthentication: %v", err)
		}
		got, err := store.PollBackchannelAuthentication(ctx, PollBackchannelAuthentication{
			AuthReqIDHash: record.AuthReqIDHash, Now: time.Now(),
		})
		if err != nil {
			t.Fatalf("PollBackchannelAuthentication: %v", err)
		}
		if got.Status != BackchannelAuthenticationApproved || got.Subject != "user-1" ||
			len(got.Scope) != 2 || got.ACR != "acr-1" || !got.AuthTime.Equal(authTime) ||
			got.DPoPJKT != record.DPoPJKT || string(got.TokenClaims["custom_claim"]) != `"value"` {
			t.Fatalf("PollBackchannelAuthentication returned %+v, want fields matching decision+record", got)
		}
	})

	// DecideBackchannelAuthentication's own return value must round-trip
	// DeliveryMode/ClientNotificationToken straight from the record
	// CreateBackchannelAuthentication persisted — the caller needs both
	// to dispatch a CIBA §10.2 ping notification without a second round
	// trip to this store.
	t.Run("DecideReturnsPingDeliveryModeAndNotificationTokenFromRecord", func(t *testing.T) {
		const wantAuthReqID = "auth-req-ping-1"
		store := factory()
		ctx := context.Background()
		record := newRecord(wantAuthReqID, "handle-ping-1")
		record.DeliveryMode = "ping"
		record.ClientNotificationToken = fapi.NewSecret("notification-token-1")
		record.AuthReqID = wantAuthReqID
		if err := store.CreateBackchannelAuthentication(ctx, record); err != nil {
			t.Fatalf("CreateBackchannelAuthentication: %v", err)
		}
		decided, err := store.DecideBackchannelAuthentication(ctx, DecideBackchannelAuthentication{
			HandleHash: record.HandleHash, Status: BackchannelAuthenticationDenied,
		})
		if err != nil {
			t.Fatalf("DecideBackchannelAuthentication: %v", err)
		}
		if decided.ClientID != record.ClientID {
			t.Fatalf("ClientID = %q, want %q", decided.ClientID, record.ClientID)
		}
		if decided.DeliveryMode != "ping" {
			t.Fatalf("DeliveryMode = %q, want %q", decided.DeliveryMode, "ping")
		}
		if decided.ClientNotificationToken.Reveal() != "notification-token-1" {
			t.Fatalf("ClientNotificationToken = %q, want %q", decided.ClientNotificationToken.Reveal(), "notification-token-1")
		}
		if decided.AuthReqID != wantAuthReqID {
			t.Fatalf("AuthReqID = %q, want %q", decided.AuthReqID, wantAuthReqID)
		}
	})

	// The poll-mode default (newRecord's own shape) round-trips too —
	// an empty ClientNotificationToken, not just a non-empty one.
	t.Run("DecideReturnsPollDeliveryModeAndEmptyNotificationTokenFromRecord", func(t *testing.T) {
		store := factory()
		ctx := context.Background()
		record := newRecord("auth-req-poll-1", "handle-poll-1")
		if err := store.CreateBackchannelAuthentication(ctx, record); err != nil {
			t.Fatalf("CreateBackchannelAuthentication: %v", err)
		}
		decided, err := store.DecideBackchannelAuthentication(ctx, DecideBackchannelAuthentication{
			HandleHash: record.HandleHash, Status: BackchannelAuthenticationDenied,
		})
		if err != nil {
			t.Fatalf("DecideBackchannelAuthentication: %v", err)
		}
		if decided.DeliveryMode != "poll" {
			t.Fatalf("DeliveryMode = %q, want %q", decided.DeliveryMode, "poll")
		}
		if decided.ClientNotificationToken.Reveal() != "" {
			t.Fatalf("ClientNotificationToken = %q, want empty", decided.ClientNotificationToken.Reveal())
		}
		if decided.AuthReqID != "" {
			t.Fatalf("AuthReqID = %q, want empty", decided.AuthReqID)
		}
	})

	t.Run("DecideBackchannelAuthenticationIsSingleUse", func(t *testing.T) {
		store := factory()
		ctx := context.Background()
		record := newRecord("auth-req-3", "handle-3")
		if err := store.CreateBackchannelAuthentication(ctx, record); err != nil {
			t.Fatalf("CreateBackchannelAuthentication: %v", err)
		}
		if _, err := store.DecideBackchannelAuthentication(ctx, DecideBackchannelAuthentication{
			HandleHash: record.HandleHash, Status: BackchannelAuthenticationDenied,
		}); err != nil {
			t.Fatalf("first DecideBackchannelAuthentication: %v", err)
		}
		if _, err := store.DecideBackchannelAuthentication(ctx, DecideBackchannelAuthentication{
			HandleHash: record.HandleHash, Status: BackchannelAuthenticationApproved, Subject: "user-1",
		}); err == nil {
			t.Fatalf("second DecideBackchannelAuthentication = nil error, want error")
		}
	})

	t.Run("ConcurrentDecideBackchannelAuthenticationHasExactlyOneWinner", func(t *testing.T) {
		store := factory()
		ctx := context.Background()
		record := newRecord("auth-req-4", "handle-4")
		if err := store.CreateBackchannelAuthentication(ctx, record); err != nil {
			t.Fatalf("CreateBackchannelAuthentication: %v", err)
		}
		successes := runConcurrently(contractConcurrentAttempts, func() bool {
			_, err := store.DecideBackchannelAuthentication(ctx, DecideBackchannelAuthentication{
				HandleHash: record.HandleHash, Status: BackchannelAuthenticationDenied,
			})
			return err == nil
		})
		if successes != 1 {
			t.Fatalf("concurrent DecideBackchannelAuthentication succeeded %d times, want exactly 1", successes)
		}
	})

	// Denied/AuthenticationFailed polls are freely repeatable — the
	// client keeps polling and must keep observing the same terminal
	// outcome, mirroring RedeemRefreshToken's reusable contract rather
	// than RedeemAuthorizationCode's single-use one.
	t.Run("PollAfterDeniedIsRepeatable", func(t *testing.T) {
		store := factory()
		ctx := context.Background()
		record := newRecord("auth-req-5", "handle-5")
		if err := store.CreateBackchannelAuthentication(ctx, record); err != nil {
			t.Fatalf("CreateBackchannelAuthentication: %v", err)
		}
		if _, err := store.DecideBackchannelAuthentication(ctx, DecideBackchannelAuthentication{
			HandleHash: record.HandleHash, Status: BackchannelAuthenticationDenied, Reason: "user declined",
		}); err != nil {
			t.Fatalf("DecideBackchannelAuthentication: %v", err)
		}
		for i := 0; i < 2; i++ {
			got, err := store.PollBackchannelAuthentication(ctx, PollBackchannelAuthentication{
				AuthReqIDHash: record.AuthReqIDHash, Now: time.Now().Add(time.Duration(i) * time.Second),
			})
			if err != nil {
				t.Fatalf("poll %d: %v", i, err)
			}
			if got.Status != BackchannelAuthenticationDenied || got.Reason != "user declined" {
				t.Fatalf("poll %d returned %+v, want Denied/%q", i, got, "user declined")
			}
		}
	})

	// The first poll to observe Approved consumes it — a second poll for
	// the same auth_req_id must report
	// *BackchannelAuthenticationAlreadyRedeemedError, the
	// RedeemAuthorizationCode-style single-use guarantee.
	t.Run("PollAfterApprovedIsSingleUse", func(t *testing.T) {
		store := factory()
		ctx := context.Background()
		record := newRecord("auth-req-6", "handle-6")
		if err := store.CreateBackchannelAuthentication(ctx, record); err != nil {
			t.Fatalf("CreateBackchannelAuthentication: %v", err)
		}
		if _, err := store.DecideBackchannelAuthentication(ctx, DecideBackchannelAuthentication{
			HandleHash: record.HandleHash, Status: BackchannelAuthenticationApproved, Subject: "user-1",
		}); err != nil {
			t.Fatalf("DecideBackchannelAuthentication: %v", err)
		}
		if _, err := store.PollBackchannelAuthentication(ctx, PollBackchannelAuthentication{
			AuthReqIDHash: record.AuthReqIDHash, Now: time.Now(),
		}); err != nil {
			t.Fatalf("first poll: %v", err)
		}
		_, err := store.PollBackchannelAuthentication(ctx, PollBackchannelAuthentication{
			AuthReqIDHash: record.AuthReqIDHash, Now: time.Now().Add(time.Second),
		})
		if err == nil {
			t.Fatalf("second poll after Approved = nil error, want error")
		}
		var alreadyRedeemed *BackchannelAuthenticationAlreadyRedeemedError
		if !errors.As(err, &alreadyRedeemed) {
			t.Fatalf("second poll error = %v, want errors.As into *BackchannelAuthenticationAlreadyRedeemedError", err)
		}
	})

	t.Run("ConcurrentPollAfterApprovedHasExactlyOneWinner", func(t *testing.T) {
		store := factory()
		ctx := context.Background()
		record := newRecord("auth-req-7", "handle-7")
		if err := store.CreateBackchannelAuthentication(ctx, record); err != nil {
			t.Fatalf("CreateBackchannelAuthentication: %v", err)
		}
		if _, err := store.DecideBackchannelAuthentication(ctx, DecideBackchannelAuthentication{
			HandleHash: record.HandleHash, Status: BackchannelAuthenticationApproved, Subject: "user-1",
		}); err != nil {
			t.Fatalf("DecideBackchannelAuthentication: %v", err)
		}
		now := time.Now()
		successes := runConcurrently(contractConcurrentAttempts, func() bool {
			_, err := store.PollBackchannelAuthentication(ctx, PollBackchannelAuthentication{
				AuthReqIDHash: record.AuthReqIDHash, Now: now,
			})
			return err == nil
		})
		if successes != 1 {
			t.Fatalf("concurrent poll-after-Approved succeeded %d times, want exactly 1", successes)
		}
	})

	t.Run("PollUnknownAuthReqIDFails", func(t *testing.T) {
		store := factory()
		hash := sha256.Sum256([]byte("never-created"))
		if _, err := store.PollBackchannelAuthentication(context.Background(), PollBackchannelAuthentication{
			AuthReqIDHash: hash, Now: time.Now(),
		}); err == nil {
			t.Fatalf("PollBackchannelAuthentication(unknown) = nil error, want error")
		}
	})

	// A poll after ExpiresAt must report expiry regardless of decision
	// status — even one that would otherwise report Approved.
	t.Run("PollAfterExpiryFailsEvenWhenApproved", func(t *testing.T) {
		store := factory()
		ctx := context.Background()
		record := newRecord("auth-req-8", "handle-8")
		record.ExpiresAt = time.Now().Add(time.Millisecond)
		if err := store.CreateBackchannelAuthentication(ctx, record); err != nil {
			t.Fatalf("CreateBackchannelAuthentication: %v", err)
		}
		if _, err := store.DecideBackchannelAuthentication(ctx, DecideBackchannelAuthentication{
			HandleHash: record.HandleHash, Status: BackchannelAuthenticationApproved, Subject: "user-1",
		}); err != nil {
			t.Fatalf("DecideBackchannelAuthentication: %v", err)
		}
		_, err := store.PollBackchannelAuthentication(ctx, PollBackchannelAuthentication{
			AuthReqIDHash: record.AuthReqIDHash, Now: record.ExpiresAt.Add(time.Second),
		})
		if err == nil {
			t.Fatalf("poll after expiry = nil error, want error")
		}
		var expired *BackchannelAuthenticationExpiredError
		if !errors.As(err, &expired) {
			t.Fatalf("poll after expiry error = %v, want errors.As into *BackchannelAuthenticationExpiredError", err)
		}
	})

	// Two polls closer together than PollInterval: the second must be
	// rejected with *BackchannelAuthenticationSlowDownError, driven by
	// injected Now rather than a real sleep.
	t.Run("PollFasterThanIntervalFails", func(t *testing.T) {
		store := factory()
		ctx := context.Background()
		record := newRecord("auth-req-9", "handle-9")
		record.PollInterval = 5 * time.Second
		if err := store.CreateBackchannelAuthentication(ctx, record); err != nil {
			t.Fatalf("CreateBackchannelAuthentication: %v", err)
		}
		now := time.Now()
		if _, err := store.PollBackchannelAuthentication(ctx, PollBackchannelAuthentication{
			AuthReqIDHash: record.AuthReqIDHash, Now: now,
		}); err != nil {
			t.Fatalf("first poll: %v", err)
		}
		_, err := store.PollBackchannelAuthentication(ctx, PollBackchannelAuthentication{
			AuthReqIDHash: record.AuthReqIDHash, Now: now.Add(time.Second),
		})
		if err == nil {
			t.Fatalf("poll faster than interval = nil error, want error")
		}
		var slowDown *BackchannelAuthenticationSlowDownError
		if !errors.As(err, &slowDown) {
			t.Fatalf("poll faster than interval error = %v, want errors.As into *BackchannelAuthenticationSlowDownError", err)
		}
	})

	// ...but a poll spaced at least PollInterval apart from the previous
	// one succeeds.
	t.Run("PollSpacedByAtLeastIntervalSucceeds", func(t *testing.T) {
		store := factory()
		ctx := context.Background()
		record := newRecord("auth-req-10", "handle-10")
		record.PollInterval = 5 * time.Second
		if err := store.CreateBackchannelAuthentication(ctx, record); err != nil {
			t.Fatalf("CreateBackchannelAuthentication: %v", err)
		}
		now := time.Now()
		if _, err := store.PollBackchannelAuthentication(ctx, PollBackchannelAuthentication{
			AuthReqIDHash: record.AuthReqIDHash, Now: now,
		}); err != nil {
			t.Fatalf("first poll: %v", err)
		}
		if _, err := store.PollBackchannelAuthentication(ctx, PollBackchannelAuthentication{
			AuthReqIDHash: record.AuthReqIDHash, Now: now.Add(record.PollInterval),
		}); err != nil {
			t.Fatalf("second poll (spaced by interval): %v, want success", err)
		}
	})
}
