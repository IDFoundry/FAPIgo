package storage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"reflect"
	"slices"
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
// redemption of authorization codes and refresh tokens, codes and
// refresh tokens kept apart (neither redemption returns the other's
// record under the same digest), faithful
// round-tripping of stored fields, and exactly one winner under
// concurrent redemption of the same code or token. Revoking a refresh
// token succeeds for a hash no token is stored under, or that was
// revoked before, and a token revoked before it's stored, or while it's
// being stored, stays unredeemable. A store that also
// implements IssuedTokensRecorder or GrantRefreshTokenRevoker is checked
// against what those promise too. factory must return a fresh, empty
// GrantStore each call — its subtests share nothing between them.
func TestGrantStoreContract(t *testing.T, factory func() GrantStore) {
	t.Helper()

	t.Run("CreateAndRedeemAuthorizationCode", func(t *testing.T) { testGrantStoreCreateAndRedeemAuthorizationCode(t, factory) })
	t.Run("RedeemAuthorizationCodeIsSingleUse", func(t *testing.T) { testGrantStoreRedeemAuthorizationCodeIsSingleUse(t, factory) })
	t.Run("RedeemAuthorizationCodeByAnotherClientLeavesItUnredeemed", func(t *testing.T) {
		testGrantStoreRedeemAuthorizationCodeByAnotherClientLeavesItUnredeemed(t, factory)
	})
	t.Run("RedeemAuthorizationCodeReuseReportsIssuedTokens", func(t *testing.T) {
		testGrantStoreRedeemAuthorizationCodeReuseReportsIssuedTokens(t, factory)
	})
	t.Run("RedeemAuthorizationCodeReuseWithoutRecordingReportsEmpty", func(t *testing.T) {
		testGrantStoreRedeemAuthorizationCodeReuseWithoutRecordingReportsEmpty(t, factory)
	})
	t.Run("RedeemUnknownAuthorizationCodeFails", func(t *testing.T) { testGrantStoreRedeemUnknownAuthorizationCodeFails(t, factory) })
	t.Run("ConcurrentRedeemAuthorizationCodeHasExactlyOneWinner", func(t *testing.T) {
		testGrantStoreConcurrentRedeemAuthorizationCodeHasExactlyOneWinner(t, factory)
	})
	t.Run("CreateAndRedeemRefreshToken", func(t *testing.T) { testGrantStoreCreateAndRedeemRefreshToken(t, factory) })
	t.Run("RedeemRefreshTokenIsReusable", func(t *testing.T) { testGrantStoreRedeemRefreshTokenIsReusable(t, factory) })
	t.Run("RedeemUnknownRefreshTokenFails", func(t *testing.T) { testGrantStoreRedeemUnknownRefreshTokenFails(t, factory) })
	t.Run("ConcurrentRedeemRefreshTokenAllSucceed", func(t *testing.T) { testGrantStoreConcurrentRedeemRefreshTokenAllSucceed(t, factory) })
	t.Run("RevokeRefreshTokenPreventsRedemption", func(t *testing.T) { testGrantStoreRevokeRefreshTokenPreventsRedemption(t, factory) })
	t.Run("RevokeRefreshTokenIsIdempotent", func(t *testing.T) { testGrantStoreRevokeRefreshTokenIsIdempotent(t, factory) })
	t.Run("RevokeRefreshTokenBeforeCreateKeepsItUnredeemable", func(t *testing.T) {
		testGrantStoreRevokeRefreshTokenBeforeCreateKeepsItUnredeemable(t, factory)
	})
	t.Run("ConcurrentRevokeAndCreateRefreshTokenKeepItUnredeemable", func(t *testing.T) {
		testGrantStoreConcurrentRevokeAndCreateRefreshTokenKeepItUnredeemable(t, factory)
	})
	t.Run("RedeemRefreshTokenDoesNotReturnAuthorizationCode", func(t *testing.T) {
		testGrantStoreRedeemRefreshTokenDoesNotReturnAuthorizationCode(t, factory)
	})
	t.Run("RedeemAuthorizationCodeDoesNotReturnRefreshToken", func(t *testing.T) {
		testGrantStoreRedeemAuthorizationCodeDoesNotReturnRefreshToken(t, factory)
	})
	if _, ok := factory().(IssuedTokensRecorder); ok {
		t.Run("RecordIssuedTokensMatchesTwoCalls", func(t *testing.T) { testGrantStoreRecordIssuedTokensMatchesTwoCalls(t, factory) })
	}
	if _, ok := factory().(GrantRefreshTokenRevoker); ok {
		t.Run("RevokeGrantRefreshTokensRevokesTheGrantsTokens", func(t *testing.T) {
			testGrantStoreRevokeGrantRefreshTokensRevokesTheGrantsTokens(t, factory)
		})
	}
}

// testGrantStoreRevokeGrantRefreshTokensRevokesTheGrantsTokens checks a
// GrantRefreshTokenRevoker: RevokeGrantRefreshTokens revokes, and
// reports, every refresh token created with the grant key, whichever of
// its GrantKeys that is, and no other token; an unknown key revokes
// nothing; and a token created with a grant key after the key's tokens
// were revoked is revoked by the next call.
func testGrantStoreRevokeGrantRefreshTokensRevokesTheGrantsTokens(t *testing.T, factory func() GrantStore) {
	store := factory()
	revoker := store.(GrantRefreshTokenRevoker)
	ctx := context.Background()
	create := func(name string, grantKeys ...string) [32]byte {
		t.Helper()
		hash := sha256.Sum256([]byte(name))
		if err := store.CreateRefreshToken(ctx, NewRefreshToken{
			TokenHash: hash, ClientID: "client-1", Grant: contractPayload,
			ExpiresAt: time.Now().Add(time.Hour), GrantKeys: grantKeys,
		}); err != nil {
			t.Fatalf("CreateRefreshToken(%s): %v", name, err)
		}
		return hash
	}
	revoke := func(grantKey string) [][32]byte {
		t.Helper()
		revoked, err := revoker.RevokeGrantRefreshTokens(ctx, grantKey)
		if err != nil {
			t.Fatalf("RevokeGrantRefreshTokens: %v", err)
		}
		return revoked
	}
	checkRedeemable := func(when string, want bool, tokens map[string][32]byte) {
		t.Helper()
		for name, hash := range tokens {
			_, err := store.RedeemRefreshToken(ctx, RefreshTokenRedemption{TokenHash: hash})
			if got := err == nil; got != want {
				t.Errorf("%s: RedeemRefreshToken(%s) redeemable = %v, want %v (error %v)", when, name, got, want, err)
			}
		}
	}

	grantKey, codeKey := contractGrantKey("grant"), contractGrantKey("code")
	grantOnly := create("grant-key-refresh", grantKey)
	both := create("both-keys-refresh", codeKey, grantKey)
	codeOnly := create("code-key-refresh", codeKey)
	other := create("other-key-refresh", contractGrantKey("other"))
	none := create("no-key-refresh")

	checkRevokedRefreshTokens(t, "revoking the grant key", revoke(grantKey), [][32]byte{grantOnly, both}, nil)
	checkRedeemable("after revoking the grant key", false, map[string][32]byte{"the grant key's token": grantOnly, "the token with both keys": both})
	checkRedeemable("after revoking the grant key", true, map[string][32]byte{"the code key's token": codeOnly, "another key's token": other, "a token without keys": none})

	checkRevokedRefreshTokens(t, "revoking an unknown key", revoke(contractGrantKey("unknown")), nil, nil)

	later := create("later-grant-key-refresh", grantKey)
	checkRevokedRefreshTokens(t, "revoking the grant key again", revoke(grantKey), [][32]byte{later}, [][32]byte{grantOnly, both})
	checkRevokedRefreshTokens(t, "revoking the code key", revoke(codeKey), [][32]byte{codeOnly}, [][32]byte{both})
	checkRedeemable("after revoking both keys again", false, map[string][32]byte{"a token created after the grant key was revoked": later, "the code key's token": codeOnly})
	checkRedeemable("after revoking both keys again", true, map[string][32]byte{"another key's token": other, "a token without keys": none})
}

// contractGrantKey is a NewRefreshToken.GrantKeys value shaped like the
// server's own: a base64url SHA-256 digest.
func contractGrantKey(name string) string {
	sum := sha256.Sum256([]byte("contract grant key\x00" + name))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// checkRevokedRefreshTokens checks what a RevokeGrantRefreshTokens call
// reported: every token in want, and none outside want and mayRepeat,
// the tokens with the key that an earlier call already revoked, which a
// store may report again.
func checkRevokedRefreshTokens(t *testing.T, call string, got, want, mayRepeat [][32]byte) {
	t.Helper()
	for _, hash := range want {
		if !slices.Contains(got, hash) {
			t.Errorf("%s didn't report a token it should have revoked (reported %d)", call, len(got))
		}
	}
	for _, hash := range got {
		if !slices.Contains(want, hash) && !slices.Contains(mayRepeat, hash) {
			t.Errorf("%s reported a token created without the key", call)
		}
	}
}

// testGrantStoreRecordIssuedTokensMatchesTwoCalls checks an
// IssuedTokensRecorder's RecordIssuedTokens against
// RecordIssuedAccessToken plus RecordIssuedRefreshToken: a reuse of a
// code recorded either way reports the same issued tokens, and recording
// one code leaves another's records alone.
func testGrantStoreRecordIssuedTokensMatchesTwoCalls(t *testing.T, factory func() GrantStore) {
	store := factory()
	recorder := store.(IssuedTokensRecorder)
	ctx := context.Background()
	accessExpiry, refreshExpiry := time.Now().Add(time.Minute), time.Now().Add(time.Hour)
	redeemed := func(name string) [32]byte {
		t.Helper()
		hash := sha256.Sum256([]byte(name))
		if err := store.CreateAuthorizationCode(ctx, NewAuthorizationCode{
			CodeHash: hash, ClientID: "client-1", ExpiresAt: time.Now().Add(time.Minute),
		}); err != nil {
			t.Fatalf("CreateAuthorizationCode(%s): %v", name, err)
		}
		if _, err := store.RedeemAuthorizationCode(ctx, AuthorizationCodeRedemption{CodeHash: hash}); err != nil {
			t.Fatalf("first RedeemAuthorizationCode(%s): %v", name, err)
		}
		return hash
	}
	twoCalls, combined, untouched := redeemed("record-two-calls-code"), redeemed("record-combined-code"), redeemed("record-untouched-code")
	refreshHash := sha256.Sum256([]byte("record-refresh"))
	if err := store.RecordIssuedAccessToken(ctx, twoCalls, "jti-1", accessExpiry); err != nil {
		t.Fatalf("RecordIssuedAccessToken: %v", err)
	}
	if err := store.RecordIssuedRefreshToken(ctx, twoCalls, refreshHash, refreshExpiry); err != nil {
		t.Fatalf("RecordIssuedRefreshToken: %v", err)
	}
	if err := recorder.RecordIssuedTokens(ctx, combined, "jti-1", accessExpiry, refreshHash, refreshExpiry); err != nil {
		t.Fatalf("RecordIssuedTokens: %v", err)
	}

	want := reusedCodeReport(t, store, twoCalls)
	if want.IssuedAccessTokenKey != "jti-1" || want.IssuedRefreshTokenHash == nil || *want.IssuedRefreshTokenHash != refreshHash {
		t.Fatalf("reuse after the two calls reported %q, %v, want jti-1 and the refresh token's hash", want.IssuedAccessTokenKey, want.IssuedRefreshTokenHash)
	}
	got := reusedCodeReport(t, store, combined)
	if got.IssuedAccessTokenKey != want.IssuedAccessTokenKey || got.IssuedRefreshTokenHash == nil || *got.IssuedRefreshTokenHash != *want.IssuedRefreshTokenHash {
		t.Fatalf("reuse after RecordIssuedTokens reported %q, %v, want %q, %v as after the two calls", got.IssuedAccessTokenKey, got.IssuedRefreshTokenHash, want.IssuedAccessTokenKey, *want.IssuedRefreshTokenHash)
	}
	if other := reusedCodeReport(t, store, untouched); other.IssuedAccessTokenKey != "" || other.IssuedRefreshTokenHash != nil {
		t.Fatalf("reuse of an unrecorded code reported %q, %v, want nothing: RecordIssuedTokens recorded another code", other.IssuedAccessTokenKey, other.IssuedRefreshTokenHash)
	}
}

// reusedCodeReport redeems hash again, as a reuse, and returns what the
// store reports the first redemption issued.
func reusedCodeReport(t *testing.T, store GrantStore, hash [32]byte) *AuthorizationCodeAlreadyRedeemedError {
	t.Helper()
	_, err := store.RedeemAuthorizationCode(context.Background(), AuthorizationCodeRedemption{CodeHash: hash})
	var alreadyRedeemed *AuthorizationCodeAlreadyRedeemedError
	if !errors.As(err, &alreadyRedeemed) {
		t.Fatalf("RedeemAuthorizationCode (reuse) error = %v, want errors.As into *AuthorizationCodeAlreadyRedeemedError", err)
	}
	return alreadyRedeemed
}

func testGrantStoreCreateAndRedeemAuthorizationCode(t *testing.T, factory func() GrantStore) {
	store := factory()
	ctx := context.Background()
	hash := sha256.Sum256([]byte("test-code"))
	want := NewAuthorizationCode{
		CodeHash: hash, ClientID: "client-1",
		Grant:     contractPayload,
		ExpiresAt: time.Now().Add(time.Minute),
	}
	if err := store.CreateAuthorizationCode(ctx, want); err != nil {
		t.Fatalf("CreateAuthorizationCode: %v", err)
	}
	got, err := store.RedeemAuthorizationCode(ctx, AuthorizationCodeRedemption{CodeHash: hash})
	if err != nil {
		t.Fatalf("RedeemAuthorizationCode: %v", err)
	}
	if got.ClientID != want.ClientID || !got.ExpiresAt.Equal(want.ExpiresAt) ||
		!jsonEquivalent(got.Grant, want.Grant) {
		t.Fatalf("RedeemAuthorizationCode returned %+v, want fields matching %+v", got, want)
	}
}

func testGrantStoreRedeemAuthorizationCodeIsSingleUse(t *testing.T, factory func() GrantStore) {
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
}

// testGrantStoreRedeemAuthorizationCodeByAnotherClientLeavesItUnredeemed
// covers AuthorizationCodeRedemption.ClientID: a store that checks it
// refuses another client's redemption of a fresh code without consuming
// it, so the client the code was issued to can still redeem it, and
// still reports a code that was already redeemed as
// *AuthorizationCodeAlreadyRedeemedError when another client presents
// it. A store that ignores the field (an empty ClientID's behavior)
// skips this subtest: the server refuses another client's code after
// redemption anyway, so ignoring it stays safe, if less protective.
func testGrantStoreRedeemAuthorizationCodeByAnotherClientLeavesItUnredeemed(t *testing.T, factory func() GrantStore) {
	store := factory()
	ctx := context.Background()
	hash := sha256.Sum256([]byte("other-client-code"))
	if err := store.CreateAuthorizationCode(ctx, NewAuthorizationCode{
		CodeHash: hash, ClientID: "client-1", Grant: contractPayload, ExpiresAt: time.Now().Add(time.Minute),
	}); err != nil {
		t.Fatalf("CreateAuthorizationCode: %v", err)
	}
	if _, err := store.RedeemAuthorizationCode(ctx, AuthorizationCodeRedemption{CodeHash: hash, ClientID: "client-2"}); err == nil {
		t.Skip("the store ignores AuthorizationCodeRedemption.ClientID")
	}
	got, err := store.RedeemAuthorizationCode(ctx, AuthorizationCodeRedemption{CodeHash: hash, ClientID: "client-1"})
	if err != nil {
		t.Fatalf("owning client's redemption after another client's was refused: %v, want the code unspent", err)
	}
	if got.ClientID != "client-1" {
		t.Fatalf("redeemed ClientID = %q, want client-1", got.ClientID)
	}
	_, err = store.RedeemAuthorizationCode(ctx, AuthorizationCodeRedemption{CodeHash: hash, ClientID: "client-2"})
	var alreadyRedeemed *AuthorizationCodeAlreadyRedeemedError
	if !errors.As(err, &alreadyRedeemed) {
		t.Fatalf("another client presenting a redeemed code: error = %v, want *AuthorizationCodeAlreadyRedeemedError", err)
	}
}

// testGrantStoreRedeemAuthorizationCodeReuseReportsIssuedTokens covers
// RFC 6749 §4.1.2: on a reuse, the store must report what the original
// redemption issued (via errors.As into
// *AuthorizationCodeAlreadyRedeemedError) so the caller can revoke it —
// see RecordIssuedAccessToken/RecordIssuedRefreshToken's own doc
// comments.
func testGrantStoreRedeemAuthorizationCodeReuseReportsIssuedTokens(t *testing.T, factory func() GrantStore) {
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
	// ClientID may be left empty (the server then revokes whoever
	// presents the code), but a store that sets it must name the client
	// the code was issued to.
	if alreadyRedeemed.ClientID != "" && alreadyRedeemed.ClientID != "client-1" {
		t.Fatalf("ClientID = %q, want %q (the code's client) or empty", alreadyRedeemed.ClientID, "client-1")
	}
}

// testGrantStoreRedeemAuthorizationCodeReuseWithoutRecordingReportsEmpty
// covers graceful degradation: a deployment that never calls
// RecordIssuedAccessToken/RecordIssuedRefreshToken (no-op
// implementation, or simply never invoked) still gets a normal reuse
// rejection — the error just carries nothing to revoke.
func testGrantStoreRedeemAuthorizationCodeReuseWithoutRecordingReportsEmpty(t *testing.T, factory func() GrantStore) {
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
	// Not requiring errors.As to succeed here at all: an implementation
	// is free to return a plain error for this case too, as long as
	// *if* it returns the typed error, the payload is empty rather than
	// stale/wrong.
}

func testGrantStoreRedeemUnknownAuthorizationCodeFails(t *testing.T, factory func() GrantStore) {
	store := factory()
	hash := sha256.Sum256([]byte("never-created"))
	if _, err := store.RedeemAuthorizationCode(context.Background(), AuthorizationCodeRedemption{CodeHash: hash}); err == nil {
		t.Fatalf("RedeemAuthorizationCode(unknown) = nil error, want error")
	}
}

func testGrantStoreConcurrentRedeemAuthorizationCodeHasExactlyOneWinner(t *testing.T, factory func() GrantStore) {
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
}

func testGrantStoreCreateAndRedeemRefreshToken(t *testing.T, factory func() GrantStore) {
	store := factory()
	ctx := context.Background()
	hash := sha256.Sum256([]byte("test-refresh"))
	want := NewRefreshToken{
		TokenHash: hash, ClientID: "client-1",
		Grant:     contractPayload,
		ExpiresAt: time.Now().Add(time.Hour),
	}
	if err := store.CreateRefreshToken(ctx, want); err != nil {
		t.Fatalf("CreateRefreshToken: %v", err)
	}
	got, err := store.RedeemRefreshToken(ctx, RefreshTokenRedemption{TokenHash: hash})
	if err != nil {
		t.Fatalf("RedeemRefreshToken: %v", err)
	}
	if got.ClientID != want.ClientID || !got.ExpiresAt.Equal(want.ExpiresAt) ||
		!jsonEquivalent(got.Grant, want.Grant) {
		t.Fatalf("RedeemRefreshToken returned %+v, want fields matching %+v", got, want)
	}
}

// testGrantStoreRedeemRefreshTokenIsReusable covers
// GrantStore.RedeemRefreshToken's own doc comment (FAPI2-SP-FINAL
// 5.3.2.1-9): a refresh token stays valid for repeated use until it
// expires, unlike an authorization code — deliberately not single-use.
// Contrast with testGrantStoreRedeemAuthorizationCodeIsSingleUse above.
func testGrantStoreRedeemRefreshTokenIsReusable(t *testing.T, factory func() GrantStore) {
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
}

func testGrantStoreRedeemUnknownRefreshTokenFails(t *testing.T, factory func() GrantStore) {
	store := factory()
	hash := sha256.Sum256([]byte("never-created-refresh"))
	if _, err := store.RedeemRefreshToken(context.Background(), RefreshTokenRedemption{TokenHash: hash}); err == nil {
		t.Fatalf("RedeemRefreshToken(unknown) = nil error, want error")
	}
}

func testGrantStoreConcurrentRedeemRefreshTokenAllSucceed(t *testing.T, factory func() GrantStore) {
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
}

// testGrantStoreRevokeRefreshTokenPreventsRedemption covers RFC 6749
// §4.1.2: a specific refresh token can be revoked (e.g. because its
// originating authorization code was reused) even though refresh
// tokens aren't single-use in the ordinary case.
func testGrantStoreRevokeRefreshTokenPreventsRedemption(t *testing.T, factory func() GrantStore) {
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
}

// testGrantStoreRevokeRefreshTokenIsIdempotent checks that
// RevokeRefreshToken returns nil for a hash no token is stored under,
// and for one revoked before, and that a stored token revoked twice
// stays unredeemable: the server revokes such hashes in the normal
// course (see GrantStore.RevokeRefreshToken), and takes an error for a
// failure to revoke.
func testGrantStoreRevokeRefreshTokenIsIdempotent(t *testing.T, factory func() GrantStore) {
	store := factory()
	ctx := context.Background()
	unstored := sha256.Sum256([]byte("never-stored-refresh"))
	stored := contractRefreshToken("revoked-twice-refresh")
	if err := store.CreateRefreshToken(ctx, stored); err != nil {
		t.Fatalf("CreateRefreshToken(a token to revoke twice): %v", err)
	}
	for _, attempt := range []string{"first", "second"} {
		if err := store.RevokeRefreshToken(ctx, unstored); err != nil {
			t.Errorf("%s RevokeRefreshToken of a hash no token was stored under: %v, want nil", attempt, err)
		}
		if err := store.RevokeRefreshToken(ctx, stored.TokenHash); err != nil {
			t.Errorf("%s RevokeRefreshToken of a stored token: %v, want nil", attempt, err)
		}
		if refreshTokenRedeems(store, stored.TokenHash) {
			t.Errorf("RedeemRefreshToken after the %s revocation of a stored token = nil error, want error", attempt)
		}
	}
}

// testGrantStoreRevokeRefreshTokenBeforeCreateKeepsItUnredeemable checks
// that a refresh token whose hash is revoked before it's stored is never
// redeemed, as a revocation through the server's grant registry can
// come before the token's issuance stores it: CreateRefreshToken may
// fail, or store the token so that RedeemRefreshToken refuses it. It
// checks a token without grant keys, then one with a grant key: the
// server's tokens carry grant keys when their grant can be revoked, and
// a store may write those another way, in a transaction rather than one
// statement, say. A token with the same keys stored afterwards and
// never revoked must still redeem, so a store that refuses every token,
// or every one stored after a revocation, fails.
func testGrantStoreRevokeRefreshTokenBeforeCreateKeepsItUnredeemable(t *testing.T, factory func() GrantStore) {
	store := factory()
	checkRevokedBeforeCreate(t, store, "without grant keys")
	checkRevokedBeforeCreate(t, store, "with a grant key", contractGrantKey("revoked-before-stored-grant"))
}

// checkRevokedBeforeCreate revokes the hash of a refresh token with
// grantKeys, as shape describes them, then stores the token, and checks
// that the token doesn't redeem, while a control token with the same
// keys, stored afterwards and never revoked, does.
func checkRevokedBeforeCreate(t *testing.T, store GrantStore, shape string, grantKeys ...string) {
	t.Helper()
	ctx := context.Background()
	revoked := contractRefreshToken("revoked-before-stored-refresh "+shape, grantKeys...)
	control := contractRefreshToken("never-revoked-refresh "+shape, grantKeys...)
	if err := store.RevokeRefreshToken(ctx, revoked.TokenHash); err != nil {
		t.Fatalf("RevokeRefreshToken of the hash of a token %s, not stored yet: %v, want nil", shape, err)
	}
	createErr := store.CreateRefreshToken(ctx, revoked)
	if err := store.CreateRefreshToken(ctx, control); err != nil {
		t.Fatalf("CreateRefreshToken(a token %s, never revoked): %v", shape, err)
	}
	if refreshTokenRedeems(store, revoked.TokenHash) {
		t.Errorf("RedeemRefreshToken of a token %s, stored after its hash was revoked = nil error, want error (its CreateRefreshToken returned %v)", shape, createErr)
	}
	checkRefreshTokenRedeems(t, store, fmt.Sprintf("a token %s, stored after another's hash was revoked", shape), control.TokenHash)
}

// contractRevokeCreateRaces is how many refresh tokens
// testGrantStoreConcurrentRevokeAndCreateRefreshTokenKeepItUnredeemable
// revokes while they're being stored, one race after another.
const contractRevokeCreateRaces = 32

// revokeCreateRace is one race of a refresh token's revocation against
// its creation, with a control token created alongside and never
// revoked, and what each of the three calls returned.
type revokeCreateRace struct {
	raced, control                   NewRefreshToken
	revokeErr, createErr, controlErr error
}

// testGrantStoreConcurrentRevokeAndCreateRefreshTokenKeepItUnredeemable
// checks that a refresh token whose hash is revoked while it's being
// stored is never redeemed. For each of contractRevokeCreateRaces
// tokens, it runs RevokeRefreshToken of the token's hash,
// CreateRefreshToken of the token and CreateRefreshToken of a control
// token from a common start. Once all three have returned, the token
// must not redeem if RevokeRefreshToken returned nil, whatever
// CreateRefreshToken returned, and the control, never revoked, must, so
// a store that refuses every token fails. Every other race's tokens
// carry a grant key, as the server's do when their grant can be
// revoked, so a store that writes those another way races both ways. A
// race whose RevokeRefreshToken failed checks nothing (an error only
// says the revocation wasn't recorded), but they mustn't all fail.
func testGrantStoreConcurrentRevokeAndCreateRefreshTokenKeepItUnredeemable(t *testing.T, factory func() GrantStore) {
	store := factory()
	checked := 0
	for i := range contractRevokeCreateRaces {
		if checkRevokeCreateRace(t, store, i, raceRevokeAndCreate(store, i)) {
			checked++
		}
	}
	if checked == 0 {
		t.Errorf("RevokeRefreshToken failed in all %d races with CreateRefreshToken, so none was checked; want nil", contractRevokeCreateRaces)
	}
}

// raceRevokeAndCreate runs race i: RevokeRefreshToken of its token's
// hash, CreateRefreshToken of the token and CreateRefreshToken of its
// control token, from a common start, and returns once all three have,
// with what each returned.
func raceRevokeAndCreate(store GrantStore, i int) revokeCreateRace {
	ctx := context.Background()
	race := revokeCreateRace{
		raced:   contractRefreshToken(fmt.Sprintf("raced-refresh-%d", i), raceGrantKeys(i)...),
		control: contractRefreshToken(fmt.Sprintf("race-control-refresh-%d", i), raceGrantKeys(i)...),
	}
	runFromCommonStart(
		func() { race.revokeErr = store.RevokeRefreshToken(ctx, race.raced.TokenHash) },
		func() { race.createErr = store.CreateRefreshToken(ctx, race.raced) },
		func() { race.controlErr = store.CreateRefreshToken(ctx, race.control) },
	)
	return race
}

// raceGrantKeys is the grant keys of race i's tokens: one for every
// other race, none for the rest.
func raceGrantKeys(i int) []string {
	if i%2 == 0 {
		return []string{contractGrantKey(fmt.Sprintf("raced-grant-%d", i))}
	}
	return nil
}

// checkRevokeCreateRace checks race i once its three calls have
// returned: its control token redeems, and, if its RevokeRefreshToken
// returned nil, its token doesn't. It reports whether
// RevokeRefreshToken returned nil, and so the token was checked.
func checkRevokeCreateRace(t *testing.T, store GrantStore, i int, race revokeCreateRace) bool {
	t.Helper()
	if race.controlErr != nil {
		t.Errorf("race %d: CreateRefreshToken of the control token: %v", i, race.controlErr)
	} else {
		checkRefreshTokenRedeems(t, store, fmt.Sprintf("race %d's control token", i), race.control.TokenHash)
	}
	if race.revokeErr != nil {
		t.Logf("race %d: RevokeRefreshToken: %v, so its token isn't checked", i, race.revokeErr)
		return false
	}
	if refreshTokenRedeems(store, race.raced.TokenHash) {
		t.Errorf("race %d: RedeemRefreshToken of a token whose hash was revoked while it was being stored = nil error, want error (its CreateRefreshToken returned %v)", i, race.createErr)
	}
	return true
}

// runFromCommonStart runs each of calls in a goroutine of its own,
// releasing them together once all are waiting, and returns once all
// have returned.
func runFromCommonStart(calls ...func()) {
	var ready, done sync.WaitGroup
	start := make(chan struct{})
	ready.Add(len(calls))
	done.Add(len(calls))
	for _, call := range calls {
		go func() {
			defer done.Done()
			ready.Done()
			<-start
			call()
		}()
	}
	ready.Wait()
	close(start)
	done.Wait()
}

// contractRefreshToken is the refresh token named name that the
// revocation subtests store: valid for an hour, with grantKeys.
func contractRefreshToken(name string, grantKeys ...string) NewRefreshToken {
	return NewRefreshToken{
		TokenHash: sha256.Sum256([]byte(name)), ClientID: "revocation-client", Grant: contractPayload,
		ExpiresAt: time.Now().Add(time.Hour), GrantKeys: grantKeys,
	}
}

// refreshTokenRedeems reports whether store redeems the refresh token
// stored under hash.
func refreshTokenRedeems(store GrantStore, hash [32]byte) bool {
	_, err := store.RedeemRefreshToken(context.Background(), RefreshTokenRedemption{TokenHash: hash})
	return err == nil
}

// checkRefreshTokenRedeems reports, with t.Errorf, a failure to redeem
// what, the refresh token stored under hash, which was never revoked: a
// store refusing every token would pass each check that a revoked one
// is refused.
func checkRefreshTokenRedeems(t *testing.T, store GrantStore, what string, hash [32]byte) {
	t.Helper()
	if _, err := store.RedeemRefreshToken(context.Background(), RefreshTokenRedemption{TokenHash: hash}); err != nil {
		t.Errorf("RedeemRefreshToken(%s, never revoked): %v, want it redeemed", what, err)
	}
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
	t.Run("BeginAuthorizationExpiredReferenceMintsNoHandle", func(t *testing.T) {
		testTransactionStoreBeginAuthorizationExpiredReferenceMintsNoHandle(t, factory)
	})
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
	if err := store.CreatePAR(ctx, NewPARRecord{
		Reference: "ref-1", ClientID: "client-1", Request: contractPayload,
		ExpiresAt: time.Now().Add(time.Minute),
	}); err != nil {
		t.Fatalf("CreatePAR: %v", err)
	}
	got, err := store.BeginAuthorization(ctx, BeginAuthorizationTransaction{
		Reference: "ref-1", Handle: "handle-1", HandleExpiresAt: time.Now().Add(time.Minute), Now: time.Now(),
	})
	if err != nil {
		t.Fatalf("BeginAuthorization: %v", err)
	}
	if got.ClientID != "client-1" {
		t.Fatalf("ClientID = %q, want client-1", got.ClientID)
	}
	if !jsonEquivalent(got.Request, contractPayload) {
		t.Fatalf("Request = %s, want %s", got.Request, contractPayload)
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
		Reference: "ref-2", Handle: "handle-2a", HandleExpiresAt: time.Now().Add(time.Minute), Now: time.Now(),
	}); err != nil {
		t.Fatalf("first BeginAuthorization: %v", err)
	}
	if _, err := store.BeginAuthorization(ctx, BeginAuthorizationTransaction{
		Reference: "ref-2", Handle: "handle-2b", HandleExpiresAt: time.Now().Add(time.Minute), Now: time.Now(),
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
		Reference: "ref-2c", Handle: "handle-2c", HandleExpiresAt: time.Now().Add(time.Minute), Now: time.Now(),
	}); err != nil {
		t.Fatalf("BeginAuthorization: %v", err)
	}
	if _, err := store.CompleteAuthorization(ctx, CompleteAuthorizationTransaction{Handle: "handle-2c"}); err != nil {
		t.Fatalf("CompleteAuthorization: %v", err)
	}
	if _, err := store.BeginAuthorization(ctx, BeginAuthorizationTransaction{
		Reference: "ref-2c", Handle: "handle-2d", HandleExpiresAt: time.Now().Add(time.Minute), Now: time.Now(),
	}); err == nil {
		t.Fatalf("BeginAuthorization after completion = nil error, want error")
	}
}

func testTransactionStoreBeginAuthorizationUnknownReferenceFails(t *testing.T, factory func() TransactionStore) {
	store := factory()
	if _, err := store.BeginAuthorization(context.Background(), BeginAuthorizationTransaction{
		Reference: "never-created", Handle: "handle-x", HandleExpiresAt: time.Now().Add(time.Minute), Now: time.Now(),
	}); err == nil {
		t.Fatalf("BeginAuthorization(unknown reference) = nil error, want error")
	}
}

// testTransactionStoreBeginAuthorizationExpiredReferenceMintsNoHandle:
// a Reference whose ExpiresAt isn't after txn.Now fails, and the Handle
// it named isn't minted, so CompleteAuthorization doesn't know it.
func testTransactionStoreBeginAuthorizationExpiredReferenceMintsNoHandle(t *testing.T, factory func() TransactionStore) {
	store := factory()
	ctx := context.Background()
	expiresAt := time.Now().Add(time.Minute)
	if err := store.CreatePAR(ctx, NewPARRecord{
		Reference: "ref-expired", ClientID: "client-1", ExpiresAt: expiresAt,
	}); err != nil {
		t.Fatalf("CreatePAR: %v", err)
	}
	for _, now := range []time.Time{expiresAt, expiresAt.Add(time.Second)} {
		if _, err := store.BeginAuthorization(ctx, BeginAuthorizationTransaction{
			Reference: "ref-expired", Handle: "handle-expired", HandleExpiresAt: now.Add(time.Minute), Now: now,
		}); err == nil {
			t.Fatalf("BeginAuthorization at %v, the reference expiring at %v = nil error, want error", now, expiresAt)
		}
	}
	if _, err := store.CompleteAuthorization(ctx, CompleteAuthorizationTransaction{Handle: "handle-expired"}); err == nil {
		t.Fatalf("CompleteAuthorization of a handle an expired reference's BeginAuthorization named = nil error, want error")
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
			Reference: "ref-3", Handle: handle, HandleExpiresAt: time.Now().Add(time.Minute), Now: time.Now(),
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
		Reference: "ref-4", Handle: "handle-4", HandleExpiresAt: time.Now().Add(time.Minute), Now: time.Now(),
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
		Reference: "ref-5", Handle: "handle-5", HandleExpiresAt: time.Now().Add(time.Minute), Now: time.Now(),
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
			Reference: "ref-6", Handle: handles[i], HandleExpiresAt: time.Now().Add(time.Minute), Now: time.Now(),
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
// Record must come back as equivalent JSON: the client refuses a session
// without it. factory must return a fresh, empty SessionStore each call.
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
		State:     "state-1",
		Record:    json.RawMessage(`{"v":1,"nonce":"nonce-1","pkce_verifier":"verifier-1","issuer":"https://as.example","max_age":300}`),
		ExpiresAt: time.Now().Add(time.Minute),
	}
	if err := store.Create(ctx, want); err != nil {
		t.Fatalf("Create: %v", err)
	}
	got, err := store.Consume(ctx, SessionConsumption{State: "state-1"})
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if !jsonEquivalent(got.Record, want.Record) || !got.ExpiresAt.Equal(want.ExpiresAt) {
		t.Fatalf("Consume returned Record %s, ExpiresAt %v; want the Record and ExpiresAt Create persisted (%s, %v)", got.Record, got.ExpiresAt, want.Record, want.ExpiresAt)
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
// guarantees NonceStore's documentation promises: an issued nonce's
// expiry round-trips, it can be looked up any number of times, including
// concurrently, and an unknown nonce is rejected. factory must return a
// fresh, empty NonceStore each call.
func TestNonceStoreContract(t *testing.T, factory func() NonceStore) {
	t.Helper()

	t.Run("IssueThenLookupRoundTripsExpiry", func(t *testing.T) { testNonceStoreIssueThenLookupRoundTripsExpiry(t, factory) })
	t.Run("LookupIsRepeatable", func(t *testing.T) { testNonceStoreLookupIsRepeatable(t, factory) })
	t.Run("LookupUnknownNonceFails", func(t *testing.T) { testNonceStoreLookupUnknownNonceFails(t, factory) })
	t.Run("ConcurrentLookupsAllSucceed", func(t *testing.T) { testNonceStoreConcurrentLookupsAllSucceed(t, factory) })
}

func testNonceStoreIssueThenLookupRoundTripsExpiry(t *testing.T, factory func() NonceStore) {
	store := factory()
	ctx := context.Background()
	expiresAt := time.Now().Add(time.Minute).Truncate(time.Second)
	if err := store.Issue(ctx, NonceIssuance{Nonce: "nonce-1", ExpiresAt: expiresAt}); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	got, err := store.Lookup(ctx, NonceLookup{Nonce: "nonce-1"})
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if !got.ExpiresAt.Equal(expiresAt) {
		t.Fatalf("Lookup returned ExpiresAt %v, want %v", got.ExpiresAt, expiresAt)
	}
}

func testNonceStoreLookupIsRepeatable(t *testing.T, factory func() NonceStore) {
	store := factory()
	ctx := context.Background()
	if err := store.Issue(ctx, NonceIssuance{Nonce: "nonce-2", ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	for i := range 3 {
		if _, err := store.Lookup(ctx, NonceLookup{Nonce: "nonce-2"}); err != nil {
			t.Fatalf("Lookup #%d: %v", i+1, err)
		}
	}
}

func testNonceStoreLookupUnknownNonceFails(t *testing.T, factory func() NonceStore) {
	store := factory()
	if _, err := store.Lookup(context.Background(), NonceLookup{Nonce: "never-issued"}); err == nil {
		t.Fatalf("Lookup(unknown nonce) = nil error, want error")
	}
}

func testNonceStoreConcurrentLookupsAllSucceed(t *testing.T, factory func() NonceStore) {
	store := factory()
	ctx := context.Background()
	if err := store.Issue(ctx, NonceIssuance{Nonce: "nonce-3", ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	successes := runConcurrently(contractConcurrentAttempts, func() bool {
		_, err := store.Lookup(ctx, NonceLookup{Nonce: "nonce-3"})
		return err == nil
	})
	if successes != contractConcurrentAttempts {
		t.Fatalf("concurrent Lookup succeeded %d times, want all %d", successes, contractConcurrentAttempts)
	}
}

// TestAccessTokenStoreContract exercises factory()'s behavior against
// the guarantees AccessTokenStore's documentation promises: a created
// token's fields round-trip faithfully through LookupAccessToken, and
// an unknown hash is rejected. factory must return a fresh, empty
// AccessTokenStore each call.
func TestAccessTokenStoreContract(t *testing.T, factory func() AccessTokenStore) {
	t.Helper()

	t.Run("CreateThenLookupRoundTripsFields", func(t *testing.T) { testAccessTokenStoreCreateThenLookupRoundTripsFields(t, factory) })
	t.Run("SenderConstrainDPoPZeroValueRoundTrips", func(t *testing.T) { testAccessTokenStoreSenderConstrainDPoPZeroValueRoundTrips(t, factory) })
	t.Run("LookupUnknownTokenFails", func(t *testing.T) { testAccessTokenStoreLookupUnknownTokenFails(t, factory) })
	t.Run("LookupExpiredTokenStillReturnsIt", func(t *testing.T) { testAccessTokenStoreLookupExpiredTokenStillReturnsIt(t, factory) })
}

func testAccessTokenStoreCreateThenLookupRoundTripsFields(t *testing.T, factory func() AccessTokenStore) {
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
	// SenderConstrain round-trips as a real, independent value — not
	// just whatever the zero value happens to be — proving a store that
	// special-cased or ignored it (e.g. only persisting
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
}

// testAccessTokenStoreSenderConstrainDPoPZeroValueRoundTrips: the
// round-trip case above sets SenderConstrainMTLS explicitly (a non-zero
// value) so a store that silently ignored the field would still be
// caught; this case separately confirms the zero value
// (SenderConstrainDPoP) itself round-trips too, rather than being
// conflated with "field absent".
func testAccessTokenStoreSenderConstrainDPoPZeroValueRoundTrips(t *testing.T, factory func() AccessTokenStore) {
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
}

func testAccessTokenStoreLookupUnknownTokenFails(t *testing.T, factory func() AccessTokenStore) {
	store := factory()
	hash := sha256.Sum256([]byte("never-created"))
	if _, err := store.LookupAccessToken(context.Background(), AccessTokenLookup{TokenHash: hash}); err == nil {
		t.Fatalf("LookupAccessToken(unknown) = nil error, want error")
	}
}

// testAccessTokenStoreLookupExpiredTokenStillReturnsIt: AccessTokenStore
// doesn't self-expire (see its own doc comment) — the caller checks
// ExpiresAt itself, the same way every other *Redeemed/LookedUp* type
// in this package is checked by its caller.
func testAccessTokenStoreLookupExpiredTokenStillReturnsIt(t *testing.T, factory func() AccessTokenStore) {
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
}

// TestBackchannelAuthenticationStoreContract exercises factory()'s
// behavior against the guarantees BackchannelAuthenticationStore's
// documentation promises: DecideBackchannelAuthentication is single-use,
// and wraps ErrBackchannelAuthenticationAlreadyDecided for a second
// decision only, if it wraps it at all;
// PollBackchannelAuthentication is reusable for Pending/Denied/AuthenticationFailed
// but single-use for the first Approved observation (mirroring
// RedeemRefreshToken's and RedeemAuthorizationCode's contracts
// respectively, layered on one interface); expiry and slow-down are
// enforced. factory must return a fresh, empty
// BackchannelAuthenticationStore each call.
func TestBackchannelAuthenticationStoreContract(t *testing.T, factory func() BackchannelAuthenticationStore) {
	t.Helper()

	t.Run("CreateThenPollReturnsPending", func(t *testing.T) { testBackchannelAuthenticationStoreCreateThenPollReturnsPending(t, factory) })
	t.Run("LookupReturnsClientIDAndRequestWithoutConsuming", func(t *testing.T) {
		testBackchannelAuthenticationStoreLookupReturnsClientIDAndRequestWithoutConsuming(t, factory)
	})
	t.Run("LookupUnknownHandleFails", func(t *testing.T) { testBackchannelAuthenticationStoreLookupUnknownHandleFails(t, factory) })
	t.Run("DecideThenPollReturnsApprovedFieldsRoundTripped", func(t *testing.T) {
		testBackchannelAuthenticationStoreDecideThenPollReturnsApprovedFieldsRoundTripped(t, factory)
	})
	t.Run("DecideReturnsPingDeliveryModeAndNotificationTokenFromRecord", func(t *testing.T) {
		testBackchannelAuthenticationStoreDecideReturnsPingDeliveryModeAndNotificationTokenFromRecord(t, factory)
	})
	t.Run("DecideReturnsPollDeliveryModeAndEmptyNotificationTokenFromRecord", func(t *testing.T) {
		testBackchannelAuthenticationStoreDecideReturnsPollDeliveryModeAndEmptyNotificationTokenFromRecord(t, factory)
	})
	t.Run("DecideBackchannelAuthenticationIsSingleUse", func(t *testing.T) {
		testBackchannelAuthenticationStoreDecideBackchannelAuthenticationIsSingleUse(t, factory)
	})
	t.Run("DecideAgainWrapsErrBackchannelAuthenticationAlreadyDecided", func(t *testing.T) {
		testBackchannelAuthenticationStoreDecideAgainWrapsAlreadyDecided(t, factory)
	})
	t.Run("DecideUnknownHandleIsNotAlreadyDecided", func(t *testing.T) {
		testBackchannelAuthenticationStoreDecideUnknownHandleIsNotAlreadyDecided(t, factory)
	})
	t.Run("ConcurrentDecideBackchannelAuthenticationHasExactlyOneWinner", func(t *testing.T) {
		testBackchannelAuthenticationStoreConcurrentDecideBackchannelAuthenticationHasExactlyOneWinner(t, factory)
	})
	t.Run("PollAfterDeniedIsRepeatable", func(t *testing.T) { testBackchannelAuthenticationStorePollAfterDeniedIsRepeatable(t, factory) })
	t.Run("PollAfterApprovedIsSingleUse", func(t *testing.T) { testBackchannelAuthenticationStorePollAfterApprovedIsSingleUse(t, factory) })
	t.Run("PollByAnotherClientLeavesTheRecordUnchanged", func(t *testing.T) {
		testBackchannelAuthenticationStorePollByAnotherClientLeavesTheRecordUnchanged(t, factory)
	})
	t.Run("ConcurrentPollAfterApprovedHasExactlyOneWinner", func(t *testing.T) {
		testBackchannelAuthenticationStoreConcurrentPollAfterApprovedHasExactlyOneWinner(t, factory)
	})
	t.Run("PollUnknownAuthReqIDFails", func(t *testing.T) { testBackchannelAuthenticationStorePollUnknownAuthReqIDFails(t, factory) })
	t.Run("PollAfterExpiryFailsEvenWhenApproved", func(t *testing.T) {
		testBackchannelAuthenticationStorePollAfterExpiryFailsEvenWhenApproved(t, factory)
	})
	t.Run("PollFasterThanIntervalFails", func(t *testing.T) { testBackchannelAuthenticationStorePollFasterThanIntervalFails(t, factory) })
	t.Run("PollSpacedByAtLeastIntervalSucceeds", func(t *testing.T) {
		testBackchannelAuthenticationStorePollSpacedByAtLeastIntervalSucceeds(t, factory)
	})
	t.Run("PollImmediatelyAfterPingDecisionSkipsIntervalCheck", func(t *testing.T) {
		testBackchannelAuthenticationStorePollImmediatelyAfterPingDecisionSkipsIntervalCheck(t, factory)
	})
}

// newBackchannelAuthenticationRecord is TestBackchannelAuthenticationStoreContract's
// shared subtest fixture: a fresh, minimal poll-mode record keyed by
// authReqID/handle so each subtest can use its own without colliding.
func newBackchannelAuthenticationRecord(authReqID, handle string) NewBackchannelAuthentication {
	return NewBackchannelAuthentication{
		AuthReqIDHash: sha256.Sum256([]byte(authReqID)),
		HandleHash:    sha256.Sum256([]byte(handle)),
		ClientID:      "client-1",
		Request:       contractPayload,
		DeliveryMode:  "poll",
		PollInterval:  time.Millisecond,
		ExpiresAt:     time.Now().Add(time.Minute),
	}
}

// testBackchannelAuthenticationStoreLookupReturnsClientIDAndRequestWithoutConsuming
// covers LookupBackchannelAuthentication's own doc comment: it must
// return the pending request's ClientID/Request without deciding or
// otherwise consuming it — confirmed here by polling afterward and still
// observing Status Pending, and by calling Lookup itself a second time.
func testBackchannelAuthenticationStoreLookupReturnsClientIDAndRequestWithoutConsuming(t *testing.T, factory func() BackchannelAuthenticationStore) {
	store := factory()
	ctx := context.Background()
	want := newBackchannelAuthenticationRecord("auth-req-lookup", "handle-lookup")
	if err := store.CreateBackchannelAuthentication(ctx, want); err != nil {
		t.Fatalf("CreateBackchannelAuthentication: %v", err)
	}
	for i := 0; i < 2; i++ {
		got, err := store.LookupBackchannelAuthentication(ctx, want.HandleHash)
		if err != nil {
			t.Fatalf("LookupBackchannelAuthentication (call %d): %v", i, err)
		}
		if got.ClientID != want.ClientID || !jsonEquivalent(got.Request, want.Request) {
			t.Fatalf("LookupBackchannelAuthentication (call %d) returned %+v, want fields matching %+v", i, got, want)
		}
	}
	polled, err := store.PollBackchannelAuthentication(ctx, PollBackchannelAuthentication{
		AuthReqIDHash: want.AuthReqIDHash, Now: time.Now(),
	})
	if err != nil {
		t.Fatalf("PollBackchannelAuthentication: %v", err)
	}
	if polled.Status != BackchannelAuthenticationPending {
		t.Fatalf("Status after Lookup = %v, want Pending — Lookup must not consume or decide the request", polled.Status)
	}
}

func testBackchannelAuthenticationStoreLookupUnknownHandleFails(t *testing.T, factory func() BackchannelAuthenticationStore) {
	store := factory()
	ctx := context.Background()
	if _, err := store.LookupBackchannelAuthentication(ctx, sha256.Sum256([]byte("no-such-handle"))); err == nil {
		t.Fatal("LookupBackchannelAuthentication for unknown handle = nil error, want error")
	}
}

func testBackchannelAuthenticationStoreCreateThenPollReturnsPending(t *testing.T, factory func() BackchannelAuthenticationStore) {
	store := factory()
	ctx := context.Background()
	want := newBackchannelAuthenticationRecord("auth-req-1", "handle-1")
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
}

func testBackchannelAuthenticationStoreDecideThenPollReturnsApprovedFieldsRoundTripped(t *testing.T, factory func() BackchannelAuthenticationStore) {
	store := factory()
	ctx := context.Background()
	record := newBackchannelAuthenticationRecord("auth-req-2", "handle-2")
	if err := store.CreateBackchannelAuthentication(ctx, record); err != nil {
		t.Fatalf("CreateBackchannelAuthentication: %v", err)
	}
	wantGrant := json.RawMessage(`{"v":1,"sub":"user-1","scope":["openid","accounts"]}`)
	if _, err := store.DecideBackchannelAuthentication(ctx, DecideBackchannelAuthentication{
		HandleHash: record.HandleHash, Status: BackchannelAuthenticationApproved,
		Grant: wantGrant,
	}); err != nil {
		t.Fatalf("DecideBackchannelAuthentication: %v", err)
	}
	got, err := store.PollBackchannelAuthentication(ctx, PollBackchannelAuthentication{
		AuthReqIDHash: record.AuthReqIDHash, Now: time.Now(),
	})
	if err != nil {
		t.Fatalf("PollBackchannelAuthentication: %v", err)
	}
	if got.Status != BackchannelAuthenticationApproved || got.ClientID != record.ClientID ||
		!jsonEquivalent(got.Grant, wantGrant) || !jsonEquivalent(got.Request, record.Request) {
		t.Fatalf("PollBackchannelAuthentication returned %+v, want fields matching decision+record", got)
	}
}

// testBackchannelAuthenticationStoreDecideReturnsPingDeliveryModeAndNotificationTokenFromRecord
// covers DecideBackchannelAuthentication's own return value round
// -tripping DeliveryMode/ClientNotificationToken straight from the
// record CreateBackchannelAuthentication persisted — the caller needs
// both to dispatch a CIBA §10.2 ping notification without a second
// round trip to this store.
func testBackchannelAuthenticationStoreDecideReturnsPingDeliveryModeAndNotificationTokenFromRecord(t *testing.T, factory func() BackchannelAuthenticationStore) {
	const wantAuthReqID = "auth-req-ping-1"
	store := factory()
	ctx := context.Background()
	record := newBackchannelAuthenticationRecord(wantAuthReqID, "handle-ping-1")
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
}

// testBackchannelAuthenticationStoreDecideReturnsPollDeliveryModeAndEmptyNotificationTokenFromRecord
// covers the poll-mode default (newBackchannelAuthenticationRecord's
// own shape) round-tripping too — an empty ClientNotificationToken, not
// just a non-empty one.
func testBackchannelAuthenticationStoreDecideReturnsPollDeliveryModeAndEmptyNotificationTokenFromRecord(t *testing.T, factory func() BackchannelAuthenticationStore) {
	store := factory()
	ctx := context.Background()
	record := newBackchannelAuthenticationRecord("auth-req-poll-1", "handle-poll-1")
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
}

func testBackchannelAuthenticationStoreDecideBackchannelAuthenticationIsSingleUse(t *testing.T, factory func() BackchannelAuthenticationStore) {
	store := factory()
	ctx := context.Background()
	record := newBackchannelAuthenticationRecord("auth-req-3", "handle-3")
	if err := store.CreateBackchannelAuthentication(ctx, record); err != nil {
		t.Fatalf("CreateBackchannelAuthentication: %v", err)
	}
	if _, err := store.DecideBackchannelAuthentication(ctx, DecideBackchannelAuthentication{
		HandleHash: record.HandleHash, Status: BackchannelAuthenticationDenied,
	}); err != nil {
		t.Fatalf("first DecideBackchannelAuthentication: %v", err)
	}
	if _, err := store.DecideBackchannelAuthentication(ctx, DecideBackchannelAuthentication{
		HandleHash: record.HandleHash, Status: BackchannelAuthenticationApproved, Grant: contractPayload,
	}); err == nil {
		t.Fatalf("second DecideBackchannelAuthentication = nil error, want error")
	}
}

// testBackchannelAuthenticationStoreDecideAgainWrapsAlreadyDecided: a
// store that reports a second decision with
// ErrBackchannelAuthenticationAlreadyDecided (optional) reports it that
// way, not as an outage. A store that doesn't wrap it skips this
// subtest: the second decision is still refused
// (DecideBackchannelAuthenticationIsSingleUse), and the server then
// reports a stale inbox entry rather than clearing it.
func testBackchannelAuthenticationStoreDecideAgainWrapsAlreadyDecided(t *testing.T, factory func() BackchannelAuthenticationStore) {
	store := factory()
	ctx := context.Background()
	record := newBackchannelAuthenticationRecord("auth-req-decided", "handle-decided")
	if err := store.CreateBackchannelAuthentication(ctx, record); err != nil {
		t.Fatalf("CreateBackchannelAuthentication: %v", err)
	}
	if _, err := store.DecideBackchannelAuthentication(ctx, DecideBackchannelAuthentication{
		HandleHash: record.HandleHash, Status: BackchannelAuthenticationApproved, Grant: contractPayload,
	}); err != nil {
		t.Fatalf("first DecideBackchannelAuthentication: %v", err)
	}
	_, err := store.DecideBackchannelAuthentication(ctx, DecideBackchannelAuthentication{
		HandleHash: record.HandleHash, Status: BackchannelAuthenticationDenied,
	})
	if !errors.Is(err, ErrBackchannelAuthenticationAlreadyDecided) {
		t.Skip("the store doesn't wrap ErrBackchannelAuthenticationAlreadyDecided")
	}
	if errors.Is(err, ErrStoreUnavailable) {
		t.Fatalf("second DecideBackchannelAuthentication = %v, which also wraps ErrStoreUnavailable; an already-decided request isn't an outage", err)
	}
}

// testBackchannelAuthenticationStoreDecideUnknownHandleIsNotAlreadyDecided:
// deciding a handle the store never stored fails without wrapping
// ErrBackchannelAuthenticationAlreadyDecided, which would have the
// server take the request for a stale inbox entry and remove it.
func testBackchannelAuthenticationStoreDecideUnknownHandleIsNotAlreadyDecided(t *testing.T, factory func() BackchannelAuthenticationStore) {
	store := factory()
	_, err := store.DecideBackchannelAuthentication(context.Background(), DecideBackchannelAuthentication{
		HandleHash: sha256.Sum256([]byte("handle-never-stored")), Status: BackchannelAuthenticationDenied,
	})
	switch {
	case err == nil:
		t.Fatal("DecideBackchannelAuthentication(unknown handle) = nil error, want error")
	case errors.Is(err, ErrBackchannelAuthenticationAlreadyDecided):
		t.Fatalf("DecideBackchannelAuthentication(unknown handle) = %v, which wraps ErrBackchannelAuthenticationAlreadyDecided; an unknown request isn't a decided one", err)
	}
}

func testBackchannelAuthenticationStoreConcurrentDecideBackchannelAuthenticationHasExactlyOneWinner(t *testing.T, factory func() BackchannelAuthenticationStore) {
	store := factory()
	ctx := context.Background()
	record := newBackchannelAuthenticationRecord("auth-req-4", "handle-4")
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
}

// testBackchannelAuthenticationStorePollAfterDeniedIsRepeatable:
// Denied/AuthenticationFailed polls are freely repeatable — the client
// keeps polling and must keep observing the same terminal outcome,
// mirroring RedeemRefreshToken's reusable contract rather than
// RedeemAuthorizationCode's single-use one.
func testBackchannelAuthenticationStorePollAfterDeniedIsRepeatable(t *testing.T, factory func() BackchannelAuthenticationStore) {
	store := factory()
	ctx := context.Background()
	record := newBackchannelAuthenticationRecord("auth-req-5", "handle-5")
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
}

// testBackchannelAuthenticationStorePollByAnotherClientLeavesTheRecordUnchanged
// covers PollBackchannelAuthentication.ClientID: a store that checks it
// refuses another client's poll of an approved record without spending
// the approval or recording the poll, so the owning client's poll at the
// same instant still succeeds (no slow_down) and observes Approved. A
// store that ignores the field (an empty ClientID's behavior) skips this
// subtest: the server refuses another client's record after the poll
// anyway, so ignoring it stays safe, if less protective.
func testBackchannelAuthenticationStorePollByAnotherClientLeavesTheRecordUnchanged(t *testing.T, factory func() BackchannelAuthenticationStore) {
	store := factory()
	ctx := context.Background()
	record := newBackchannelAuthenticationRecord("auth-req-other", "handle-other")
	if err := store.CreateBackchannelAuthentication(ctx, record); err != nil {
		t.Fatalf("CreateBackchannelAuthentication: %v", err)
	}
	if _, err := store.DecideBackchannelAuthentication(ctx, DecideBackchannelAuthentication{
		HandleHash: record.HandleHash, Status: BackchannelAuthenticationApproved, Grant: contractPayload,
	}); err != nil {
		t.Fatalf("DecideBackchannelAuthentication: %v", err)
	}
	now := time.Now()
	if _, err := store.PollBackchannelAuthentication(ctx, PollBackchannelAuthentication{
		AuthReqIDHash: record.AuthReqIDHash, Now: now, ClientID: "client-2",
	}); err == nil {
		t.Skip("the store ignores PollBackchannelAuthentication.ClientID")
	}
	got, err := store.PollBackchannelAuthentication(ctx, PollBackchannelAuthentication{
		AuthReqIDHash: record.AuthReqIDHash, Now: now, ClientID: record.ClientID,
	})
	if err != nil {
		t.Fatalf("owning client's poll after another client's was refused: %v, want the approval unspent and the refused poll unrecorded", err)
	}
	if got.Status != BackchannelAuthenticationApproved {
		t.Fatalf("owning client's poll status = %v, want Approved", got.Status)
	}
}

// testBackchannelAuthenticationStorePollAfterApprovedIsSingleUse: the
// first poll to observe Approved consumes it — a second poll for the
// same auth_req_id must report
// *BackchannelAuthenticationAlreadyRedeemedError, the
// RedeemAuthorizationCode-style single-use guarantee.
func testBackchannelAuthenticationStorePollAfterApprovedIsSingleUse(t *testing.T, factory func() BackchannelAuthenticationStore) {
	store := factory()
	ctx := context.Background()
	record := newBackchannelAuthenticationRecord("auth-req-6", "handle-6")
	if err := store.CreateBackchannelAuthentication(ctx, record); err != nil {
		t.Fatalf("CreateBackchannelAuthentication: %v", err)
	}
	if _, err := store.DecideBackchannelAuthentication(ctx, DecideBackchannelAuthentication{
		HandleHash: record.HandleHash, Status: BackchannelAuthenticationApproved, Grant: contractPayload,
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
}

func testBackchannelAuthenticationStoreConcurrentPollAfterApprovedHasExactlyOneWinner(t *testing.T, factory func() BackchannelAuthenticationStore) {
	store := factory()
	ctx := context.Background()
	record := newBackchannelAuthenticationRecord("auth-req-7", "handle-7")
	if err := store.CreateBackchannelAuthentication(ctx, record); err != nil {
		t.Fatalf("CreateBackchannelAuthentication: %v", err)
	}
	if _, err := store.DecideBackchannelAuthentication(ctx, DecideBackchannelAuthentication{
		HandleHash: record.HandleHash, Status: BackchannelAuthenticationApproved, Grant: contractPayload,
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
}

func testBackchannelAuthenticationStorePollUnknownAuthReqIDFails(t *testing.T, factory func() BackchannelAuthenticationStore) {
	store := factory()
	hash := sha256.Sum256([]byte("never-created"))
	if _, err := store.PollBackchannelAuthentication(context.Background(), PollBackchannelAuthentication{
		AuthReqIDHash: hash, Now: time.Now(),
	}); err == nil {
		t.Fatalf("PollBackchannelAuthentication(unknown) = nil error, want error")
	}
}

// testBackchannelAuthenticationStorePollAfterExpiryFailsEvenWhenApproved:
// a poll after ExpiresAt must report expiry regardless of decision
// status — even one that would otherwise report Approved.
func testBackchannelAuthenticationStorePollAfterExpiryFailsEvenWhenApproved(t *testing.T, factory func() BackchannelAuthenticationStore) {
	store := factory()
	ctx := context.Background()
	record := newBackchannelAuthenticationRecord("auth-req-8", "handle-8")
	record.ExpiresAt = time.Now().Add(time.Millisecond)
	if err := store.CreateBackchannelAuthentication(ctx, record); err != nil {
		t.Fatalf("CreateBackchannelAuthentication: %v", err)
	}
	if _, err := store.DecideBackchannelAuthentication(ctx, DecideBackchannelAuthentication{
		HandleHash: record.HandleHash, Status: BackchannelAuthenticationApproved, Grant: contractPayload,
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
}

// testBackchannelAuthenticationStorePollFasterThanIntervalFails: two
// polls closer together than PollInterval — the second must be
// rejected with *BackchannelAuthenticationSlowDownError, driven by
// injected Now rather than a real sleep.
func testBackchannelAuthenticationStorePollFasterThanIntervalFails(t *testing.T, factory func() BackchannelAuthenticationStore) {
	store := factory()
	ctx := context.Background()
	record := newBackchannelAuthenticationRecord("auth-req-9", "handle-9")
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
}

// testBackchannelAuthenticationStorePollSpacedByAtLeastIntervalSucceeds:
// a poll spaced at least PollInterval apart from the previous one
// succeeds, unlike testBackchannelAuthenticationStorePollFasterThanIntervalFails.
func testBackchannelAuthenticationStorePollSpacedByAtLeastIntervalSucceeds(t *testing.T, factory func() BackchannelAuthenticationStore) {
	store := factory()
	ctx := context.Background()
	record := newBackchannelAuthenticationRecord("auth-req-10", "handle-10")
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
}

// testBackchannelAuthenticationStorePollImmediatelyAfterPingDecisionSkipsIntervalCheck
// covers CIBA Core 1.0 §10.2: a ping notification is the client's
// permission to poll immediately, regardless of PollInterval —
// confirmed live against the OIDF suite's own fapi-ciba-id1-ping-*
// modules, which call the token endpoint the instant they receive the
// notification and require success, not slow_down.
// DecideBackchannelAuthentication must therefore exempt the very next
// poll from the interval check under ping delivery, even though an
// earlier poll happened well within the interval.
func testBackchannelAuthenticationStorePollImmediatelyAfterPingDecisionSkipsIntervalCheck(t *testing.T, factory func() BackchannelAuthenticationStore) {
	store := factory()
	ctx := context.Background()
	record := newBackchannelAuthenticationRecord("auth-req-ping-interval-1", "handle-ping-interval-1")
	record.DeliveryMode = "ping"
	record.ClientNotificationToken = fapi.NewSecret("notification-token-1")
	record.AuthReqID = "auth-req-ping-interval-1"
	record.PollInterval = 5 * time.Second
	if err := store.CreateBackchannelAuthentication(ctx, record); err != nil {
		t.Fatalf("CreateBackchannelAuthentication: %v", err)
	}
	now := time.Now()
	if _, err := store.PollBackchannelAuthentication(ctx, PollBackchannelAuthentication{
		AuthReqIDHash: record.AuthReqIDHash, Now: now,
	}); err != nil {
		t.Fatalf("first poll (pending): %v", err)
	}
	if _, err := store.DecideBackchannelAuthentication(ctx, DecideBackchannelAuthentication{
		HandleHash: record.HandleHash, Status: BackchannelAuthenticationApproved, Grant: contractPayload,
	}); err != nil {
		t.Fatalf("DecideBackchannelAuthentication: %v", err)
	}
	// Well within PollInterval of the first poll above — would fail
	// with *BackchannelAuthenticationSlowDownError under poll delivery
	// (see testBackchannelAuthenticationStorePollFasterThanIntervalFails),
	// but must succeed here since a ping notification was just
	// dispatched.
	if _, err := store.PollBackchannelAuthentication(ctx, PollBackchannelAuthentication{
		AuthReqIDHash: record.AuthReqIDHash, Now: now.Add(time.Second),
	}); err != nil {
		t.Fatalf("poll immediately after ping decision: %v, want success", err)
	}
}

// contractPayload stands in for the opaque Request/Grant values server
// stores: nested JSON a store must return equivalent, without
// interpreting it.
var contractPayload = json.RawMessage(`{"v":1,"sub":"user-1","scope":["openid","accounts"],"claims":{"acr":"urn:acr:1","nested":[1,{"a":null}]}}`)

// jsonEquivalent reports whether a and b are the same JSON value,
// ignoring key order and whitespace — a store may keep an opaque value
// in a JSON column that normalizes either.
func jsonEquivalent(a, b json.RawMessage) bool {
	var av, bv any
	if json.Unmarshal(a, &av) != nil || json.Unmarshal(b, &bv) != nil {
		return false
	}
	return reflect.DeepEqual(av, bv)
}

// TestRevocationStoreContract exercises the security-critical behaviour
// of a RevocationStore implementation: a revoked key reads as revoked,
// keys are compared exactly (an access token's key, a grant's "grant:"
// key and a reused code's "code-grant:" key never answer for each
// other, and neither does one issuer's grant key for another's),
// revoking again is harmless, and concurrent revocations all
// land. A store failing any of these lets a revoked token or grant keep
// working.
func TestRevocationStoreContract(t *testing.T, factory func() RevocationStore) {
	t.Helper()
	ctx := context.Background()
	later := time.Now().Add(time.Hour)

	t.Run("UnknownKeyIsNotRevoked", func(t *testing.T) {
		revoked, err := factory().IsRevoked(ctx, "never-revoked")
		if err != nil || revoked {
			t.Fatalf("IsRevoked(unknown) = %v, %v, want false, nil", revoked, err)
		}
	})
	t.Run("RevokedKeyIsRevoked", func(t *testing.T) {
		s := factory()
		if err := s.Revoke(ctx, "jti-1", later); err != nil {
			t.Fatalf("Revoke: %v", err)
		}
		if revoked, err := s.IsRevoked(ctx, "jti-1"); err != nil || !revoked {
			t.Fatalf("IsRevoked(revoked) = %v, %v, want true, nil", revoked, err)
		}
	})
	t.Run("KeysAreExact", func(t *testing.T) {
		s := factory()
		for _, key := range []string{"grant:g1", "grant:g2@https://as.example.com", "abc"} {
			if err := s.Revoke(ctx, key, later); err != nil {
				t.Fatalf("Revoke(%q): %v", key, err)
			}
		}
		for _, key := range []string{
			"g1", "code-grant:g1", "grant:g", "grant:g1 ", "GRANT:g1", "ABC", "abc ", "grant:abc", "",
			"grant:g2", "grant:g1@https://as.example.com", "grant:g2@https://as.example.com/",
			"grant:g2@https://AS.example.com", "grant:g2@https://tenant-b.example.com", "code-grant:g2@https://as.example.com",
		} {
			if revoked, err := s.IsRevoked(ctx, key); err != nil || revoked {
				t.Fatalf("IsRevoked(%q) = %v, %v, want false, nil: only exactly the revoked keys are revoked", key, revoked, err)
			}
		}
	})
	t.Run("RevokeAgainKeepsItRevoked", func(t *testing.T) {
		s := factory()
		for _, expiresAt := range []time.Time{later, later.Add(time.Hour), later} {
			if err := s.Revoke(ctx, "jti-2", expiresAt); err != nil {
				t.Fatalf("Revoke again: %v", err)
			}
		}
		if revoked, err := s.IsRevoked(ctx, "jti-2"); err != nil || !revoked {
			t.Fatalf("IsRevoked after revoking again = %v, %v, want true, nil", revoked, err)
		}
	})
	t.Run("ConcurrentRevokesAllLand", func(t *testing.T) {
		s := factory()
		var n int
		var mu sync.Mutex
		runConcurrently(contractConcurrentAttempts, func() bool {
			mu.Lock()
			key := fmt.Sprintf("concurrent-%d", n)
			n++
			mu.Unlock()
			return s.Revoke(ctx, key, later) == nil
		})
		for i := 0; i < contractConcurrentAttempts; i++ {
			key := fmt.Sprintf("concurrent-%d", i)
			if revoked, err := s.IsRevoked(ctx, key); err != nil || !revoked {
				t.Fatalf("IsRevoked(%q) = %v, %v, want true, nil", key, revoked, err)
			}
		}
	})
	if _, ok := factory().(RevocationBatchChecker); ok {
		t.Run("IsAnyRevokedMatchesIsRevoked", func(t *testing.T) { testRevocationStoreIsAnyRevoked(t, factory) })
	}
}

// testRevocationStoreIsAnyRevoked checks a RevocationBatchChecker's
// IsAnyRevoked against IsRevoked: true exactly when some key is revoked,
// wherever it is among keys, with keys compared exactly; false for no
// keys.
func testRevocationStoreIsAnyRevoked(t *testing.T, factory func() RevocationStore) {
	ctx := context.Background()
	s := factory()
	batch := s.(RevocationBatchChecker)
	revokedKey := "grant:g1@https://as.example.com"
	if err := s.Revoke(ctx, revokedKey, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	near := []string{"jti-1", "grant:g1", "grant:g1@https://as.example.com/", "GRANT:g1@https://as.example.com", "code-grant:g1@https://as.example.com"}
	for _, tc := range []struct {
		name string
		keys []string
		want bool
	}{
		{"None", nil, false},
		{"Empty", []string{}, false},
		{"OnlyUnrevoked", near, false},
		{"EmptyKey", []string{""}, false},
		{"OnlyRevoked", []string{revokedKey}, true},
		{"RevokedFirst", append([]string{revokedKey}, near...), true},
		{"RevokedLast", append(slices.Clone(near), revokedKey), true},
		{"RevokedInMiddle", []string{near[0], near[1], revokedKey, near[2], near[3]}, true},
		{"RevokedTwice", []string{revokedKey, revokedKey}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := batch.IsAnyRevoked(ctx, tc.keys)
			if err != nil || got != tc.want {
				t.Fatalf("IsAnyRevoked(%q) = %v, %v, want %v, nil", tc.keys, got, err, tc.want)
			}
			each := false
			for _, key := range tc.keys {
				revoked, err := s.IsRevoked(ctx, key)
				if err != nil {
					t.Fatalf("IsRevoked(%q): %v", key, err)
				}
				each = each || revoked
			}
			if got != each {
				t.Fatalf("IsAnyRevoked(%q) = %v, but IsRevoked says %v", tc.keys, got, each)
			}
		})
	}
}

// TestClientRepositoryContract exercises the security-critical behaviour
// of a ClientRepository implementation, given a factory returning one
// holding exactly the clients passed: ResolveClient returns the client
// registered under exactly the requested ID — never another — and an
// unknown ID is an error that isn't ErrStoreUnavailable, so the server
// answers it as an unknown client rather than an outage.
func TestClientRepositoryContract(t *testing.T, factory func(clients []RegisteredClient) ClientRepository) {
	t.Helper()
	ctx := context.Background()
	newClient := func(t *testing.T, id fapi.ClientID) RegisteredClient {
		t.Helper()
		c, err := NewRegisteredClient(RegisteredClientConfig{
			ID:                       id,
			RedirectURIs:             []fapi.RegisteredRedirectURI{"https://rp.example/callback"},
			ClientAssertionAlgorithm: fapi.ES256,
			AllowedScopes:            []string{"accounts"},
		})
		if err != nil {
			t.Fatalf("NewRegisteredClient(%q): %v", id, err)
		}
		return c
	}

	t.Run("ResolvesExactlyTheRequestedClient", func(t *testing.T) {
		repo := factory([]RegisteredClient{newClient(t, "client-1"), newClient(t, "client-2")})
		for _, id := range []fapi.ClientID{"client-1", "client-2"} {
			c, err := repo.ResolveClient(ctx, id)
			if err != nil {
				t.Fatalf("ResolveClient(%q): %v", id, err)
			}
			if c.ID() != id {
				t.Fatalf("ResolveClient(%q) returned client %q", id, c.ID())
			}
		}
	})
	t.Run("UnknownClientIsAnErrorNotAnOutage", func(t *testing.T) {
		repo := factory([]RegisteredClient{newClient(t, "client-1")})
		for _, id := range []fapi.ClientID{"client-3", "CLIENT-1", "client-1 ", "client-", "client-10", ""} {
			_, err := repo.ResolveClient(ctx, id)
			if err == nil {
				t.Fatalf("ResolveClient(%q) = nil error, want an unknown client", id)
			}
			if errors.Is(err, ErrStoreUnavailable) {
				t.Fatalf("ResolveClient(%q) = %v, which wraps ErrStoreUnavailable; an unknown client isn't an outage", id, err)
			}
		}
	})
}

// TestPairwiseSubjectStoreContract exercises factory()'s behavior
// against the PairwiseSubjectStore contract: GetOrCreate stores a body
// once and returns it ever after, exactly one candidate wins under
// concurrency, a body already in use in the same issuer and sector is
// refused as a collision without storing anything, and Lookup maps a
// body back to its subject within exactly its issuer and sector.
func TestPairwiseSubjectStoreContract(t *testing.T, factory func() PairwiseSubjectStore) {
	t.Helper()
	t.Run("GetOrCreateStoresTheCandidate", func(t *testing.T) { testPairwiseSubjectStoreGetOrCreate(t, factory) })
	t.Run("GetOrCreateKeepsTheFirstBody", func(t *testing.T) { testPairwiseSubjectStoreKeepsFirstBody(t, factory) })
	t.Run("ConcurrentGetOrCreateHasExactlyOneWinner", func(t *testing.T) { testPairwiseSubjectStoreConcurrentGetOrCreate(t, factory) })
	t.Run("LookupUnknownBodyIsNotFound", func(t *testing.T) { testPairwiseSubjectStoreLookupUnknown(t, factory) })
	t.Run("CollisionIsReportedAndStoresNothing", func(t *testing.T) { testPairwiseSubjectStoreCollision(t, factory) })
	t.Run("IssuersAndSectorsAreSeparate", func(t *testing.T) { testPairwiseSubjectStoreIsolation(t, factory) })
	t.Run("KeysAndBodiesAreExact", func(t *testing.T) { testPairwiseSubjectStoreExactness(t, factory) })
}

const (
	contractPairwiseIssuer = "https://as.example"
	contractPairwiseSector = "rp.example"
)

func contractPairwiseKey(subject string) PairwiseSubjectKey {
	return PairwiseSubjectKey{Issuer: contractPairwiseIssuer, Sector: contractPairwiseSector, Subject: subject}
}

// mustGetOrCreate calls GetOrCreate and fails the test on an error or
// a body other than want.
func mustGetOrCreate(t *testing.T, s PairwiseSubjectStore, key PairwiseSubjectKey, candidate, want string) {
	t.Helper()
	body, err := s.GetOrCreate(context.Background(), key, candidate)
	if err != nil || body != want {
		t.Fatalf("GetOrCreate(%+v, %q) = %q, %v, want %q, nil", key, candidate, body, err, want)
	}
}

// mustLookup calls Lookup and fails the test on an error or a subject
// other than want.
func mustLookup(t *testing.T, s PairwiseSubjectStore, issuer, sector, body, want string) {
	t.Helper()
	subject, err := s.Lookup(context.Background(), issuer, sector, body)
	if err != nil || subject != want {
		t.Fatalf("Lookup(%q, %q, %q) = %q, %v, want %q, nil", issuer, sector, body, subject, err, want)
	}
}

// mustNotFind calls Lookup and fails the test unless it reports
// ErrPairwiseSubjectNotFound, and not ErrStoreUnavailable.
func mustNotFind(t *testing.T, s PairwiseSubjectStore, issuer, sector, body string) {
	t.Helper()
	subject, err := s.Lookup(context.Background(), issuer, sector, body)
	if !errors.Is(err, ErrPairwiseSubjectNotFound) || errors.Is(err, ErrStoreUnavailable) {
		t.Fatalf("Lookup(%q, %q, %q) = %q, %v, want ErrPairwiseSubjectNotFound", issuer, sector, body, subject, err)
	}
}

func testPairwiseSubjectStoreGetOrCreate(t *testing.T, factory func() PairwiseSubjectStore) {
	s := factory()
	mustGetOrCreate(t, s, contractPairwiseKey("user-1"), "body-1", "body-1")
	mustLookup(t, s, contractPairwiseIssuer, contractPairwiseSector, "body-1", "user-1")
}

func testPairwiseSubjectStoreKeepsFirstBody(t *testing.T, factory func() PairwiseSubjectStore) {
	s := factory()
	mustGetOrCreate(t, s, contractPairwiseKey("user-1"), "body-1", "body-1")
	mustGetOrCreate(t, s, contractPairwiseKey("user-1"), "body-2", "body-1")
	// A candidate already in use is ignored too once the key has a body.
	mustGetOrCreate(t, s, contractPairwiseKey("user-2"), "body-3", "body-3")
	mustGetOrCreate(t, s, contractPairwiseKey("user-1"), "body-3", "body-1")
	mustNotFind(t, s, contractPairwiseIssuer, contractPairwiseSector, "body-2")
	mustLookup(t, s, contractPairwiseIssuer, contractPairwiseSector, "body-1", "user-1")
}

func testPairwiseSubjectStoreConcurrentGetOrCreate(t *testing.T, factory func() PairwiseSubjectStore) {
	s := factory()
	var mu sync.Mutex
	var next int
	bodies := make(map[string]bool)
	runConcurrently(contractConcurrentAttempts, func() bool {
		mu.Lock()
		candidate := fmt.Sprintf("candidate-%d", next)
		next++
		mu.Unlock()
		body, err := s.GetOrCreate(context.Background(), contractPairwiseKey("user-1"), candidate)
		if err != nil {
			t.Errorf("GetOrCreate(%q): %v", candidate, err)
			return false
		}
		mu.Lock()
		bodies[body] = true
		mu.Unlock()
		return true
	})
	if len(bodies) != 1 {
		t.Fatalf("concurrent GetOrCreate returned %d different bodies, want 1: %v", len(bodies), bodies)
	}
	for body := range bodies {
		mustLookup(t, s, contractPairwiseIssuer, contractPairwiseSector, body, "user-1")
	}
	// Every losing candidate was stored for no one.
	for i := 0; i < contractConcurrentAttempts; i++ {
		if candidate := fmt.Sprintf("candidate-%d", i); !bodies[candidate] {
			mustNotFind(t, s, contractPairwiseIssuer, contractPairwiseSector, candidate)
		}
	}
}

func testPairwiseSubjectStoreLookupUnknown(t *testing.T, factory func() PairwiseSubjectStore) {
	mustNotFind(t, factory(), contractPairwiseIssuer, contractPairwiseSector, "never-stored")
}

func testPairwiseSubjectStoreCollision(t *testing.T, factory func() PairwiseSubjectStore) {
	s := factory()
	mustGetOrCreate(t, s, contractPairwiseKey("user-1"), "body-1", "body-1")
	body, err := s.GetOrCreate(context.Background(), contractPairwiseKey("user-2"), "body-1")
	if !errors.Is(err, ErrPairwiseSubjectCollision) {
		t.Fatalf("GetOrCreate(another subject, a body in use) = %q, %v, want ErrPairwiseSubjectCollision", body, err)
	}
	mustLookup(t, s, contractPairwiseIssuer, contractPairwiseSector, "body-1", "user-1")
	// Nothing was stored for user-2, so a fresh candidate succeeds.
	mustGetOrCreate(t, s, contractPairwiseKey("user-2"), "body-2", "body-2")
	mustLookup(t, s, contractPairwiseIssuer, contractPairwiseSector, "body-2", "user-2")
}

func testPairwiseSubjectStoreIsolation(t *testing.T, factory func() PairwiseSubjectStore) {
	s := factory()
	otherSector := PairwiseSubjectKey{Issuer: contractPairwiseIssuer, Sector: "other.example", Subject: "user-2"}
	otherIssuer := PairwiseSubjectKey{Issuer: "https://other-as.example", Sector: contractPairwiseSector, Subject: "user-3"}
	mustGetOrCreate(t, s, contractPairwiseKey("user-1"), "body-1", "body-1")
	// The same body is free in another sector or issuer.
	mustGetOrCreate(t, s, otherSector, "body-1", "body-1")
	mustGetOrCreate(t, s, otherIssuer, "body-1", "body-1")
	mustLookup(t, s, contractPairwiseIssuer, contractPairwiseSector, "body-1", "user-1")
	mustLookup(t, s, contractPairwiseIssuer, "other.example", "body-1", "user-2")
	mustLookup(t, s, "https://other-as.example", contractPairwiseSector, "body-1", "user-3")
	// The same subject has a separate body per sector.
	sameUserOtherSector := PairwiseSubjectKey{Issuer: contractPairwiseIssuer, Sector: "third.example", Subject: "user-1"}
	mustGetOrCreate(t, s, sameUserOtherSector, "body-4", "body-4")
	mustGetOrCreate(t, s, contractPairwiseKey("user-1"), "body-5", "body-1")
	mustNotFind(t, s, contractPairwiseIssuer, contractPairwiseSector, "body-4")
}

func testPairwiseSubjectStoreExactness(t *testing.T, factory func() PairwiseSubjectStore) {
	s := factory()
	mustGetOrCreate(t, s, contractPairwiseKey("user-1"), "Body-1", "Body-1")
	for _, body := range []string{"body-1", "BODY-1", "Body-1 ", " Body-1", "Body-", ""} {
		mustNotFind(t, s, contractPairwiseIssuer, contractPairwiseSector, body)
	}
	mustNotFind(t, s, contractPairwiseIssuer+"/", contractPairwiseSector, "Body-1")
	mustNotFind(t, s, contractPairwiseIssuer, "RP.example", "Body-1")
	// A differently spelled subject is a different user.
	mustGetOrCreate(t, s, contractPairwiseKey("User-1"), "body-2", "body-2")
	mustLookup(t, s, contractPairwiseIssuer, contractPairwiseSector, "body-2", "User-1")
}

// testGrantStoreRedeemRefreshTokenDoesNotReturnAuthorizationCode and
// testGrantStoreRedeemAuthorizationCodeDoesNotReturnRefreshToken cover
// GrantStore's two kinds of record staying apart: a store keeping both
// in one table keyed by digest alone would redeem an authorization code
// as a refresh token (skipping the code exchange's PKCE, redirect_uri,
// DPoP binding and single use) were the two digests ever equal.
func testGrantStoreRedeemRefreshTokenDoesNotReturnAuthorizationCode(t *testing.T, factory func() GrantStore) {
	store := factory()
	ctx := context.Background()
	hash := sha256.Sum256([]byte("code-not-refresh"))
	if err := store.CreateAuthorizationCode(ctx, NewAuthorizationCode{
		CodeHash: hash, ClientID: "client-1", Grant: contractPayload, ExpiresAt: time.Now().Add(time.Minute),
	}); err != nil {
		t.Fatalf("CreateAuthorizationCode: %v", err)
	}
	if _, err := store.RedeemRefreshToken(ctx, RefreshTokenRedemption{TokenHash: hash}); err == nil {
		t.Fatalf("RedeemRefreshToken(an authorization code's digest) = nil error, want error")
	}
	if _, err := store.RedeemAuthorizationCode(ctx, AuthorizationCodeRedemption{CodeHash: hash}); err != nil {
		t.Fatalf("RedeemAuthorizationCode after the refused RedeemRefreshToken: %v", err)
	}
}

func testGrantStoreRedeemAuthorizationCodeDoesNotReturnRefreshToken(t *testing.T, factory func() GrantStore) {
	store := factory()
	ctx := context.Background()
	hash := sha256.Sum256([]byte("refresh-not-code"))
	if err := store.CreateRefreshToken(ctx, NewRefreshToken{
		TokenHash: hash, ClientID: "client-1", Grant: contractPayload, ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("CreateRefreshToken: %v", err)
	}
	if _, err := store.RedeemAuthorizationCode(ctx, AuthorizationCodeRedemption{CodeHash: hash}); err == nil {
		t.Fatalf("RedeemAuthorizationCode(a refresh token's digest) = nil error, want error")
	}
	if _, err := store.RedeemRefreshToken(ctx, RefreshTokenRedemption{TokenHash: hash}); err != nil {
		t.Fatalf("RedeemRefreshToken after the refused RedeemAuthorizationCode: %v", err)
	}
}

// TestInteractionLookupContract exercises factory()'s InteractionLookup
// against the guarantees its documentation promises, together with the
// TransactionStore it reads: a lookup returns the interaction as
// BeginAuthorization stored it and consumes nothing, and an unknown,
// completed or expired interaction isn't returned. factory must return a
// fresh, empty TransactionStore each call, with the InteractionLookup
// built on the same storage.
func TestInteractionLookupContract(t *testing.T, factory func() (TransactionStore, InteractionLookup)) {
	t.Helper()

	t.Run("LookupReturnsStoredInteraction", func(t *testing.T) { testInteractionLookupReturnsStoredInteraction(t, factory) })
	t.Run("LookupConsumesNothing", func(t *testing.T) { testInteractionLookupConsumesNothing(t, factory) })
	t.Run("LookupUnknownHandleFails", func(t *testing.T) { testInteractionLookupUnknownHandleFails(t, factory) })
	t.Run("LookupFailsAfterCompletion", func(t *testing.T) { testInteractionLookupFailsAfterCompletion(t, factory) })
	t.Run("LookupFailsOnceExpired", func(t *testing.T) { testInteractionLookupFailsOnceExpired(t, factory) })
}

// beginForLookup pushes reference for client-1 and begins each of
// handles for it, expiring at handleExpiresAt.
func beginForLookup(t *testing.T, store TransactionStore, reference string, handleExpiresAt time.Time, handles ...string) {
	t.Helper()
	ctx := context.Background()
	if err := store.CreatePAR(ctx, NewPARRecord{
		Reference: reference, ClientID: "client-1", Request: contractPayload, ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("CreatePAR: %v", err)
	}
	for _, handle := range handles {
		if _, err := store.BeginAuthorization(ctx, BeginAuthorizationTransaction{
			Reference: reference, Handle: handle, HandleExpiresAt: handleExpiresAt, Now: time.Now(),
		}); err != nil {
			t.Fatalf("BeginAuthorization(%q): %v", handle, err)
		}
	}
}

func testInteractionLookupReturnsStoredInteraction(t *testing.T, factory func() (TransactionStore, InteractionLookup)) {
	store, lookup := factory()
	expires := time.Now().Add(time.Minute).Truncate(time.Millisecond)
	beginForLookup(t, store, "ref-l1", expires, "handle-l1")
	got, err := lookup.LookupAuthorization(context.Background(), LookupAuthorizationTransaction{Handle: "handle-l1", Now: time.Now()})
	if err != nil {
		t.Fatalf("LookupAuthorization: %v", err)
	}
	if got.ClientID != "client-1" {
		t.Errorf("ClientID = %q, want client-1", got.ClientID)
	}
	if !jsonEquivalent(got.Request, contractPayload) {
		t.Errorf("Request = %s, want %s", got.Request, contractPayload)
	}
	if !got.ExpiresAt.Equal(expires) {
		t.Errorf("ExpiresAt = %v, want %v", got.ExpiresAt, expires)
	}
}

func testInteractionLookupConsumesNothing(t *testing.T, factory func() (TransactionStore, InteractionLookup)) {
	store, lookup := factory()
	ctx := context.Background()
	beginForLookup(t, store, "ref-l2", time.Now().Add(time.Minute), "handle-l2")
	for i := range 2 {
		if _, err := lookup.LookupAuthorization(ctx, LookupAuthorizationTransaction{Handle: "handle-l2", Now: time.Now()}); err != nil {
			t.Fatalf("LookupAuthorization #%d: %v", i+1, err)
		}
	}
	if _, err := store.BeginAuthorization(ctx, BeginAuthorizationTransaction{
		Reference: "ref-l2", Handle: "handle-l2b", HandleExpiresAt: time.Now().Add(time.Minute), Now: time.Now(),
	}); err != nil {
		t.Fatalf("BeginAuthorization after lookups: %v, want the reference still unconsumed", err)
	}
	if _, err := store.CompleteAuthorization(ctx, CompleteAuthorizationTransaction{Handle: "handle-l2"}); err != nil {
		t.Fatalf("CompleteAuthorization after lookups: %v, want the handle still unconsumed", err)
	}
}

func testInteractionLookupUnknownHandleFails(t *testing.T, factory func() (TransactionStore, InteractionLookup)) {
	_, lookup := factory()
	if _, err := lookup.LookupAuthorization(context.Background(), LookupAuthorizationTransaction{Handle: "never-began", Now: time.Now()}); err == nil {
		t.Fatal("LookupAuthorization(unknown handle) = nil error, want error")
	}
}

// testInteractionLookupFailsAfterCompletion: once one interaction for a
// reference completes, neither its handle nor another minted from the
// same reference is returned, since neither can complete any more.
func testInteractionLookupFailsAfterCompletion(t *testing.T, factory func() (TransactionStore, InteractionLookup)) {
	store, lookup := factory()
	ctx := context.Background()
	beginForLookup(t, store, "ref-l3", time.Now().Add(time.Minute), "handle-l3a", "handle-l3b")
	if _, err := store.CompleteAuthorization(ctx, CompleteAuthorizationTransaction{Handle: "handle-l3a"}); err != nil {
		t.Fatalf("CompleteAuthorization: %v", err)
	}
	for _, handle := range []string{"handle-l3a", "handle-l3b"} {
		if _, err := lookup.LookupAuthorization(ctx, LookupAuthorizationTransaction{Handle: handle, Now: time.Now()}); err == nil {
			t.Errorf("LookupAuthorization(%q) after completion = nil error, want error", handle)
		}
	}
}

func testInteractionLookupFailsOnceExpired(t *testing.T, factory func() (TransactionStore, InteractionLookup)) {
	store, lookup := factory()
	expires := time.Now().Add(time.Minute)
	beginForLookup(t, store, "ref-l4", expires, "handle-l4")
	for _, now := range []time.Time{expires, expires.Add(time.Second)} {
		if _, err := lookup.LookupAuthorization(context.Background(), LookupAuthorizationTransaction{Handle: "handle-l4", Now: now}); err == nil {
			t.Errorf("LookupAuthorization at %v, handle expiring %v = nil error, want error", now, expires)
		}
	}
}

// TestPushedRequestLookupContract exercises factory()'s
// PushedRequestLookup against the guarantees its documentation
// promises, together with the TransactionStore it reads: a lookup
// returns the ClientID and expiry CreatePAR stored, consumes nothing,
// and still finds a request begun but not completed; an unknown,
// completed or expired request isn't returned, with an error that
// doesn't wrap ErrStoreUnavailable. factory must return a fresh, empty
// TransactionStore each call, with the PushedRequestLookup built on the
// same storage.
func TestPushedRequestLookupContract(t *testing.T, factory func() (TransactionStore, PushedRequestLookup)) {
	t.Helper()

	t.Run("LookupReturnsStoredRequest", func(t *testing.T) { testPushedRequestLookupReturnsStoredRequest(t, factory) })
	t.Run("LookupConsumesNothing", func(t *testing.T) { testPushedRequestLookupConsumesNothing(t, factory) })
	t.Run("LookupUnknownReferenceFails", func(t *testing.T) { testPushedRequestLookupUnknownReferenceFails(t, factory) })
	t.Run("LookupFailsAfterCompletion", func(t *testing.T) { testPushedRequestLookupFailsAfterCompletion(t, factory) })
	t.Run("LookupFailsOnceExpired", func(t *testing.T) { testPushedRequestLookupFailsOnceExpired(t, factory) })
}

// pushForLookup pushes reference for client-1, expiring at expiresAt.
func pushForLookup(t *testing.T, store TransactionStore, reference string, expiresAt time.Time) {
	t.Helper()
	if err := store.CreatePAR(context.Background(), NewPARRecord{
		Reference: reference, ClientID: "client-1", Request: contractPayload, ExpiresAt: expiresAt,
	}); err != nil {
		t.Fatalf("CreatePAR: %v", err)
	}
}

// beginAndCompleteForLookup begins an interaction for reference under
// handle and, when complete is set, completes it.
func beginAndCompleteForLookup(t *testing.T, store TransactionStore, reference, handle string, complete bool) {
	t.Helper()
	ctx := context.Background()
	if _, err := store.BeginAuthorization(ctx, BeginAuthorizationTransaction{
		Reference: reference, Handle: handle, HandleExpiresAt: time.Now().Add(time.Minute), Now: time.Now(),
	}); err != nil {
		t.Fatalf("BeginAuthorization(%q): %v", reference, err)
	}
	if !complete {
		return
	}
	if _, err := store.CompleteAuthorization(ctx, CompleteAuthorizationTransaction{Handle: handle}); err != nil {
		t.Fatalf("CompleteAuthorization(%q): %v", handle, err)
	}
}

// wantPushedRequestUnusable checks lookup refuses reference at now,
// with an error that doesn't wrap ErrStoreUnavailable: the server would
// answer that with 500 server_error, not as the unusable request_uri it
// is. what names the case in the failure.
func wantPushedRequestUnusable(t *testing.T, lookup PushedRequestLookup, reference string, now time.Time, what string) {
	t.Helper()
	_, err := lookup.LookupPushedRequest(context.Background(), LookupPushedRequestTransaction{Reference: reference, Now: now})
	switch {
	case err == nil:
		t.Errorf("LookupPushedRequest(%s) = nil error, want error", what)
	case errors.Is(err, ErrStoreUnavailable):
		t.Errorf("LookupPushedRequest(%s) = %v, which wraps ErrStoreUnavailable; an unusable request_uri isn't an outage", what, err)
	}
}

func testPushedRequestLookupReturnsStoredRequest(t *testing.T, factory func() (TransactionStore, PushedRequestLookup)) {
	store, lookup := factory()
	expires := time.Now().Add(time.Minute).Truncate(time.Millisecond)
	pushForLookup(t, store, "ref-p1", expires)
	got, err := lookup.LookupPushedRequest(context.Background(), LookupPushedRequestTransaction{Reference: "ref-p1", Now: time.Now()})
	if err != nil {
		t.Fatalf("LookupPushedRequest: %v", err)
	}
	if got.ClientID != "client-1" {
		t.Errorf("ClientID = %q, want client-1", got.ClientID)
	}
	if !got.ExpiresAt.Equal(expires) {
		t.Errorf("ExpiresAt = %v, want %v", got.ExpiresAt, expires)
	}
}

// testPushedRequestLookupConsumesNothing: lookups leave the reference to
// be begun and completed as if they hadn't happened, and a reference
// begun but not completed is still found, since it can be begun again
// (FAPI 2.0 Security Profile 5.3.2.2 Note 3).
func testPushedRequestLookupConsumesNothing(t *testing.T, factory func() (TransactionStore, PushedRequestLookup)) {
	store, lookup := factory()
	ctx := context.Background()
	pushForLookup(t, store, "ref-p2", time.Now().Add(time.Hour))
	lookUp := func(when string) {
		t.Helper()
		if _, err := lookup.LookupPushedRequest(ctx, LookupPushedRequestTransaction{Reference: "ref-p2", Now: time.Now()}); err != nil {
			t.Fatalf("LookupPushedRequest %s: %v", when, err)
		}
	}
	lookUp("before BeginAuthorization")
	lookUp("a second time")
	beginAndCompleteForLookup(t, store, "ref-p2", "handle-p2a", false)
	lookUp("after BeginAuthorization, before completion")
	beginAndCompleteForLookup(t, store, "ref-p2", "handle-p2b", true)
}

func testPushedRequestLookupUnknownReferenceFails(t *testing.T, factory func() (TransactionStore, PushedRequestLookup)) {
	store, lookup := factory()
	pushForLookup(t, store, "ref-p3", time.Now().Add(time.Hour))
	wantPushedRequestUnusable(t, lookup, "never-pushed", time.Now(), "an unknown reference")
}

// testPushedRequestLookupFailsAfterCompletion: once an interaction for a
// reference completes, BeginAuthorization can't begin it any more, so
// the lookup doesn't find it.
func testPushedRequestLookupFailsAfterCompletion(t *testing.T, factory func() (TransactionStore, PushedRequestLookup)) {
	store, lookup := factory()
	pushForLookup(t, store, "ref-p4", time.Now().Add(time.Hour))
	beginAndCompleteForLookup(t, store, "ref-p4", "handle-p4", true)
	wantPushedRequestUnusable(t, lookup, "ref-p4", time.Now(), "a reference whose interaction completed")
}

func testPushedRequestLookupFailsOnceExpired(t *testing.T, factory func() (TransactionStore, PushedRequestLookup)) {
	store, lookup := factory()
	expires := time.Now().Add(time.Minute)
	pushForLookup(t, store, "ref-p5", expires)
	for _, now := range []time.Time{expires, expires.Add(time.Second)} {
		wantPushedRequestUnusable(t, lookup, "ref-p5", now, fmt.Sprintf("at %v, the reference expiring at %v", now, expires))
	}
}

// TestGrantRegistryContract exercises factory()'s behavior against the
// guarantees GrantRegistry's documentation promises: entries round-trip
// unmodified, are listed only for their own subject and only until they
// expire, are replaced by key, and are deleted by key. factory must
// return a fresh, empty GrantRegistry each call.
func TestGrantRegistryContract(t *testing.T, factory func() GrantRegistry) {
	t.Helper()

	t.Run("RecordAndList", func(t *testing.T) { testGrantRegistryRecordAndList(t, factory) })
	t.Run("ListOnlyTheSubjects", func(t *testing.T) { testGrantRegistryListOnlyTheSubjects(t, factory) })
	t.Run("ListOnlyUnexpired", func(t *testing.T) { testGrantRegistryListOnlyUnexpired(t, factory) })
	t.Run("RecordReplacesByKey", func(t *testing.T) { testGrantRegistryRecordReplacesByKey(t, factory) })
	t.Run("Delete", func(t *testing.T) { testGrantRegistryDelete(t, factory) })
	t.Run("ListByKey", func(t *testing.T) { testGrantRegistryListByKey(t, factory) })
}

func recordGrantEntry(t *testing.T, registry GrantRegistry, entry NewGrantEntry) {
	t.Helper()
	if err := registry.RecordGrant(context.Background(), entry); err != nil {
		t.Fatalf("RecordGrant(%q): %v", entry.Key, err)
	}
}

func listGrantKeys(t *testing.T, registry GrantRegistry, subjectKey string, now time.Time) []string {
	t.Helper()
	entries, err := registry.ListGrants(context.Background(), GrantListing{SubjectKey: subjectKey, Now: now})
	if err != nil {
		t.Fatalf("ListGrants(%q): %v", subjectKey, err)
	}
	keys := make([]string, 0, len(entries))
	for _, e := range entries {
		keys = append(keys, e.Key)
	}
	slices.Sort(keys)
	return keys
}

func testGrantRegistryRecordAndList(t *testing.T, factory func() GrantRegistry) {
	registry := factory()
	expires := time.Now().Add(time.Hour).Truncate(time.Millisecond)
	recordGrantEntry(t, registry, NewGrantEntry{Key: "g1", SubjectKey: "s1", ClientID: "client-1", Record: contractPayload, ExpiresAt: expires})
	entries, err := registry.ListGrants(context.Background(), GrantListing{SubjectKey: "s1", Now: time.Now()})
	if err != nil {
		t.Fatalf("ListGrants: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("ListGrants = %d entries, want 1", len(entries))
	}
	got := entries[0]
	if got.Key != "g1" || got.ClientID != "client-1" || !got.ExpiresAt.Equal(expires) {
		t.Errorf("entry = %q %q %v, want g1 client-1 %v", got.Key, got.ClientID, got.ExpiresAt, expires)
	}
	if !jsonEquivalent(got.Record, contractPayload) {
		t.Errorf("Record = %s, want %s", got.Record, contractPayload)
	}
}

func testGrantRegistryListOnlyTheSubjects(t *testing.T, factory func() GrantRegistry) {
	registry := factory()
	expires := time.Now().Add(time.Hour)
	recordGrantEntry(t, registry, NewGrantEntry{Key: "g1", SubjectKey: "s1", ClientID: "client-1", Record: contractPayload, ExpiresAt: expires})
	recordGrantEntry(t, registry, NewGrantEntry{Key: "g2", SubjectKey: "s1", ClientID: "client-2", Record: contractPayload, ExpiresAt: expires})
	recordGrantEntry(t, registry, NewGrantEntry{Key: "g3", SubjectKey: "s2", ClientID: "client-1", Record: contractPayload, ExpiresAt: expires})
	if got := listGrantKeys(t, registry, "s1", time.Now()); !slices.Equal(got, []string{"g1", "g2"}) {
		t.Errorf("ListGrants(s1) = %v, want [g1 g2]", got)
	}
	if got := listGrantKeys(t, registry, "s3", time.Now()); len(got) != 0 {
		t.Errorf("ListGrants(unknown subject) = %v, want none", got)
	}
}

func testGrantRegistryListOnlyUnexpired(t *testing.T, factory func() GrantRegistry) {
	registry := factory()
	expires := time.Now().Add(time.Hour)
	recordGrantEntry(t, registry, NewGrantEntry{Key: "g1", SubjectKey: "s1", ClientID: "client-1", Record: contractPayload, ExpiresAt: expires})
	for _, now := range []time.Time{expires, expires.Add(time.Second)} {
		if got := listGrantKeys(t, registry, "s1", now); len(got) != 0 {
			t.Errorf("ListGrants at %v, entry expiring %v = %v, want none", now, expires, got)
		}
	}
}

func testGrantRegistryRecordReplacesByKey(t *testing.T, factory func() GrantRegistry) {
	registry := factory()
	expires := time.Now().Add(time.Hour)
	recordGrantEntry(t, registry, NewGrantEntry{Key: "g1", SubjectKey: "s1", ClientID: "client-1", Record: contractPayload, ExpiresAt: expires})
	replacement := json.RawMessage(`{"v":2}`)
	recordGrantEntry(t, registry, NewGrantEntry{Key: "g1", SubjectKey: "s1", ClientID: "client-1", Record: replacement, ExpiresAt: expires})
	entries, err := registry.ListGrants(context.Background(), GrantListing{SubjectKey: "s1", Now: time.Now()})
	if err != nil {
		t.Fatalf("ListGrants: %v", err)
	}
	if len(entries) != 1 || !jsonEquivalent(entries[0].Record, replacement) {
		t.Fatalf("ListGrants after replacing g1 = %d entries, want the one replacement", len(entries))
	}
}

func testGrantRegistryDelete(t *testing.T, factory func() GrantRegistry) {
	registry := factory()
	ctx := context.Background()
	expires := time.Now().Add(time.Hour)
	recordGrantEntry(t, registry, NewGrantEntry{Key: "g1", SubjectKey: "s1", ClientID: "client-1", Record: contractPayload, ExpiresAt: expires})
	recordGrantEntry(t, registry, NewGrantEntry{Key: "g2", SubjectKey: "s1", ClientID: "client-1", Record: contractPayload, ExpiresAt: expires})
	if err := registry.DeleteGrant(ctx, "g1"); err != nil {
		t.Fatalf("DeleteGrant(g1): %v", err)
	}
	if got := listGrantKeys(t, registry, "s1", time.Now()); !slices.Equal(got, []string{"g2"}) {
		t.Errorf("ListGrants after deleting g1 = %v, want [g2]", got)
	}
	if err := registry.DeleteGrant(ctx, "g1"); err != nil {
		t.Errorf("DeleteGrant(already deleted) = %v, want nil", err)
	}
}

// testGrantRegistryListByKey covers GrantListing.Key: the entry with
// that key is listed while it's the subject's and unexpired, and never
// another subject's entry. A store may list the subject's other entries
// too, so only their absence from another subject's listing is checked.
func testGrantRegistryListByKey(t *testing.T, factory func() GrantRegistry) {
	registry := factory()
	expires := time.Now().Add(time.Hour)
	recordGrantEntry(t, registry, NewGrantEntry{Key: "g1", SubjectKey: "s1", ClientID: "client-1", Record: contractPayload, ExpiresAt: expires})
	recordGrantEntry(t, registry, NewGrantEntry{Key: "g2", SubjectKey: "s1", ClientID: "client-2", Record: contractPayload, ExpiresAt: expires})
	recordGrantEntry(t, registry, NewGrantEntry{Key: "g3", SubjectKey: "s2", ClientID: "client-1", Record: contractPayload, ExpiresAt: expires})
	keyed := func(subjectKey, key string, now time.Time) []string {
		t.Helper()
		entries, err := registry.ListGrants(context.Background(), GrantListing{SubjectKey: subjectKey, Now: now, Key: key})
		if err != nil {
			t.Fatalf("ListGrants(%q, key %q): %v", subjectKey, key, err)
		}
		keys := make([]string, 0, len(entries))
		for _, e := range entries {
			keys = append(keys, e.Key)
		}
		return keys
	}
	if got := keyed("s1", "g1", time.Now()); !slices.Contains(got, "g1") || slices.Contains(got, "g3") {
		t.Errorf("ListGrants(s1, key g1) = %v, want g1 and nothing of s2's", got)
	}
	if got := keyed("s2", "g1", time.Now()); slices.Contains(got, "g1") {
		t.Errorf("ListGrants(s2, key g1) = %v, want no entry of s1's", got)
	}
	if got := keyed("s1", "g1", expires); slices.Contains(got, "g1") {
		t.Errorf("ListGrants(s1, key g1) at expiry = %v, want g1 not listed", got)
	}
	if err := registry.DeleteGrant(context.Background(), "g1"); err != nil {
		t.Fatalf("DeleteGrant(g1): %v", err)
	}
	if got := keyed("s1", "g1", time.Now()); slices.Contains(got, "g1") {
		t.Errorf("ListGrants(s1, key g1) after deleting it = %v, want g1 not listed", got)
	}
}

// TestBackchannelInboxContract exercises factory()'s behavior against
// the guarantees BackchannelInbox's documentation promises: entries
// round-trip unmodified, are listed only for their own subject and only
// until they expire, are replaced by handle hash, and are removed by it;
// and, on one instance, an add shows at once. For that, concurrent
// callers each add an entry of their own, remove an entry added
// beforehand and list, so adds race removals as well as one another: no
// add may be lost, and each listing must include every entry whose add
// had returned before it began.
// factory must return a fresh, empty BackchannelInbox each call.
func TestBackchannelInboxContract(t *testing.T, factory func() BackchannelInbox) {
	t.Helper()

	t.Run("AddAndList", func(t *testing.T) { testBackchannelInboxAddAndList(t, factory) })
	t.Run("ListOnlyTheSubjects", func(t *testing.T) { testBackchannelInboxListOnlyTheSubjects(t, factory) })
	t.Run("ListOnlyUnexpired", func(t *testing.T) { testBackchannelInboxListOnlyUnexpired(t, factory) })
	t.Run("AddReplacesByHandle", func(t *testing.T) { testBackchannelInboxAddReplacesByHandle(t, factory) })
	t.Run("Remove", func(t *testing.T) { testBackchannelInboxRemove(t, factory) })
	t.Run("ConcurrentAddsAreAllListed", func(t *testing.T) { testBackchannelInboxConcurrentAddsAreAllListed(t, factory) })
}

func inboxHash(name string) [32]byte { return sha256.Sum256([]byte(name)) }

func addInboxEntry(t *testing.T, inbox BackchannelInbox, entry NewBackchannelInboxEntry) {
	t.Helper()
	if err := inbox.AddBackchannelRequest(context.Background(), entry); err != nil {
		t.Fatalf("AddBackchannelRequest: %v", err)
	}
}

func listInboxHashes(t *testing.T, inbox BackchannelInbox, subjectKey string, now time.Time) [][32]byte {
	t.Helper()
	entries, err := inbox.ListBackchannelRequests(context.Background(), BackchannelInboxListing{SubjectKey: subjectKey, Now: now})
	if err != nil {
		t.Fatalf("ListBackchannelRequests(%q): %v", subjectKey, err)
	}
	hashes := make([][32]byte, 0, len(entries))
	for _, e := range entries {
		hashes = append(hashes, e.HandleHash)
	}
	slices.SortFunc(hashes, func(a, b [32]byte) int { return bytes.Compare(a[:], b[:]) })
	return hashes
}

func sortedHashes(names ...string) [][32]byte {
	hashes := make([][32]byte, 0, len(names))
	for _, n := range names {
		hashes = append(hashes, inboxHash(n))
	}
	slices.SortFunc(hashes, func(a, b [32]byte) int { return bytes.Compare(a[:], b[:]) })
	return hashes
}

func testBackchannelInboxAddAndList(t *testing.T, factory func() BackchannelInbox) {
	inbox := factory()
	expires := time.Now().Add(time.Hour).Truncate(time.Millisecond)
	addInboxEntry(t, inbox, NewBackchannelInboxEntry{HandleHash: inboxHash("h1"), SubjectKey: "s1", ClientID: "client-1", Record: contractPayload, ExpiresAt: expires})
	entries, err := inbox.ListBackchannelRequests(context.Background(), BackchannelInboxListing{SubjectKey: "s1", Now: time.Now()})
	if err != nil {
		t.Fatalf("ListBackchannelRequests: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("ListBackchannelRequests = %d entries, want 1", len(entries))
	}
	got := entries[0]
	if got.HandleHash != inboxHash("h1") || got.ClientID != "client-1" || !got.ExpiresAt.Equal(expires) {
		t.Errorf("entry = %x %q %v, want h1 client-1 %v", got.HandleHash, got.ClientID, got.ExpiresAt, expires)
	}
	if !jsonEquivalent(got.Record, contractPayload) {
		t.Errorf("Record = %s, want %s", got.Record, contractPayload)
	}
}

func testBackchannelInboxListOnlyTheSubjects(t *testing.T, factory func() BackchannelInbox) {
	inbox := factory()
	expires := time.Now().Add(time.Hour)
	addInboxEntry(t, inbox, NewBackchannelInboxEntry{HandleHash: inboxHash("h1"), SubjectKey: "s1", ClientID: "client-1", Record: contractPayload, ExpiresAt: expires})
	addInboxEntry(t, inbox, NewBackchannelInboxEntry{HandleHash: inboxHash("h2"), SubjectKey: "s1", ClientID: "client-2", Record: contractPayload, ExpiresAt: expires})
	addInboxEntry(t, inbox, NewBackchannelInboxEntry{HandleHash: inboxHash("h3"), SubjectKey: "s2", ClientID: "client-1", Record: contractPayload, ExpiresAt: expires})
	if got, want := listInboxHashes(t, inbox, "s1", time.Now()), sortedHashes("h1", "h2"); !slices.Equal(got, want) {
		t.Errorf("ListBackchannelRequests(s1) = %x, want h1 and h2", got)
	}
	if got := listInboxHashes(t, inbox, "s3", time.Now()); len(got) != 0 {
		t.Errorf("ListBackchannelRequests(unknown subject) = %x, want none", got)
	}
}

func testBackchannelInboxListOnlyUnexpired(t *testing.T, factory func() BackchannelInbox) {
	inbox := factory()
	expires := time.Now().Add(time.Hour)
	addInboxEntry(t, inbox, NewBackchannelInboxEntry{HandleHash: inboxHash("h1"), SubjectKey: "s1", ClientID: "client-1", Record: contractPayload, ExpiresAt: expires})
	for _, now := range []time.Time{expires, expires.Add(time.Second)} {
		if got := listInboxHashes(t, inbox, "s1", now); len(got) != 0 {
			t.Errorf("ListBackchannelRequests at %v, entry expiring %v = %x, want none", now, expires, got)
		}
	}
}

func testBackchannelInboxAddReplacesByHandle(t *testing.T, factory func() BackchannelInbox) {
	inbox := factory()
	expires := time.Now().Add(time.Hour)
	addInboxEntry(t, inbox, NewBackchannelInboxEntry{HandleHash: inboxHash("h1"), SubjectKey: "s1", ClientID: "client-1", Record: contractPayload, ExpiresAt: expires})
	replacement := json.RawMessage(`{"v":2}`)
	addInboxEntry(t, inbox, NewBackchannelInboxEntry{HandleHash: inboxHash("h1"), SubjectKey: "s1", ClientID: "client-1", Record: replacement, ExpiresAt: expires})
	entries, err := inbox.ListBackchannelRequests(context.Background(), BackchannelInboxListing{SubjectKey: "s1", Now: time.Now()})
	if err != nil {
		t.Fatalf("ListBackchannelRequests: %v", err)
	}
	if len(entries) != 1 || !jsonEquivalent(entries[0].Record, replacement) {
		t.Fatalf("ListBackchannelRequests after replacing h1 = %d entries, want the one replacement", len(entries))
	}
}

func testBackchannelInboxRemove(t *testing.T, factory func() BackchannelInbox) {
	inbox := factory()
	ctx := context.Background()
	expires := time.Now().Add(time.Hour)
	addInboxEntry(t, inbox, NewBackchannelInboxEntry{HandleHash: inboxHash("h1"), SubjectKey: "s1", ClientID: "client-1", Record: contractPayload, ExpiresAt: expires})
	addInboxEntry(t, inbox, NewBackchannelInboxEntry{HandleHash: inboxHash("h2"), SubjectKey: "s1", ClientID: "client-1", Record: contractPayload, ExpiresAt: expires})
	if err := inbox.RemoveBackchannelRequest(ctx, inboxHash("h1")); err != nil {
		t.Fatalf("RemoveBackchannelRequest(h1): %v", err)
	}
	if got, want := listInboxHashes(t, inbox, "s1", time.Now()), sortedHashes("h2"); !slices.Equal(got, want) {
		t.Errorf("ListBackchannelRequests after removing h1 = %x, want h2", got)
	}
	if err := inbox.RemoveBackchannelRequest(ctx, inboxHash("h1")); err != nil {
		t.Errorf("RemoveBackchannelRequest(already removed) = %v, want nil", err)
	}
}

// contractInboxConcurrentAdds is how many concurrent callers
// testBackchannelInboxConcurrentAddsAreAllListed has add an entry for
// one subject: more than twice server.Limits' default cap of 32 pending
// requests, so an inbox that cuts a listing off at 32 entries, or at 64,
// fails it too.
const contractInboxConcurrentAdds = 65

// testBackchannelInboxConcurrentAddsAreAllListed checks, on one
// instance, that an add shows at once and that none is lost to another
// add or to a removal. It first adds, for one subject, an entry for each
// of its concurrent callers to remove. Each caller then adds an entry of
// its own, from one of a few clients, removes the one added for it, and
// lists the subject, so adds race removals as well as one another. Each
// listing must include every entry, with its ClientID, whose add had
// returned before the listing began, the caller's own among them, and
// once every add has returned, a listing must include all of them.
// Neither check needs a removal to have shown. A caller removes after
// its add rather than before it, so the removals don't spread the adds
// out: fewer of them would race, and an inbox that loses concurrent adds
// would pass more often.
func testBackchannelInboxConcurrentAddsAreAllListed(t *testing.T, factory func() BackchannelInbox) {
	inbox := factory()
	expires := time.Now().Add(time.Hour)
	names := make([]string, contractInboxConcurrentAdds)
	entries := make([]NewBackchannelInboxEntry, len(names))
	for i := range names {
		names[i] = fmt.Sprintf("h%d", i)
		entries[i] = NewBackchannelInboxEntry{HandleHash: inboxHash(names[i]), SubjectKey: "s1", ClientID: fapi.ClientID(fmt.Sprintf("client-%d", i%3)), Record: contractPayload, ExpiresAt: expires}
		addInboxEntry(t, inbox, NewBackchannelInboxEntry{HandleHash: inboxHash("r" + names[i]), SubjectKey: "s1", ClientID: "client-r", Record: contractPayload, ExpiresAt: expires})
	}
	var mu sync.Mutex
	next := 0
	added := make(map[[32]byte]fapi.ClientID, len(entries))
	complete := runConcurrently(len(entries), func() bool {
		mu.Lock()
		i := next
		next++
		mu.Unlock()
		return addRemoveAndListInboxEntries(t, inbox, entries[i], inboxHash("r"+names[i]), &mu, added)
	})
	if complete != len(entries) {
		t.Errorf("%d of %d concurrent callers' listings included every entry, with its ClientID, whose add had returned before the listing began, the caller's own among them; want all", complete, len(entries))
	}
	listed := listInboxHashes(t, inbox, "s1", time.Now())
	missing := 0
	for _, name := range names {
		if _, found := slices.BinarySearchFunc(listed, inboxHash(name), func(a, b [32]byte) int { return bytes.Compare(a[:], b[:]) }); !found {
			missing++
		}
	}
	if missing != 0 {
		t.Errorf("ListBackchannelRequests once every add had returned is missing %d of the %d entries added", missing, len(names))
	}
}

// addRemoveAndListInboxEntries adds entry to inbox and records it in
// added, by HandleHash with its ClientID, under mu. It then removes the
// entry whose HandleHash is remove, lists entry's subject, and reports
// whether the listing includes, with its ClientID, every entry that
// added held just before the listing began: each one an entry whose add
// had returned by then, entry itself among them. It reports a failed
// call with t.Errorf rather than t.Fatalf, so a goroutine other than the
// test's can call it.
func addRemoveAndListInboxEntries(t *testing.T, inbox BackchannelInbox, entry NewBackchannelInboxEntry, remove [32]byte, mu *sync.Mutex, added map[[32]byte]fapi.ClientID) bool {
	t.Helper()
	ctx := context.Background()
	if err := inbox.AddBackchannelRequest(ctx, entry); err != nil {
		t.Errorf("AddBackchannelRequest: %v", err)
		return false
	}
	mu.Lock()
	added[entry.HandleHash] = entry.ClientID
	mu.Unlock()
	if err := inbox.RemoveBackchannelRequest(ctx, remove); err != nil {
		t.Errorf("RemoveBackchannelRequest: %v", err)
	}
	mu.Lock()
	want := maps.Clone(added)
	mu.Unlock()
	listed, err := inbox.ListBackchannelRequests(ctx, BackchannelInboxListing{SubjectKey: entry.SubjectKey, Now: time.Now()})
	if err != nil {
		t.Errorf("ListBackchannelRequests(%q): %v", entry.SubjectKey, err)
		return false
	}
	for _, e := range listed {
		if clientID, ok := want[e.HandleHash]; ok && clientID == e.ClientID {
			delete(want, e.HandleHash)
		}
	}
	return len(want) == 0
}

// TestPairwiseSubjectEraserContract exercises factory()'s ForgetSubject
// against the guarantees PairwiseSubjectEraser's documentation promises:
// a forgotten user's bodies stop resolving in every sector, stay retired
// for everyone, and a later GetOrCreate for them stores a new body,
// while other users and issuers keep theirs. factory must return a
// fresh, empty store each call.
func TestPairwiseSubjectEraserContract(t *testing.T, factory func() PairwiseSubjectEraser) {
	t.Helper()
	t.Run("ForgetSubjectStopsEveryBodyResolving", func(t *testing.T) { testPairwiseEraserForgets(t, factory) })
	t.Run("ForgottenBodiesStayRetired", func(t *testing.T) { testPairwiseEraserRetires(t, factory) })
	t.Run("ForgetSubjectLeavesOthers", func(t *testing.T) { testPairwiseEraserLeavesOthers(t, factory) })
}

const contractOtherPairwiseIssuer = "https://other-as.example"

// eraserGetOrCreate checks GetOrCreate(issuer, sector, subject, body)
// returns want, or an error wrapping wantErr when it's set.
func eraserGetOrCreate(t *testing.T, store PairwiseSubjectEraser, issuer, sector, subject, body, want string, wantErr error) {
	t.Helper()
	got, err := store.GetOrCreate(context.Background(), PairwiseSubjectKey{Issuer: issuer, Sector: sector, Subject: subject}, body)
	if (wantErr == nil && (err != nil || got != want)) || (wantErr != nil && !errors.Is(err, wantErr)) {
		t.Fatalf("GetOrCreate(%s, %s, %s, %s) = %q, %v, want %q, %v", issuer, sector, subject, body, got, err, want, wantErr)
	}
}

// eraserLookup checks Lookup(issuer, sector, body) finds want, or none
// when want is empty.
func eraserLookup(t *testing.T, store PairwiseSubjectEraser, issuer, sector, body, want string) {
	t.Helper()
	got, err := store.Lookup(context.Background(), issuer, sector, body)
	if (want == "" && !errors.Is(err, ErrPairwiseSubjectNotFound)) || (want != "" && (err != nil || got != want)) {
		t.Fatalf("Lookup(%s, %s, %s) = %q, %v, want %q", issuer, sector, body, got, err, want)
	}
}

// eraserForget checks ForgetSubject(issuer, subject) forgets want
// mappings.
func eraserForget(t *testing.T, store PairwiseSubjectEraser, issuer, subject string, want int) {
	t.Helper()
	if n, err := store.ForgetSubject(context.Background(), issuer, subject); err != nil || n != want {
		t.Fatalf("ForgetSubject(%s, %s) = %d, %v, want %d", issuer, subject, n, err, want)
	}
}

func testPairwiseEraserForgets(t *testing.T, factory func() PairwiseSubjectEraser) {
	store := factory()
	eraserGetOrCreate(t, store, contractPairwiseIssuer, "sector-a", "user-1", "body-a", "body-a", nil)
	eraserGetOrCreate(t, store, contractPairwiseIssuer, "sector-b", "user-1", "body-b", "body-b", nil)
	eraserForget(t, store, contractPairwiseIssuer, "user-1", 2)
	eraserLookup(t, store, contractPairwiseIssuer, "sector-a", "body-a", "")
	eraserLookup(t, store, contractPairwiseIssuer, "sector-b", "body-b", "")
	// The user seen again gets a new identifier, as one never seen would.
	eraserGetOrCreate(t, store, contractPairwiseIssuer, "sector-a", "user-1", "body-a2", "body-a2", nil)
	eraserForget(t, store, contractPairwiseIssuer, "nobody", 0)
}

func testPairwiseEraserRetires(t *testing.T, factory func() PairwiseSubjectEraser) {
	store := factory()
	eraserGetOrCreate(t, store, contractPairwiseIssuer, "sector-a", "user-1", "body-a", "body-a", nil)
	eraserForget(t, store, contractPairwiseIssuer, "user-1", 1)
	eraserGetOrCreate(t, store, contractPairwiseIssuer, "sector-a", "user-2", "body-a", "", ErrPairwiseSubjectCollision)
	eraserGetOrCreate(t, store, contractPairwiseIssuer, "sector-a", "user-1", "body-a", "", ErrPairwiseSubjectCollision)
}

func testPairwiseEraserLeavesOthers(t *testing.T, factory func() PairwiseSubjectEraser) {
	store := factory()
	eraserGetOrCreate(t, store, contractPairwiseIssuer, "sector-a", "user-1", "body-1", "body-1", nil)
	eraserGetOrCreate(t, store, contractPairwiseIssuer, "sector-a", "user-2", "body-2", "body-2", nil)
	eraserGetOrCreate(t, store, contractOtherPairwiseIssuer, "sector-a", "user-1", "body-1", "body-1", nil)
	eraserForget(t, store, contractPairwiseIssuer, "user-1", 1)
	eraserLookup(t, store, contractPairwiseIssuer, "sector-a", "body-2", "user-2")
	eraserLookup(t, store, contractOtherPairwiseIssuer, "sector-a", "body-1", "user-1")
}
