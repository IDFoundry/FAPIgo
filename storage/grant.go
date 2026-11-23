package storage

import (
	"context"
	"encoding/json"
	"time"

	fapi "github.com/idfoundry/fapigo"
)

// IssuedTokensRecorder is an optional interface a GrantStore may
// implement to record both tokens a code exchange issues in one write.
// When the authorization includes "offline_access" and the server's
// Dependencies.Revocation can be read (it has IsRevoked, so each token
// carries the code's grant ID), the server issues the refresh token and
// then the access token, and calls RecordIssuedTokens once with both, in
// place of RecordIssuedAccessToken followed later by
// RecordIssuedRefreshToken. Otherwise — without "offline_access", with a
// revocation store the server can only write to, or for a store without
// it — it makes those two calls as before (the second only with a
// refresh token).
//
// RecordIssuedTokens must have exactly the effect of
// RecordIssuedAccessToken(ctx, codeHash, accessTokenKey,
// accessExpiresAt) and RecordIssuedRefreshToken(ctx, codeHash,
// refreshTokenHash, refreshExpiresAt) together, atomically: a
// RedeemAuthorizationCode reusing codeHash reports both recorded tokens
// in its AuthorizationCodeAlreadyRedeemedError, or neither, never only
// one. Like those two, a failure is tolerated (the server discards it),
// at the cost of a reused code's tokens staying usable.
// TestGrantStoreContract checks a store that implements it against the
// two-call form.
//
// The server finds RecordIssuedTokens by type assertion, and then
// doesn't call RecordIssuedAccessToken or RecordIssuedRefreshToken for
// that exchange. A wrapper that embeds a store implementing it inherits
// RecordIssuedTokens through Go's method promotion, so a wrapper
// overriding RecordIssuedAccessToken or RecordIssuedRefreshToken is
// bypassed: the server records through the inner store, skipping the
// wrapper's own recording, and a reuse of the code depends on what the
// inner store kept. A wrapper that overrides either method must also
// override RecordIssuedTokens, or hold the inner store in a field of
// the plain GrantStore type, so nothing is promoted.
// TestGrantStoreContract run against the wrapper catches the mismatch
// whenever it changes what a reuse of the code reports.
type IssuedTokensRecorder interface {
	RecordIssuedTokens(ctx context.Context, codeHash [32]byte, accessTokenKey string, accessExpiresAt time.Time, refreshTokenHash [32]byte, refreshExpiresAt time.Time) error
}

// GrantRefreshTokenRevoker is an optional interface a GrantStore may
// implement to revoke every refresh token issued from a grant at once.
// server.Server.RevokeGrant, and the reuse of an authorization code,
// record the grant as revoked, then, with a store that implements it,
// revoke the grant's refresh tokens too. Without it those stay stored,
// refused only while the grant's revocation record lasts (at least 400
// days): a refresh token lifetime longer than that, applying after the
// revocation, can make one redeemable again.
//
// CreateRefreshToken indexes a token by each of its
// NewRefreshToken.GrantKeys. RevokeGrantRefreshTokens revokes every
// token indexed by grantKey, as RevokeRefreshToken revokes one, so
// RedeemRefreshToken fails for each from then on, and returns their
// hashes, in any order, for the server to remove from its
// GrantRegistry. It may leave out, or report again, a token that was
// already revoked. It revokes the tokens indexed by grantKey when it's
// called: one created with grantKey afterwards is revoked by the next
// call. An unknown grantKey has no tokens, which isn't an error. An
// error means the tokens may not all have been revoked: RevokeGrant then
// fails, so the application can call it again to revoke the rest. A
// store that fails part way returns, with its error, the hashes of the
// tokens it did revoke, since a later call may leave those out. A SQL
// store can keep the keys in indexed columns, or a table of grant key
// and token hash rows, and revoke the tokens with one DELETE ...
// RETURNING, which revokes all of them or, failing, none.
// TestGrantStoreContract checks a store that implements it.
//
// The server finds RevokeGrantRefreshTokens by type assertion. A wrapper
// that embeds a store implementing it inherits the method through Go's
// method promotion, so a wrapper overriding CreateRefreshToken,
// RedeemRefreshToken or RevokeRefreshToken is bypassed: a token it keeps
// or serves apart from the inner store isn't revoked, and its own
// RevokeRefreshToken doesn't run. That never makes a revoked grant's
// token redeemable — the server checks the grant's revocation on every
// redemption, whatever this method did — but it leaves the token to that
// record alone. A wrapper that overrides any of those methods must also
// override RevokeGrantRefreshTokens, or hold the inner store in a field
// of the plain GrantStore type, so nothing is promoted.
// TestGrantStoreContract run against the wrapper catches the mismatch
// whenever a token the call should have revoked can still be redeemed
// through the wrapper.
type GrantRefreshTokenRevoker interface {
	RevokeGrantRefreshTokens(ctx context.Context, grantKey string) ([][32]byte, error)
}

// AuthorizationCodeAlreadyRedeemedError is what RedeemAuthorizationCode
// must return (satisfying errors.As) when CodeHash was already
// consumed — as opposed to any other failure (e.g. an unknown code),
// which returns a plain error. RFC 6749 §4.1.2: "If an authorization
// code is used more than once, the authorization server MUST deny the
// request and SHOULD revoke (when possible) all tokens previously issued
// based on that authorization code" — "all tokens," so this carries
// both halves back to the caller, whichever were actually issued and
// recorded.
type AuthorizationCodeAlreadyRedeemedError struct {
	// IssuedAccessTokenKey is the revocation-lookup key of the access
	// token issued on the original (first) redemption (a JWT's jti
	// claim, or an opaque token's own hash — see
	// server.AccessTokenIssuer.IssueAccessToken) — "" if
	// RecordIssuedAccessToken was never called for this code (e.g. no
	// revocation support wired in).
	IssuedAccessTokenKey string

	// IssuedRefreshTokenHash is the hash of the refresh token issued on
	// the original redemption, if one was (the authorization included
	// "offline_access") and RecordIssuedRefreshToken was called for it
	// — nil otherwise.
	IssuedRefreshTokenHash *[32]byte

	// ClientID is the client the code was issued to
	// (NewAuthorizationCode.ClientID). The server revokes the original
	// redemption's tokens only when the client presenting the code again
	// is that client: a different client holding a leaked code must not
	// be able to revoke another client's tokens. Set it; a store that
	// leaves it empty gets the old behaviour, revoking whoever presents
	// the code.
	ClientID fapi.ClientID
}

func (e *AuthorizationCodeAlreadyRedeemedError) Error() string {
	return "storage: authorization code already redeemed"
}

// NewAuthorizationCode is what CreateAuthorizationCode persists for one
// issued authorization code. CodeHash is a SHA-256 digest of the raw
// code value, domain-separated so it never equals a refresh token's
// digest (NewRefreshToken.TokenHash) of the same value — matching
// ReplayStore's digest-only philosophy — never the code itself; the raw value exists only long enough to be hashed
// here and returned to the client in the redirect response. The digest
// also covers the code's PKCE challenge, its redirect URI and the DPoP
// key it is bound to, if any, and, for a code issued to a client
// authenticated by Client Attestation, the client instance it was
// issued to, so a token request presenting the code with another
// code_verifier, redirect_uri or DPoP key, or from another instance of
// the same client, finds none. A store just keys the record by it
// either way. The server may look for a code under two digests, with
// the presented DPoP key and without, since it can't tell which the
// code is bound to: a CodeHash the store doesn't know is only an error
// (see RedeemAuthorizationCode), changing nothing.
type NewAuthorizationCode struct {
	CodeHash [32]byte

	ClientID fapi.ClientID

	// Grant is the authorization this code grants — opaque to the store
	// (see the package doc). RedeemAuthorizationCode must return it
	// unmodified.
	Grant json.RawMessage

	ExpiresAt time.Time
}

// AuthorizationCodeRedemption is the input to
// GrantStore.RedeemAuthorizationCode.
type AuthorizationCodeRedemption struct {
	// CodeHash is the digest of the presented code value — computed the
	// same way as the one CreateAuthorizationCode stored it under (see
	// NewAuthorizationCode).
	CodeHash [32]byte

	// ClientID is the authenticated client presenting the code. When it
	// is set, a store must refuse a not-yet-redeemed code that was
	// issued to another client (NewAuthorizationCode.ClientID) with an
	// error, without consuming the code or otherwise changing it, so a
	// client holding a leaked code can't spend another client's
	// authorization. A code that was already redeemed is still reported
	// with *AuthorizationCodeAlreadyRedeemedError whoever presents it:
	// its ClientID tells the server whether to revoke. Empty means no
	// such check, as before. A store that ignores it stays safe: the
	// server refuses another client's code after redemption anyway, but
	// by then the code has been spent.
	ClientID fapi.ClientID
}

// RedeemedAuthorizationCode is what RedeemAuthorizationCode returns for
// a successfully redeemed code.
type RedeemedAuthorizationCode struct {
	ClientID  fapi.ClientID
	Grant     json.RawMessage
	ExpiresAt time.Time
}

// NewRefreshToken is what CreateRefreshToken persists for one issued
// refresh token. TokenHash is the SHA-256 digest of the raw token value,
// never the value itself — the same digest-only discipline as
// NewAuthorizationCode.CodeHash.
type NewRefreshToken struct {
	TokenHash [32]byte

	ClientID fapi.ClientID

	// Grant is the authorization this refresh token carries forward —
	// opaque to the store, like NewAuthorizationCode.Grant.
	// RedeemRefreshToken must return it unmodified.
	Grant json.RawMessage

	ExpiresAt time.Time

	// GrantKeys name the grants the token was issued from, for a
	// GrantRefreshTokenRevoker to index it by: one for the application's
	// grant ID (server.GrantedAuthorization.GrantID), one for the
	// authorization code or CIBA request the grant came from, both, or
	// neither — at most two today. Each is a digest the server derives
	// from its issuer and the grant's ID (base64url, at most 64 bytes),
	// never the ID itself. A store that doesn't implement
	// GrantRefreshTokenRevoker ignores them.
	GrantKeys []string
}

// RefreshTokenRedemption is the input to GrantStore.RedeemRefreshToken.
type RefreshTokenRedemption struct {
	// TokenHash is the SHA-256 digest of the presented refresh token
	// value — the same digest CreateRefreshToken stored it under.
	TokenHash [32]byte
}

// RedeemedRefreshToken is what RedeemRefreshToken returns for a
// successfully redeemed token.
type RedeemedRefreshToken struct {
	ClientID  fapi.ClientID
	Grant     json.RawMessage
	ExpiresAt time.Time
}

// GrantStore persists issued authorization codes and refresh tokens.
//
// The two are separate kinds of record: RedeemRefreshToken returns only
// a refresh token, and RedeemAuthorizationCode only an authorization
// code, whatever digest each is given. A store keeping both in one
// table keyed by digest must also key or filter by kind. The server
// never stores both under one digest, and each record's opaque Grant
// says which kind it is, so a record of the wrong kind is refused
// rather than redeemed; TestGrantStoreContract still checks that a
// store keeps them apart.
type GrantStore interface {
	// CreateAuthorizationCode persists code under its CodeHash until at
	// least its ExpiresAt, unredeemed. An error fails the authorization
	// it was issued for.
	CreateAuthorizationCode(ctx context.Context, code NewAuthorizationCode) error

	// RedeemAuthorizationCode atomically retrieves and consumes the
	// authorization code identified by CodeHash — a second call with the
	// same CodeHash must fail. It returns an error if CodeHash is
	// unknown or already consumed; the caller checks the returned
	// record's own expiry (ExpiresAt) itself, the same way
	// BeginAuthorization and CompleteAuthorization do. On a repeat call
	// specifically (as opposed to an unknown code), the returned error
	// must satisfy errors.As into *AuthorizationCodeAlreadyRedeemedError
	// — see its own doc comment. A code issued to a client other than a
	// non-empty AuthorizationCodeRedemption.ClientID is refused without
	// being consumed — see that field's doc comment.
	RedeemAuthorizationCode(ctx context.Context, redemption AuthorizationCodeRedemption) (RedeemedAuthorizationCode, error)

	// RecordIssuedAccessToken associates the access token's
	// revocation-lookup key (see AuthorizationCodeAlreadyRedeemedError.
	// IssuedAccessTokenKey) issued when codeHash was (successfully)
	// redeemed, purely so a later reuse of the same code can report
	// which token was issued the first time (RFC 6749 §4.1.2). Called
	// once, right after a successful redemption issues its access
	// token. A no-op implementation (return nil, remember nothing) is
	// tolerated: RedeemAuthorizationCode's reuse error then always
	// carries an empty IssuedAccessTokenKey, the reused code is still
	// refused, but the tokens its first redemption issued can't be
	// revoked (RFC 6749 §4.1.2 says they should be).
	RecordIssuedAccessToken(ctx context.Context, codeHash [32]byte, key string, expiresAt time.Time) error

	// RecordIssuedRefreshToken is RecordIssuedAccessToken's counterpart
	// for the refresh token issued alongside it, when one is (the
	// authorization included "offline_access"). Same contract: a no-op
	// is tolerated, at the cost of a reused code's refresh token
	// staying usable.
	RecordIssuedRefreshToken(ctx context.Context, codeHash, refreshTokenHash [32]byte, expiresAt time.Time) error

	// CreateRefreshToken persists token under its TokenHash until at
	// least its ExpiresAt. An error fails the token request that issued
	// it. For the first token stored under a hash RevokeRefreshToken
	// revoked less than an hour before, it must instead either fail or
	// store the token so that RedeemRefreshToken refuses it: see
	// RevokeRefreshToken.
	CreateRefreshToken(ctx context.Context, token NewRefreshToken) error

	// RedeemRefreshToken retrieves the refresh token identified by
	// TokenHash. Unlike RedeemAuthorizationCode, this is deliberately
	// NOT single-use: FAPI2-SP-FINAL requirement 5.3.2.1-9 states an
	// authorization server "shall not use refresh token rotation except
	// in extraordinary circumstances", so RefreshAccessToken never
	// consumes or replaces the presented token — it stays valid for
	// repeated use until it expires (or is otherwise revoked). It
	// returns an error only if TokenHash is unknown or has been revoked,
	// after the token was stored or before (RFC 6749 doesn't need a
	// distinct error code for "revoked" vs "invalid"), though a
	// revocation made before the token was stored need only hold for
	// the hour RevokeRefreshToken requires; the caller checks the
	// returned record's own expiry (ExpiresAt) itself, the same way
	// BeginAuthorization and CompleteAuthorization do for their own
	// redemptions.
	RedeemRefreshToken(ctx context.Context, redemption RefreshTokenRedemption) (RedeemedRefreshToken, error)

	// RevokeRefreshToken marks the refresh token under tokenHash (the
	// hash CreateRefreshToken stores it under) as no longer redeemable: a
	// subsequent RedeemRefreshToken for tokenHash must fail, for a token
	// already stored and, as below, for one stored while or after it
	// runs. The server relies on it when the token's originating
	// authorization code is detected being reused (RFC 6749 §4.1.2's "all
	// tokens"), in Server.RevokeToken (RFC 7009), which reports the token
	// revoked once this returns nil, and when it revokes a grant through
	// its GrantRegistry. A no-op implementation is NOT valid — it would
	// let RevokeToken report a token revoked that still works.
	//
	// It returns nil for a hash no token is stored under — one not
	// stored yet, already revoked, or removed once it expired — as for
	// one revoked before: an error means only that the revocation
	// couldn't be recorded, which the server reports as a failure to
	// revoke. The server revokes such hashes in the normal course.
	// Server.RevokeToken revokes a token's grant first, which, for a
	// grant with a GrantID and a GrantRefreshTokenRevoker store, has
	// revoked the token by the time RevokeToken revokes it itself.
	// Server.RevokeListedGrant and RevokeSubjectGrants revoke a token
	// again once they have deleted its grant's registry entry, and,
	// before deleting the entries of grants revoked another way, revoke
	// those grants' tokens, which may be gone already. A reused code's
	// token, and one an issuance withdraws, may be revoked already too.
	// An error for any of these would make the server report a failure
	// for a token that is revoked: RevokeToken would answer server_error,
	// and RevokeListedGrant and RevokeSubjectGrants would fail on every
	// call, keeping the entry.
	//
	// A token revoked before it's stored must stay revoked. The server
	// stores each refresh token under a hash of its own, with one
	// CreateRefreshToken, but a revocation through the registry reads the
	// hash from the grant's entry, which the token's issuance records
	// before storing the token, so its RevokeRefreshToken can come first.
	// So once RevokeRefreshToken has returned nil, the token under
	// tokenHash must never be redeemable if its CreateRefreshToken
	// returns after RevokeRefreshToken was called — running concurrently
	// or afterwards — and within an hour of that call, by the store's
	// clock: CreateRefreshToken may fail, as sqlstore's does on the
	// tombstone its RevokeRefreshToken leaves, or store the token so that
	// RedeemRefreshToken refuses it, as memstore's does. This covers the
	// one CreateRefreshToken the server makes for a hash: a store needn't
	// refuse a token stored again under a hash whose stored token
	// RevokeRefreshToken found and removed. An hour outlasts any issuance
	// in flight: the server stores the token straight after recording its
	// entry. A store that only deleted a stored token would keep nothing
	// of a revocation that found none, and the token stored afterwards
	// would be live, and, once the revocation deletes the entry,
	// unlisted. The server checks again once it has stored the token,
	// and withdraws it if the grant's entry is gone or the grant is
	// revoked, but that's a second layer, resting on the GrantRegistry
	// and the revocation store, not a reason for a store to forget.
	// TestGrantStoreContract checks both requirements, with revocations
	// racing creations, but not how long a revocation lasts.
	RevokeRefreshToken(ctx context.Context, tokenHash [32]byte) error
}
