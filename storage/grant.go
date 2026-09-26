package storage

import (
	"context"
	"encoding/json"
	"time"

	fapi "github.com/idfoundry/fapigo"
)

// AuthorizationCodeAlreadyRedeemedError is what RedeemAuthorizationCode
// must return (satisfying errors.As) when CodeHash was already
// consumed — as opposed to any other failure (e.g. an unknown code),
// which returns a plain error. RFC 6749 §4.1.2: "If an authorization
// code is used more than once, the authorization server MUST deny the
// request and SHOULD revoke (if possible) all tokens previously issued
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
}

func (e *AuthorizationCodeAlreadyRedeemedError) Error() string {
	return "storage: authorization code already redeemed"
}

// NewAuthorizationCode is what CreateAuthorizationCode persists for one
// issued authorization code. CodeHash is the SHA-256 digest of the raw
// code value — matching ReplayStore's digest-only philosophy — never
// the code itself; the raw value exists only long enough to be hashed
// here and returned to the client in the redirect response.
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
	// CodeHash is the SHA-256 digest of the presented code value — the
	// same digest CreateAuthorizationCode stored it under.
	CodeHash [32]byte
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
type GrantStore interface {
	CreateAuthorizationCode(ctx context.Context, code NewAuthorizationCode) error

	// RedeemAuthorizationCode atomically retrieves and consumes the
	// authorization code identified by CodeHash — a second call with the
	// same CodeHash must fail. It returns an error if CodeHash is
	// unknown or already consumed; the caller checks the returned
	// record's own expiry (ExpiresAt) itself, the same way
	// BeginAuthorization and CompleteAuthorization do. On a repeat call
	// specifically (as opposed to an unknown code), the returned error
	// must satisfy errors.As into *AuthorizationCodeAlreadyRedeemedError
	// — see its own doc comment.
	RedeemAuthorizationCode(ctx context.Context, redemption AuthorizationCodeRedemption) (RedeemedAuthorizationCode, error)

	// RecordIssuedAccessToken associates the access token's
	// revocation-lookup key (see AuthorizationCodeAlreadyRedeemedError.
	// IssuedAccessTokenKey) issued when codeHash was (successfully)
	// redeemed, purely so a later reuse of the same code can report
	// which token was issued the first time (RFC 6749 §4.1.2). Called
	// once, right after a successful redemption issues its access
	// token. A no-op implementation (return nil, remember nothing) is
	// entirely valid for a deployment that doesn't support revocation
	// — costs nothing to implement, and RedeemAuthorizationCode's
	// reuse error just always carries an empty IssuedAccessTokenKey in
	// that case.
	RecordIssuedAccessToken(ctx context.Context, codeHash [32]byte, key string, expiresAt time.Time) error

	// RecordIssuedRefreshToken is RecordIssuedAccessToken's counterpart
	// for the refresh token issued alongside it, when one is (the
	// authorization included "offline_access"). Same no-op-able
	// contract.
	RecordIssuedRefreshToken(ctx context.Context, codeHash [32]byte, refreshTokenHash [32]byte, expiresAt time.Time) error

	CreateRefreshToken(ctx context.Context, token NewRefreshToken) error

	// RedeemRefreshToken retrieves the refresh token identified by
	// TokenHash. Unlike RedeemAuthorizationCode, this is deliberately
	// NOT single-use: FAPI2-SP-FINAL requirement 5.3.2.1-9 states an
	// authorization server "shall not use refresh token rotation except
	// in extraordinary circumstances", so RefreshAccessToken never
	// consumes or replaces the presented token — it stays valid for
	// repeated use until it expires (or is otherwise revoked). It
	// returns an error only if TokenHash is unknown or has been
	// revoked (see RevokeRefreshToken — RFC 6749 doesn't need a
	// distinct error code for "revoked" vs "invalid"); the caller
	// checks the returned record's own expiry (ExpiresAt) itself, the
	// same way BeginAuthorization and CompleteAuthorization do for
	// their own redemptions.
	RedeemRefreshToken(ctx context.Context, redemption RefreshTokenRedemption) (RedeemedRefreshToken, error)

	// RevokeRefreshToken marks a previously-created refresh token (by
	// the same hash CreateRefreshToken stored it under) as no longer
	// redeemable — used when its originating authorization code is
	// detected being reused (RFC 6749 §4.1.2's "all tokens"). A
	// subsequent RedeemRefreshToken for tokenHash must fail. A no-op
	// implementation is valid for a deployment that doesn't support
	// revocation, the same as RecordIssuedAccessToken.
	RevokeRefreshToken(ctx context.Context, tokenHash [32]byte) error
}
