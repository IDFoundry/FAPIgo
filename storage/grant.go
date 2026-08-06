package storage

import (
	"context"
	"encoding/json"
	"time"

	fapi "github.com/osanderson/go-fapi"
)

// NewAuthorizationCode is what CreateAuthorizationCode persists for one
// issued authorization code. CodeHash is the SHA-256 digest of the raw
// code value — matching ReplayStore's digest-only philosophy — never
// the code itself; the raw value exists only long enough to be hashed
// here and returned to the client in the redirect response.
type NewAuthorizationCode struct {
	CodeHash [32]byte

	ClientID            fapi.ClientID
	RedirectURI         string
	CodeChallenge       string
	CodeChallengeMethod string

	Subject  string
	Scope    []string
	Nonce    string // "" if the authorization request carried none
	AuthTime time.Time
	ACR      string
	AMR      []string

	// TokenClaims are the validated extension parameter values
	// (extension.Definition.ReturnInTokenClaims) carried by the
	// authorization request this code grants — see
	// storage.NewPARRecord.TokenClaims. RedeemAuthorizationCode must
	// return them unmodified, so ExchangeAuthorizationCode can copy them
	// into the access and ID tokens it issues.
	TokenClaims map[string]json.RawMessage

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
	ClientID            fapi.ClientID
	RedirectURI         string
	CodeChallenge       string
	CodeChallengeMethod string

	Subject     string
	Scope       []string
	Nonce       string
	AuthTime    time.Time
	ACR         string
	AMR         []string
	TokenClaims map[string]json.RawMessage

	ExpiresAt time.Time
}

// NewRefreshToken is what CreateRefreshToken persists for one issued
// refresh token. TokenHash is the SHA-256 digest of the raw token value,
// never the value itself — the same digest-only discipline as
// NewAuthorizationCode.CodeHash. Thumbprint is the DPoP key thumbprint
// this token, and every access token minted from it, is bound to;
// RefreshAccessToken rejects a request whose DPoP proof doesn't match.
type NewRefreshToken struct {
	TokenHash [32]byte

	ClientID    fapi.ClientID
	Subject     string
	Scope       []string
	Thumbprint  string
	AuthTime    time.Time
	ACR         string
	AMR         []string
	TokenClaims map[string]json.RawMessage

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
	ClientID    fapi.ClientID
	Subject     string
	Scope       []string
	Thumbprint  string
	AuthTime    time.Time
	ACR         string
	AMR         []string
	TokenClaims map[string]json.RawMessage

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
	// BeginAuthorization and CompleteAuthorization do.
	RedeemAuthorizationCode(ctx context.Context, redemption AuthorizationCodeRedemption) (RedeemedAuthorizationCode, error)

	CreateRefreshToken(ctx context.Context, token NewRefreshToken) error

	// RedeemRefreshToken atomically retrieves and consumes the refresh
	// token identified by TokenHash — a second call with the same
	// TokenHash must fail. RefreshAccessToken always rotates: every
	// successful refresh consumes the presented token and issues a new
	// one via CreateRefreshToken, so a stolen-and-replayed old token is
	// detectable (it will already be consumed).
	RedeemRefreshToken(ctx context.Context, redemption RefreshTokenRedemption) (RedeemedRefreshToken, error)
}
