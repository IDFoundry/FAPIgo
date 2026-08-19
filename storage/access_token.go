package storage

import (
	"context"
	"encoding/json"
	"time"

	fapi "github.com/idfoundry/fapigo"
)

// NewAccessToken is what CreateAccessToken persists for one issued
// opaque access token. TokenHash is the SHA-256 digest of the raw
// token value, never the value itself — the same digest-only
// discipline as NewAuthorizationCode.CodeHash/NewRefreshToken.TokenHash.
// Only relevant to an opaque AccessTokenIssuer/AccessTokenVerifier
// (see server.OpaqueAccessTokens/resource.OpaqueAccessTokens) — a
// deployment issuing JWT access tokens never calls this.
type NewAccessToken struct {
	TokenHash [32]byte

	ClientID   fapi.ClientID
	Subject    string
	Scope      []string
	Thumbprint string
	Claims     map[string]json.RawMessage

	ExpiresAt time.Time
}

// AccessTokenLookup is the input to AccessTokenStore.LookupAccessToken.
type AccessTokenLookup struct {
	// TokenHash is the SHA-256 digest of the presented access token
	// value — the same digest CreateAccessToken stored it under.
	TokenHash [32]byte
}

// LookedUpAccessToken is what LookupAccessToken returns for a known
// token.
type LookedUpAccessToken struct {
	ClientID   fapi.ClientID
	Subject    string
	Scope      []string
	Thumbprint string
	Claims     map[string]json.RawMessage

	ExpiresAt time.Time
}

// AccessTokenStore persists opaque access tokens — the storage-backed
// alternative to a self-contained JWT (see server.JWTAccessTokens vs.
// server.OpaqueAccessTokens, and resource's matching pair). Only
// relevant when an opaque AccessTokenIssuer/AccessTokenVerifier is in
// use; a deployment issuing JWT access tokens never needs this
// dependency at all.
//
// Revocation is deliberately not this interface's concern — see
// server.RevocationSink/resource.RevocationChecker, called separately
// and uniformly by this library regardless of access-token format, the
// same way for both JWT and opaque tokens. LookupAccessToken only
// needs to answer "does this exist and what does it mean" — existence
// and expiry, nothing else.
type AccessTokenStore interface {
	CreateAccessToken(ctx context.Context, tok NewAccessToken) error

	// LookupAccessToken returns the stored record for lookup.TokenHash.
	// It returns an error only if the hash is unknown; the caller
	// checks the returned record's own expiry (ExpiresAt) itself, the
	// same way every other *Redeemed/LookedUp* type in this package is
	// checked by its caller.
	LookupAccessToken(ctx context.Context, lookup AccessTokenLookup) (LookedUpAccessToken, error)
}
