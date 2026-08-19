package server

import (
	"context"
	"time"
)

// RevocationSink lets this server revoke an access token it already
// issued — used when a reused authorization code is detected (RFC 6749
// §4.1.2: "the authorization server SHOULD revoke (if possible) all
// tokens previously issued based on that authorization code").
// Dependencies.Revocation has no default: pass a real implementation,
// or NoRevocation{} to explicitly decline — see NoRevocation's own doc
// comment for why declining must be a visible choice, not a silent one.
type RevocationSink interface {
	// Revoke marks key as revoked — a JWT's jti claim when the active
	// AccessTokenIssuer is JWTAccessTokens, an opaque token's own hash
	// when it's OpaqueAccessTokens; opaque either way from this
	// interface's point of view. expiresAt is a conservative upper
	// bound on the access token's own expiry (the server no longer has
	// the token's real exp claim at this point in the flow) — a
	// backend with native per-key TTL support (Redis EXPIRE, a
	// DynamoDB TTL attribute, a SQL row swept on a schedule) can use it
	// to self-expire the record: once the token's own expiry would make
	// it invalid anyway, nothing depends on the revocation record
	// still existing. A backend without TTL support can ignore it —
	// storage/memstore.RevocationStore, this module's own reference
	// implementation, does exactly that; see its doc comment for why.
	Revoke(ctx context.Context, key string, expiresAt time.Time) error
}

// NoRevocation is an explicit no-op RevocationSink for a deployment
// that has decided not to support access-token revocation. There is no
// implicit default here (see server/dependencies.go and
// ARCHITECTURE.md: "no silently-installed in-memory store") — New
// rejects a nil Dependencies.Revocation the same way it rejects a nil
// Grants or Clock. NoRevocation exists so declining is a conscious,
// visible line of code (Revocation: server.NoRevocation{}) instead of
// an easily-forgotten omission — the whole point of making this field
// required rather than silently skippable.
type NoRevocation struct{}

// Revoke implements RevocationSink by doing nothing.
func (NoRevocation) Revoke(context.Context, string, time.Time) error { return nil }
