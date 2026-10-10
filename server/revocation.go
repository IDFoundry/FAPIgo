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
	// A backend that does use a TTL must keep the record until at
	// least expiresAt (a TTL of time.Until(expiresAt), rounded up),
	// never a fixed TTL that could be shorter: see
	// storage.RevocationStore.
	//
	// The same store also records revoked grants, under keys of their
	// own: "grant:" and the grant ID (RevokeGrant), and "code-grant:"
	// and an ID the server derives from an authorization code, when
	// that code is reused. For those, expiresAt is when nothing issued
	// from the grant can still be used. Keys must be compared exactly,
	// and a key kept revoked until at least its expiresAt: run
	// storage.TestRevocationStoreContract against an implementation.
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
