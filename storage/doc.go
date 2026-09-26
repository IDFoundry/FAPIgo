// Package storage defines the persistence contracts used by client and
// server, plus the replay-detection primitive they can both safely share.
//
// Client and server state have different semantics and must not be
// collapsed into one generic CRUD interface: client_repository.go
// defines the server's registered-client lookup, transaction.go defines
// the server's PAR transaction store — CreatePAR persists a pushed
// authorization request, BeginAuthorization atomically retrieves and
// consumes one and associates it with a new interaction handle, and
// CompleteAuthorization atomically retrieves and consumes that
// interaction — grant.go defines the server's authorization-code and
// refresh-token store — CreateAuthorizationCode/CreateRefreshToken each
// persist one, RedeemAuthorizationCode/RedeemRefreshToken each
// retrieve one (an authorization code single-use, a refresh token
// reusable until it expires or is revoked) — access_token.go
// defines AccessTokenStore, the storage-backed alternative to a
// self-contained JWT access token (CreateAccessToken/LookupAccessToken
// only — existence and expiry, never revocation, see that file's own
// doc comment for why) — and replay.go defines a single-use ReplayStore
// keyed by a namespaced identifier (e.g. "client:jarm", "server:dpop")
// so that different roles and subsystems can never collide on the same
// use-once token. The client's own session store will follow the same
// per-role-type pattern once the endpoint that needs it exists. No
// interface here exposes GetX/UpdateX/DeleteX-style CRUD —
// every method is a named security operation (Create, Consume, Redeem,
// UseOnce), and redemption-style operations verify and consume state
// atomically in one call rather than as separate check-then-act steps.
// replay.Store persists only a digest and expiry per use, never a
// complete client assertion or DPoP proof.
//
// Records keep as explicit fields only what a store itself acts on — a
// lookup hash, ClientID, ExpiresAt, and for CIBA the decision status and
// delivery state. Everything else server needs later (the original
// request's parameters, the granted scope, subject, authentication
// context, claims) travels as one opaque, versioned JSON value — the
// Request and Grant fields — that a store persists and returns as-is
// without interpreting it. Store it in any column type that returns
// equivalent JSON (bytes, text, or a JSON/JSONB column; key order and
// whitespace needn't be preserved). A server feature that changes what
// a grant carries changes only that value, never a store.
//
// Because a backend's atomicity/durability guarantees are self-asserted,
// this package also defines a StoreAssurance.Capabilities interface
// (durable, atomic-consume, serializable-redemption,
// cross-instance-consistent, encrypted-at-rest) that server checks at
// construction time under its production assurance level, plus a
// reusable contract test suite (e.g. TestGrantStoreContract(t, factory))
// that exercises single-use redemption and its exactly-one-winner
// behavior under in-process concurrency, field round-tripping,
// unknown-key handling, and revocation, against any implementation —
// first-party or downstream. The suite runs one store instance in one
// process against context.Background(); it deliberately does not
// verify cross-instance/cross-connection atomicity, ExpiresAt-driven
// eviction, context-cancellation, or that the store deep-copies
// caller-supplied slices/maps. A production backend must establish
// those separately — see StoreAssurance.Capabilities for the
// atomicity/durability properties server requires under its production
// assurance level.
package storage
