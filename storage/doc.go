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
// atomically retrieve and consume one (refresh tokens rotate: every
// redemption is paired with a new CreateRefreshToken call) — access_token.go
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
