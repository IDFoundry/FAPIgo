package storage

import (
	"context"
	"time"
)

// NonceIssuance is what Issue persists for one DPoP nonce a verifier has
// handed out — either as an RFC 9449 §8/§9 challenge, or proactively
// alongside a successful response — keyed by Nonce itself.
type NonceIssuance struct {
	Nonce     string
	ExpiresAt time.Time
}

// NonceLookup is the input to NonceStore.Lookup.
type NonceLookup struct {
	// Nonce is the value a presented DPoP proof's own "nonce" claim
	// carried — the lookup key.
	Nonce string
}

// NonceRecord is what Lookup returns for an issued nonce — the expiry
// Issue persisted, for the caller to compare against the time it's
// verifying at, the same division of responsibility every other store
// in this package uses (the store itself never judges expiry).
type NonceRecord struct {
	ExpiresAt time.Time
}

// NonceStore persists DPoP nonces a verifier has issued, keyed by the
// nonce value itself. Like SessionStore, it exposes no generic CRUD.
//
// A nonce is valid for a time window, not for one use: RFC 9449 §8
// expects "clients need to keep only one nonce value and servers need
// to keep a window of recent nonces", and a client presents the same
// nonce on every request until the server supplies a new one (§8.2). A
// replayed proof is refused by its "jti" (Dependencies.Replay), not by
// its nonce. The verifiers built on this store hand out one current
// nonce at a time and issue the next before half its lifetime has
// passed, so Issue is called rarely and Lookup on every request.
type NonceStore interface {
	// Issue persists issuance under its Nonce until at least its
	// ExpiresAt, so Lookup can find it.
	Issue(ctx context.Context, issuance NonceIssuance) error

	// Lookup returns the record Issue persisted for lookup.Nonce,
	// leaving it in place: any number of calls, concurrent or not, with
	// an issued nonce must all succeed. It returns an error if the nonce
	// is unknown; the caller checks the returned record's own expiry
	// (ExpiresAt) against the time it's verifying at, so the store may
	// drop a record once it has expired. An error wrapping
	// ErrStoreUnavailable (the store couldn't answer at all),
	// context.Canceled or context.DeadlineExceeded is answered by a
	// resource server with 500 server_error instead of a fresh
	// use_dpop_nonce challenge.
	Lookup(ctx context.Context, lookup NonceLookup) (NonceRecord, error)
}
