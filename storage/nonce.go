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

// NonceConsumption is the input to NonceStore.Consume.
type NonceConsumption struct {
	// Nonce is the value a presented DPoP proof's own "nonce" claim
	// carried — the lookup key.
	Nonce string
}

// NonceRecord is what Consume returns for a successfully consumed
// nonce — the expiry Issue persisted, for the caller to compare against
// the time it's verifying at, the same division of responsibility every
// other store in this package uses (the store itself never judges
// expiry).
type NonceRecord struct {
	ExpiresAt time.Time
}

// NonceStore persists DPoP nonces a verifier has issued, keyed by the
// nonce value itself. Like SessionStore, it exposes no generic CRUD —
// Consume is the only way to check a nonce, and it always retires the
// record it returns.
type NonceStore interface {
	Issue(ctx context.Context, issuance NonceIssuance) error

	// Consume atomically retrieves and retires the nonce identified by
	// consumption.Nonce — a second call with the same value must fail,
	// exactly like SessionStore.Consume, so a captured nonce can never
	// be presented twice. It returns an error if the nonce is unknown or
	// already consumed; the caller checks the returned record's own
	// expiry (ExpiresAt) against the time it's verifying at.
	Consume(ctx context.Context, consumption NonceConsumption) (NonceRecord, error)
}
