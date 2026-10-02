package storage

import (
	"context"
	"encoding/json"
	"time"
)

// NewSession is what Create persists for one in-progress client
// authorization attempt, keyed by State — the value the client generated
// for the authorization request's "state" parameter.
type NewSession struct {
	State string

	// Record is everything the client later needs from this attempt —
	// its nonce, PKCE verifier, expected issuer, redirect URI and
	// response mode, and the max_age it requested — as opaque, versioned
	// JSON the client package owns. A store never interprets it: it
	// persists it as is (byte for byte, or as equivalent JSON) and
	// Consume returns it. A new client feature changes only this record,
	// never the store.
	Record json.RawMessage

	ExpiresAt time.Time
}

// SessionConsumption is the input to SessionStore.Consume.
type SessionConsumption struct {
	// State is the value the client generated for this session's "state"
	// parameter — the lookup key.
	State string
}

// ConsumedSession is what Consume returns for a successfully consumed
// session: the Record and ExpiresAt Create persisted. The client refuses
// a session whose Record is missing or unreadable.
type ConsumedSession struct {
	Record    json.RawMessage
	ExpiresAt time.Time
}

// SessionStore persists client-side authorization-flow state, keyed by
// the "state" parameter the client generated for one authorization
// attempt. Like TransactionStore and GrantStore, it exposes no generic
// CRUD (no GetSession, no DeleteSession) — Consume is the only way to
// retrieve a session, and it always retires the record it returns.
type SessionStore interface {
	Create(ctx context.Context, session NewSession) error

	// Consume atomically retrieves and retires the session identified by
	// State — a second call with the same State must fail, exactly like
	// GrantStore's Redeem methods — so a callback (or an attacker
	// replaying one) can never be processed twice. It returns an error if
	// State is unknown or already consumed; the caller checks the
	// returned record's own expiry (ExpiresAt) and compares the Record's
	// contents against what the authorization response actually carried,
	// the same division of responsibility TransactionStore and GrantStore
	// use.
	Consume(ctx context.Context, consumption SessionConsumption) (ConsumedSession, error)
}
