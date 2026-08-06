package storage

import (
	"context"
	"time"
)

// NewSession is what Create persists for one in-progress client
// authorization attempt, keyed by State — the value the client generated
// for the authorization request's "state" parameter.
type NewSession struct {
	State string

	// Nonce is the value the client generated for the authorization
	// request's "nonce" parameter, to check against an issued ID token's
	// own nonce claim.
	Nonce string

	// PKCEVerifier is the code_verifier the client generated; ExchangeCode
	// presents it to redeem the authorization code.
	PKCEVerifier string

	// ExpectedIssuer is the authorization server this session's
	// authorization response must come from.
	ExpectedIssuer string

	// ExpectedRedirectURI is the redirect_uri this session's authorization
	// request carried, presented again at code exchange.
	ExpectedRedirectURI string

	// ExpectedResponseMode is the response mode this session's
	// authorization request declared (plain query parameters, or a signed
	// JARM response) — checked against how the response actually arrived,
	// so a downgrade from a signed response to a plain one can't be used
	// to bypass JARM's integrity guarantee.
	ExpectedResponseMode string

	ExpiresAt time.Time
}

// SessionConsumption is the input to SessionStore.Consume.
type SessionConsumption struct {
	// State is the value the client generated for this session's "state"
	// parameter — the lookup key.
	State string
}

// ConsumedSession is what Consume returns for a successfully consumed
// session — the correlation state Create persisted, for the caller to
// compare against what the authorization response actually carried.
type ConsumedSession struct {
	Nonce                string
	PKCEVerifier         string
	ExpectedIssuer       string
	ExpectedRedirectURI  string
	ExpectedResponseMode string
	ExpiresAt            time.Time
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
	// returned record's own expiry (ExpiresAt) and compares every field
	// against what the authorization response actually carried, the same
	// division of responsibility TransactionStore and GrantStore use.
	Consume(ctx context.Context, consumption SessionConsumption) (ConsumedSession, error)
}
