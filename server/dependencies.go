package server

import (
	"io"

	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/storage"
)

// Dependencies are this server's injected collaborators. New rejects a
// nil value for any field except Audit, whose requirement depends on
// Config.Assurance — there is no implicit fallback for any of them (no
// silently-installed in-memory store, no default clock, no default
// randomness source).
type Dependencies struct {
	// Clients resolves a registered client by ID.
	Clients storage.ClientRepository

	// Transactions persists pushed-authorization-request and
	// interaction state.
	Transactions storage.TransactionStore

	// Grants persists issued authorization codes.
	Grants storage.GrantStore

	// Replay detects reuse of a client assertion's, request object's or
	// DPoP proof's jti.
	Replay storage.ReplayStore

	// ClientKeys resolves a registered client's verification keys.
	ClientKeys keys.ClientKeySource

	// Keys performs this server's own signing operations: JARM response
	// signing (when Config.Profile requires it), and access/ID token
	// signing (always).
	Keys keys.KeyManager

	// Audit records security-significant events. Required when
	// Config.Assurance is AssuranceProduction; optional otherwise.
	Audit AuditSink

	// Clock supplies the current time.
	Clock Clock

	// Random is the source of randomness for request_uri, interaction
	// handle and authorization code generation.
	Random io.Reader

	// IdentityClaims resolves identity claim values (e.g. "name",
	// "email") to embed in an ID token when the granted scope included
	// "openid". Optional — nil means no identity claims are ever added,
	// which is a permitted response to the "claims" request parameter
	// (see IdentityClaimsSource), not an error.
	IdentityClaims IdentityClaimsSource
}
