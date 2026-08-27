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

	// ClientEncryptionKeys resolves a registered client's encryption
	// keys, for issuing it an encrypted ID token (OIDC Core §2).
	// Required exactly when Config.Algorithms.IDTokenEncryptionKeyManagement/
	// IDTokenEncryptionContentEncryption are non-empty; nil otherwise —
	// most deployments never enable this, so it stays an opt-in
	// dependency rather than a mandatory one every embedder has to wire
	// up.
	ClientEncryptionKeys keys.ClientEncryptionKeySource

	// Keys performs this server's own signing operations: JARM response
	// signing (when Config.Profile requires it), and ID token signing
	// (always). Access-token signing, when AccessTokens is
	// JWTAccessTokens, is that type's own concern — see its doc
	// comment.
	Keys keys.KeyManager

	// AccessTokens issues this server's access tokens. Required — pass
	// JWTAccessTokens{...} (the default), OpaqueAccessTokens{...}, or
	// your own AccessTokenIssuer.
	AccessTokens AccessTokenIssuer

	// Audit records security-significant events. Required when
	// Config.Assurance is AssuranceProduction; optional otherwise.
	Audit AuditSink

	// Revocation lets this server revoke an access token it already
	// issued, on detected authorization-code reuse (RFC 6749 §4.1.2).
	// Required, like every field above except Audit/IdentityClaims —
	// pass a real RevocationSink, or NoRevocation{} to explicitly
	// decline (see NoRevocation's own doc comment for why).
	Revocation RevocationSink

	// Clock supplies the current time.
	Clock Clock

	// Random is the source of randomness for request_uri, interaction
	// handle, authorization code and DPoP nonce generation.
	Random io.Reader

	// IdentityClaims resolves identity claim values (e.g. "name",
	// "email") to embed in an ID token when the granted scope included
	// "openid". Optional — nil means no identity claims are ever added,
	// which is a permitted response to the "claims" request parameter
	// (see IdentityClaimsSource), not an error.
	IdentityClaims IdentityClaimsSource

	// Nonces persists DPoP nonces this server issues and consumes for
	// requests to the PAR and token endpoints. Nil disables DPoP
	// nonce-challenge support entirely (RFC 9449 §8) — like
	// IdentityClaims, this is a genuinely optional field, not a
	// security check this module treats as non-negotiable the way
	// Revocation is: declining it is the normal, fully spec-compliant
	// default. One shared store covers both endpoints — a nonce issued
	// from a PAR response is valid at the token endpoint and vice
	// versa, the same way resource.Dependencies.Nonces covers every
	// protected-resource endpoint uniformly rather than one store per
	// endpoint. Set it (and Config.Limits.DPoPNonceLifetime) to have
	// this server challenge a DPoP proof carrying no valid nonce, and
	// proactively reissue a fresh one on every successful call.
	Nonces storage.NonceStore
}
