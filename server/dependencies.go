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

	// Backchannel persists CIBA backchannel authentication requests.
	// Required exactly when Config.Endpoints.BackchannelAuthentication
	// is set; nil otherwise — CIBA is an entirely optional capability,
	// like ID token encryption's ClientEncryptionKeys.
	Backchannel storage.BackchannelAuthenticationStore

	// BackchannelNotifier dispatches a CIBA §10.2 ping notification once
	// a backchannel authentication request reaches a decision. Required
	// exactly when Config.Endpoints.BackchannelAuthentication is set —
	// the same condition Backchannel itself is required under — pass a
	// real implementation, or NoBackchannelNotifications{} to explicitly
	// decline (see that type's own doc comment for why).
	BackchannelNotifier BackchannelNotifier

	// ClientCredentialsRARPolicy decides which Rich Authorization
	// Requests (RFC 9396) detail objects a client_credentials token
	// request is entitled to receive — see RARPolicy's own doc comment.
	// Optional, like IdentityClaims, but unlike IdentityClaims its
	// absence is not permissive: a client_credentials request naming
	// authorization_details with no policy configured is refused, not
	// silently granted everything Config.RAR happens to have registered.
	ClientCredentialsRARPolicy RARPolicy

	// RARRequestPolicy is PAR/CIBA's own request-time counterpart of
	// ClientCredentialsRARPolicy — a defense-in-depth gate on which Rich
	// Authorization Requests (RFC 9396) detail types a client may even
	// *request*, consulted before the request is ever stored or shown to
	// a resource owner. See RARPolicy's own doc comment for the full
	// contract, including why an unconfigured policy refuses rather than
	// falling back to "anything Config.RAR has registered is
	// requestable" — the resource owner's own approval
	// (GrantedAuthorization.AuthorizationDetails) remains the primary
	// entitlement check for these two flows regardless of whether this
	// field is set; this only narrows what a client may put in front of
	// that resource owner in the first place.
	RARRequestPolicy RARPolicy
}
