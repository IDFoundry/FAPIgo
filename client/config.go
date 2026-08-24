package client

import (
	"time"

	fapi "github.com/idfoundry/fapigo"
)

// Profile selects which FAPI 2.0 security profile this client targets.
// It must match the authorization server's own configured profile — see
// server.Profile.
type Profile uint8

const (
	_ Profile = iota

	// ProfileFAPISecurity is the FAPI 2.0 Security Profile baseline: PAR,
	// PKCE and DPoP are always used; the pushed authorization request
	// carries plain parameters, and the authorization response is plain
	// query parameters.
	ProfileFAPISecurity

	// ProfileFAPISecurityWithMessageSigning additionally signs every
	// pushed authorization request as a request object, and requires the
	// authorization response to be a signed JARM response.
	ProfileFAPISecurityWithMessageSigning
)

// Algorithms are the single algorithm this client uses for each signing
// operation it performs, and the single algorithm it expects the
// authorization server to use for each of its own. A closed
// fapi.SignatureAlgorithm value, never a caller-suppliable string — see
// ARCHITECTURE.md design rule 2.
type Algorithms struct {
	// ClientAuthentication is the algorithm this client signs its
	// private_key_jwt client assertions with.
	ClientAuthentication fapi.SignatureAlgorithm

	// RequestObject is the algorithm this client signs pushed
	// authorization request objects with. Required only when Profile is
	// ProfileFAPISecurityWithMessageSigning.
	RequestObject fapi.SignatureAlgorithm

	// DPoP is the algorithm this client signs DPoP proofs with.
	DPoP fapi.SignatureAlgorithm

	// JARM is the algorithm the authorization server is registered (or
	// discovered) to sign authorization responses with. Required only
	// when Profile is ProfileFAPISecurityWithMessageSigning.
	JARM fapi.SignatureAlgorithm

	// IDToken is the algorithm the authorization server is registered (or
	// discovered) to sign ID tokens with.
	IDToken fapi.SignatureAlgorithm

	// IDTokenKeyManagement, if set, declares that this client expects
	// (and can decrypt) an encrypted — or encrypted-then-signed nested
	// JWT (OIDC Core §10.2) — ID token, using this key-management
	// algorithm. Zero (the default) means this client expects an
	// ordinary signed-only ID token; a plain signed ID token arriving
	// when this is set is rejected outright, not silently accepted,
	// since the whole point of registering for encryption is that a
	// downgrade to plaintext must not go unnoticed. Whatever value is
	// set here reflects a registration this client made with the
	// authorization server out of band — this module has no dynamic
	// client registration flow of its own — and Dependencies must
	// supply a matching keys.Decrypter when it is non-zero.
	IDTokenKeyManagement fapi.KeyManagementAlgorithm

	// IDTokenContentEncryption is the content-encryption algorithm
	// paired with IDTokenKeyManagement. Required together: both zero, or
	// both set. Kept as its own field — separate from
	// IDTokenKeyManagement — so a future second
	// fapi.ContentEncryptionAlgorithm value doesn't change this field's
	// meaning or Config's shape, the same reasoning
	// jwe.EncryptRequest/DecryptRequest already apply.
	IDTokenContentEncryption fapi.ContentEncryptionAlgorithm

	// UserInfo is the algorithm the authorization server is registered
	// (or discovered) to sign an issuer-verified JWS with, for
	// VerifyIssuerJWS — most commonly the inner JWS of a signed (or
	// signed-then-encrypted) UserInfo response (OIDC Core §5.3.2).
	// Required only to call VerifyIssuerJWS; a client that never
	// verifies such an artifact can leave this zero.
	UserInfo fapi.SignatureAlgorithm
}

// Endpoints are the authorization server's endpoint URLs this client
// calls or redirects the user agent to.
type Endpoints struct {
	Authorization              fapi.URL
	Token                      fapi.URL
	PushedAuthorizationRequest fapi.URL
}

// Limits bounds the lifetimes and clock tolerances this client enforces
// or sets. None of these have an implicit default — New rejects a zero
// (or, for MaxClockSkew, negative) value.
type Limits struct {
	// ClientAssertionLifetime is how long a client assertion this client
	// signs remains valid for (exp = Now + ClientAssertionLifetime).
	ClientAssertionLifetime time.Duration

	// RequestObjectLifetime is how long a signed request object this
	// client produces remains valid for. Required only when Profile is
	// ProfileFAPISecurityWithMessageSigning.
	RequestObjectLifetime time.Duration

	// SessionLifetime bounds how long between BeginAuthorization and a
	// completed HandleAuthorizationResponse a session remains valid.
	SessionLifetime time.Duration

	// MaxJARMResponseLifetime bounds how far in the future a JARM
	// response's exp claim may be. Required only when Profile is
	// ProfileFAPISecurityWithMessageSigning.
	MaxJARMResponseLifetime time.Duration

	// MaxIDTokenLifetime bounds how far in the future an ID token's exp
	// claim may be.
	MaxIDTokenLifetime time.Duration

	// MaxClockSkew bounds how far in the future an iat/nbf claim may be,
	// and extends how long past exp an artifact is still accepted. Zero
	// means no tolerance.
	MaxClockSkew time.Duration

	// HTTPTimeout bounds how long a single PAR or token-endpoint call may
	// take.
	HTTPTimeout time.Duration

	// MaxHTTPResponseBytes bounds how much of a PAR or token-endpoint
	// response body this client reads before failing.
	MaxHTTPResponseBytes int64
}

// Config is this client's immutable configuration. It is copied by New;
// mutating a Config after passing it to New has no effect.
type Config struct {
	// Issuer is the authorization server this client talks to — the
	// audience client assertions and request objects are addressed to,
	// and the issuer authorization responses and ID tokens must come
	// from.
	Issuer fapi.URL

	ClientID fapi.ClientID

	// RedirectURI is this client's registered redirect URI, sent on every
	// authorization request exactly as registered.
	RedirectURI string

	Endpoints  Endpoints
	Profile    Profile
	Algorithms Algorithms
	Limits     Limits

	// RequireAuthorizationResponseIss makes HandleAuthorizationResponse
	// reject a callback with no "iss" parameter at all, rather than only
	// checking one that's present. RFC 9207 §2.4 mandates both halves
	// unconditionally regardless of this setting — a present-but-wrong
	// "iss" is always rejected — but "MUST reject authorization responses
	// without the iss parameter" applies only "from authorization servers
	// that do support the parameter", which this client can't determine
	// on its own; set this from
	// DiscoveredMetadata.AuthorizationResponseIssSupported (or a
	// deployment's own out-of-band knowledge of the server).
	RequireAuthorizationResponseIss bool
}
