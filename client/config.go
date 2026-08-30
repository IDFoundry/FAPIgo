package client

import (
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/storage"
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

// PARDPoPBinding selects how BeginAuthorization commits the eventual
// authorization code to this client's DPoP key at PAR time (RFC 9449
// §10.1 recognizes two mechanisms; an authorization server supporting
// both PAR and DPoP must accept either). Unlike Profile/Algorithms/
// Limits, whose zero value is deliberately invalid because there's no
// universally-preferable choice, this type's zero value is a real,
// meaningful default: RFC 9449 §10.1 itself recommends
// PARDPoPBindingProof over PARDPoPBindingJKT, so a Config that never
// mentions this field gets the recommended behavior for free rather
// than a validation error.
type PARDPoPBinding uint8

const (
	// PARDPoPBindingProof (the default, zero value) sends an actual DPoP
	// proof — not just its key's thumbprint — as this pushed
	// authorization request's own "DPoP" header, binding the eventual
	// authorization code to whichever key demonstrated possession here.
	// RFC 9449 §10.1 recommends this over PARDPoPBindingJKT: it reuses
	// the same proof-building this client already does at the token and
	// resource endpoints (no separate thumbprint computation or
	// parameter), and unlike a bare dpop_jkt claim, it's actual proof of
	// possession at PAR time, not just a key identifier.
	PARDPoPBindingProof PARDPoPBinding = iota

	// PARDPoPBindingJKT instead declares the key via the plain
	// "dpop_jkt" request parameter (RFC 9449 §10), without proving
	// possession of it until the token endpoint. Every authorization
	// server supporting DPoP at PAR must accept this mechanism too (RFC
	// 9449 §10.1's own MUST) — kept for interop with a deployment that
	// has a specific reason to prefer it.
	PARDPoPBindingJKT
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
	// Required to call VerifyIssuerJWS or FetchUserInfo; a client that
	// never verifies such an artifact can leave this zero.
	UserInfo fapi.SignatureAlgorithm

	// UserInfoKeyManagement, if set, declares that FetchUserInfo expects
	// (and can decrypt) a signed-then-encrypted nested JWT UserInfo
	// response (OIDC Core §5.3.2), using this key-management algorithm.
	// Zero (the default) means FetchUserInfo expects a plain JSON or
	// signed-only response; a response arriving encrypted when this is
	// zero — or unencrypted when this is set — is rejected outright, the
	// same downgrade protection Algorithms.IDTokenKeyManagement applies.
	// Whatever value is set here reflects a registration this client
	// made with the authorization server out of band, and Dependencies
	// must supply a matching keys.Decrypter when it is non-zero.
	UserInfoKeyManagement fapi.KeyManagementAlgorithm

	// UserInfoContentEncryption is the content-encryption algorithm
	// paired with UserInfoKeyManagement. Required together: both zero,
	// or both set.
	UserInfoContentEncryption fapi.ContentEncryptionAlgorithm

	// BackchannelAuthenticationRequest is the algorithm this client
	// signs its CIBA backchannel authentication requests with.
	// Required only when Endpoints.BackchannelAuthentication is set.
	BackchannelAuthenticationRequest fapi.SignatureAlgorithm
}

// Endpoints are the authorization server's endpoint URLs this client
// calls or redirects the user agent to.
type Endpoints struct {
	Authorization              fapi.URL
	Token                      fapi.URL
	PushedAuthorizationRequest fapi.URL

	// UserInfo is the server's UserInfo Endpoint (OpenID Connect
	// Discovery 1.0 §3), if this client calls FetchUserInfo. OPTIONAL —
	// zero means FetchUserInfo is unavailable (it returns an error
	// rather than assuming any particular URL). Discover populates this
	// automatically when the server advertises one; otherwise, set it
	// from a deployment's own out-of-band knowledge of the server.
	UserInfo fapi.URL

	// BackchannelAuthentication is the server's CIBA backchannel
	// authentication endpoint (OpenID Connect CIBA Core 1.0 §7), if
	// this client calls BeginBackchannelAuthentication. OPTIONAL —
	// zero means CIBA is unavailable. Discover populates this
	// automatically when the server advertises one; otherwise, set it
	// from a deployment's own out-of-band knowledge of the server.
	BackchannelAuthentication fapi.URL
}

// MTLSEndpoints are the mTLS-requiring alternate URLs (RFC 8705 §5's
// "mtls_endpoint_aliases") a server may advertise for whichever of its
// own endpoints need one — only relevant to a
// Config.SenderConstrain == SenderConstrainMTLS client;
// DiscoveredMetadata.MTLSEndpointAliases surfaces this from discovery.
type MTLSEndpoints struct {
	Token                      fapi.URL
	PushedAuthorizationRequest fapi.URL
	BackchannelAuthentication  fapi.URL
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

	// BackchannelAuthenticationRequestLifetime is how long this
	// client's own signed CIBA backchannel authentication request
	// remains valid for (exp = Now + BackchannelAuthenticationRequestLifetime),
	// mirroring RequestObjectLifetime's role for PAR. Required only
	// when Endpoints.BackchannelAuthentication is set.
	BackchannelAuthenticationRequestLifetime time.Duration

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

	// MaxJOSECompactBytes bounds how large a JOSE compact serialization
	// (JWS or JWE) this client will parse for an ID token or a UserInfo
	// response — the two artifacts whose size scales with however many
	// scopes/claims this deployment's issuer was asked to grant, so a
	// fixed size can fit one user's response and not another's. This is
	// deliberately narrower than MaxHTTPResponseBytes, which still
	// bounds the outer HTTP read first: a DPoP proof, client assertion
	// or request object has no such variability and is not affected by
	// this field at all — those stay on jose.DefaultMaxCompactBytes.
	MaxJOSECompactBytes int
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

	// TrustedIDTokenAudiences lists any other party this client trusts
	// to also be named alongside its own ClientID in a multi-valued
	// "aud" claim on a received ID token. OIDC Core §3.1.3.7 step 3
	// requires rejecting an ID token "if it contains additional
	// audiences not trusted by the Client" — by default (nil/empty)
	// this client trusts none, so any audience besides its own ClientID
	// causes rejection, exactly as before this field existed. Set only
	// to entries this client has an actual, specific reason to trust;
	// see internal/token.IDTokenValidatePolicy.TrustedAudiences, which
	// this configures.
	TrustedIDTokenAudiences []string

	// TolerateUserInfoSubjectEqualsClientID works around a defect some
	// authorization servers have been observed to have: returning the
	// client's own client_id as the UserInfo response's "sub" claim,
	// instead of the authenticated end-user's actual subject identifier.
	// OIDC Core §5.3.2 requires this client to reject a UserInfo
	// response whose "sub" doesn't exactly match the ID token's "sub" —
	// the defense against a resource server (or a network attacker in
	// front of it) substituting another user's claims into a response
	// this flow would otherwise trust. Setting this to true additionally
	// accepts "sub" equal to this client's own ClientID as a fallback
	// when it doesn't match the ID token's subject.
	//
	// Enable this only against a specific authorization server you've
	// confirmed has this defect, and only until it's fixed server-side:
	// every one of that server's UserInfo responses now carries the same
	// "sub" value (the client_id) regardless of which end-user actually
	// authenticated, so this check can no longer distinguish one user's
	// claims from another's for that server — the exact substitution
	// OIDC Core §5.3.2 exists to catch. Defaults to false, which
	// preserves the exact-match behavior this package has always had.
	TolerateUserInfoSubjectEqualsClientID bool

	// PARDPoPBinding selects how BeginAuthorization commits this
	// client's DPoP key at PAR time — see PARDPoPBinding's own doc
	// comment. Defaults to PARDPoPBindingProof, RFC 9449 §10.1's own
	// recommended mechanism. Only meaningful when SenderConstrain is
	// SenderConstrainDPoP; ignored entirely under SenderConstrainMTLS,
	// which has no PAR-time pre-commitment concept of its own (RFC 8705
	// binding is derived purely from whichever certificate authenticates
	// the eventual token-endpoint connection).
	PARDPoPBinding PARDPoPBinding

	// SenderConstrain selects how this client's access tokens are
	// sender-constrained — storage.SenderConstrainDPoP (the default,
	// zero value) builds and presents a DPoP proof on every PAR/token/
	// backchannel call, exactly as this package has always done;
	// storage.SenderConstrainMTLS instead presents no DPoP proof at
	// all, relying entirely on Dependencies.HTTP's own configured
	// transport (an *http.Client whose Transport.TLSClientConfig.Certificates
	// is set) to present this client's certificate on the underlying
	// TLS connection. This package never holds or manages that
	// certificate itself — consistent with keeping raw credential
	// material behind an injected dependency rather than inside Config,
	// the same principle that keeps JWS signing keys behind
	// Dependencies.Keys instead of here.
	SenderConstrain storage.SenderConstrain

	// ClientAuthMethod selects how this client authenticates itself to
	// the authorization server — storage.ClientAuthMethodPrivateKeyJWT
	// (the default, zero value) signs and sends a client_assertion on
	// every client-authenticated call, exactly as this package has
	// always done. Every other value (storage.ClientAuthMethodSelfSignedTLSClientAuth,
	// storage.ClientAuthMethodTLSClientAuth, and the four
	// storage.ClientAuthMethodTLSClientAuthSAN* variants — RFC 8705 §2)
	// instead send a plain client_id form parameter and no assertion at
	// all — the TLS client certificate Dependencies.HTTP's own transport
	// presents on the connection (see SenderConstrain's own doc comment
	// for how that certificate gets there) is the credential. Reuses
	// storage's enum type directly rather than duplicating it, the same
	// precedent SenderConstrain itself establishes.
	ClientAuthMethod storage.ClientAuthMethod

	// BackchannelTokenDeliveryMode selects how this client expects to
	// learn a CIBA backchannel authentication request's decision —
	// storage.BackchannelTokenDeliveryModePoll (the default, zero
	// value) means this client polls the token endpoint itself
	// (PollBackchannelAuthentication), exactly as this package has
	// always done. storage.BackchannelTokenDeliveryModePing additionally
	// makes BeginBackchannelAuthentication generate and send a
	// client_notification_token, exposed on the returned
	// BackchannelAuthenticationSession for the caller to correlate an
	// incoming ping callback (CIBA §10.2) back to the right session —
	// this package never receives that callback itself, since it has no
	// HTTP server of its own. Reuses storage's enum type directly, the
	// same precedent SenderConstrain/ClientAuthMethod establish.
	BackchannelTokenDeliveryMode storage.BackchannelTokenDeliveryMode
}
