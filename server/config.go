package server

import (
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/extension"
	"github.com/idfoundry/fapigo/federation"
)

// Profile selects which FAPI 2.0 security profile this server enforces.
type Profile uint8

const (
	_ Profile = iota

	// ProfileFAPISecurity is the FAPI 2.0 Security Profile baseline: PAR,
	// PKCE and sender-constrained tokens are always required, but a
	// pushed authorization request may carry either plain parameters or
	// a signed request object.
	ProfileFAPISecurity

	// ProfileFAPISecurityWithMessageSigning additionally requires every
	// pushed authorization request to carry a signed request object; a
	// plain-parameter submission is rejected.
	ProfileFAPISecurityWithMessageSigning
)

// AlgorithmSet is a closed, ordered allow-list of signature algorithms.
type AlgorithmSet []fapi.SignatureAlgorithm

// Contains reports whether alg is in the set.
func (s AlgorithmSet) Contains(alg fapi.SignatureAlgorithm) bool {
	for _, a := range s {
		if a == alg {
			return true
		}
	}
	return false
}

// Strings returns s's own elements' wire values, in order — the shape
// an "*_alg_values_supported" discovery-metadata field needs (RFC 8414
// §2, OIDC Discovery 1.0 §3). Go has no way to enumerate an iota-based
// constant's own closed set at runtime, so an embedder extending
// Metadata with its own additional algorithm-list field (see Metadata's
// own doc comment) needs exactly this conversion; Metadata's own
// generation uses it internally for every field of this shape already.
func (s AlgorithmSet) Strings() []string { return algorithmSetStrings(s) }

// KeyManagementAlgorithmSet is a closed, ordered allow-list of JWE
// key-management algorithms.
type KeyManagementAlgorithmSet []fapi.KeyManagementAlgorithm

// Contains reports whether alg is in the set.
func (s KeyManagementAlgorithmSet) Contains(alg fapi.KeyManagementAlgorithm) bool {
	for _, a := range s {
		if a == alg {
			return true
		}
	}
	return false
}

// Strings returns s's own elements' wire values, in order — see
// AlgorithmSet.Strings' own doc comment.
func (s KeyManagementAlgorithmSet) Strings() []string { return algorithmSetStrings(s) }

// ContentEncryptionAlgorithmSet is a closed, ordered allow-list of JWE
// content-encryption algorithms.
type ContentEncryptionAlgorithmSet []fapi.ContentEncryptionAlgorithm

// Contains reports whether alg is in the set.
func (s ContentEncryptionAlgorithmSet) Contains(alg fapi.ContentEncryptionAlgorithm) bool {
	for _, a := range s {
		if a == alg {
			return true
		}
	}
	return false
}

// Strings returns s's own elements' wire values, in order — see
// AlgorithmSet.Strings' own doc comment.
func (s ContentEncryptionAlgorithmSet) Strings() []string { return algorithmSetStrings(s) }

// AlgorithmPolicy is the server-wide allow-list of algorithms clients
// may use, independent of and in addition to each RegisteredClient's own
// configured algorithm. A client registered with an algorithm outside
// these sets is rejected even though its own registration is
// internally consistent — this is the operator's override, not the
// client's.
type AlgorithmPolicy struct {
	ClientAssertion AlgorithmSet
	RequestObject   AlgorithmSet

	// JARM is the single algorithm this server signs authorization
	// responses with. Required (and validated) only when Profile is
	// ProfileFAPISecurityWithMessageSigning.
	JARM fapi.SignatureAlgorithm

	// IDToken is the single algorithm this server signs ID tokens with.
	// Required unless Config.OAuthOnly is true, in which case this
	// server never issues an ID token at all and this field is ignored.
	IDToken fapi.SignatureAlgorithm

	// IDTokenEncryptionKeyManagement/IDTokenEncryptionContentEncryption
	// are the server-wide allow-lists for encrypted ID tokens (OIDC Core
	// §2) — like ClientAssertion/RequestObject, a per-client choice
	// checked against this operator-controlled set, not a single
	// server-wide algorithm the way JARM/IDToken are. Both empty (the
	// default) means this server never encrypts ID tokens, regardless
	// of what any individual RegisteredClient's own fields say.
	IDTokenEncryptionKeyManagement     KeyManagementAlgorithmSet
	IDTokenEncryptionContentEncryption ContentEncryptionAlgorithmSet

	// UserInfo is the single algorithm this server signs UserInfo
	// responses with (OIDC Core §5.3.2), for an embedder's own UserInfo
	// handler to request via SignUserInfoResponse. Zero (the default)
	// means this server never signs UserInfo responses — most
	// deployments return plain JSON instead, the same "opt-in, no
	// implicit default" precedent already used for ID token encryption.
	UserInfo fapi.SignatureAlgorithm

	// UserInfoEncryptionKeyManagement/UserInfoEncryptionContentEncryption
	// are the server-wide allow-lists for encrypted UserInfo responses,
	// mirroring IDTokenEncryptionKeyManagement/ContentEncryption exactly
	// but independent of them — a client's UserInfo encryption
	// preference is its own separate OIDC registration
	// (userinfo_encrypted_response_alg/enc), not a reuse of its ID token
	// one. Both empty (the default) means this server never encrypts
	// UserInfo responses.
	UserInfoEncryptionKeyManagement     KeyManagementAlgorithmSet
	UserInfoEncryptionContentEncryption ContentEncryptionAlgorithmSet

	// BackchannelAuthenticationRequest is the server-wide allow-list for
	// CIBA's client-signed backchannel authentication request — kept
	// distinct from RequestObject even though both verify through the
	// same internal/requestobject machinery, since a client could
	// reasonably want a different algorithm for each. Required (and
	// validated) only when Endpoints.BackchannelAuthentication is set.
	BackchannelAuthenticationRequest AlgorithmSet
}

// Endpoints are this server's own endpoint URLs: the expected
// audience/target for artefacts bound to a specific endpoint (e.g. a
// DPoP proof's htu), and what Metadata advertises. They are not inferred
// from an incoming request's Host header — see fapihttp for why that
// matters.
type Endpoints struct {
	Authorization              fapi.URL
	Token                      fapi.URL
	PushedAuthorizationRequest fapi.URL
	JWKS                       fapi.URL

	// BackchannelAuthentication is this server's CIBA backchannel
	// authentication endpoint (OIDC CIBA §7). Optional — zero disables
	// CIBA entirely: BeginBackchannelAuthentication then always fails,
	// and Metadata omits every CIBA-related field, the same "zero
	// disables the feature" precedent client.Config.Endpoints.UserInfo
	// already uses.
	BackchannelAuthentication fapi.URL
}

// MTLSEndpoints are the mTLS-requiring alternate URLs (RFC 8705 §5's
// "mtls_endpoint_aliases") this server advertises for whichever of its
// own endpoints actually need one — only relevant to a client whose
// storage.RegisteredClient.SenderConstrain() is SenderConstrainMTLS;
// a DPoP-bound client keeps using Config.Endpoints' own plain URLs.
// Purely advertisement: this package has no opinion on listener
// topology (a second TLS listener requiring a client certificate, or a
// single listener that merely requests one — that's the HTTP adapter's
// own concern, the same way it alone owns TLS termination for
// Config.Endpoints too), and does not itself enforce that a request to
// one of these URLs actually arrived over a connection that presented
// a certificate — every SenderConstrainMTLS check already happens
// per-request via PeerCertificate on the relevant request struct,
// regardless of which URL it arrived at. Zero value (every field
// zero) omits mtls_endpoint_aliases from Metadata entirely.
type MTLSEndpoints struct {
	Token                      fapi.URL
	PushedAuthorizationRequest fapi.URL
	BackchannelAuthentication  fapi.URL
}

// IsZero reports whether every field of e is zero — Metadata uses this
// to decide whether to advertise mtls_endpoint_aliases at all.
func (e MTLSEndpoints) IsZero() bool {
	return e.Token.IsZero() && e.PushedAuthorizationRequest.IsZero() && e.BackchannelAuthentication.IsZero()
}

// Limits bounds the lifetimes and clock tolerances this server enforces.
// None of these have an implicit default — New rejects a zero (or, for
// MaxClockSkew, negative) value.
type Limits struct {
	// PushedRequestLifetime is how long a pushed authorization request's
	// request_uri remains valid, and is reported to the client as
	// expires_in.
	PushedRequestLifetime time.Duration

	// MaxClientAssertionLifetime bounds how far in the future a client
	// assertion's exp claim may be, relative to the time it's verified.
	MaxClientAssertionLifetime time.Duration

	// MaxRequestObjectLifetime bounds how far in the future a request
	// object's exp claim may be, relative to the time it's verified.
	MaxRequestObjectLifetime time.Duration

	// InteractionLifetime bounds how long an InteractionHandle returned
	// by BeginAuthorization remains valid.
	InteractionLifetime time.Duration

	// AuthorizationCodeLifetime bounds how long an authorization code
	// issued by CompleteAuthorization remains redeemable.
	AuthorizationCodeLifetime time.Duration

	// JARMResponseLifetime bounds how long a signed authorization
	// response remains valid, when Profile requires one.
	JARMResponseLifetime time.Duration

	// AccessTokenLifetime bounds how long an issued access token remains
	// valid.
	AccessTokenLifetime time.Duration

	// IDTokenLifetime bounds how long an issued ID token remains valid.
	// Required unless Config.OAuthOnly is true — see
	// AlgorithmPolicy.IDToken's own doc comment.
	IDTokenLifetime time.Duration

	// RefreshTokenLifetime bounds how long a newly issued (or rotated)
	// refresh token remains redeemable.
	RefreshTokenLifetime time.Duration

	// MaxDPoPProofAge bounds how old (relative to verification time) a
	// DPoP proof's iat claim may be.
	MaxDPoPProofAge time.Duration

	// MaxClockSkew bounds how far in the future an iat/nbf claim may be,
	// and extends how long past exp an artifact is still accepted. Zero
	// means no tolerance.
	MaxClockSkew time.Duration

	// DPoPNonceLifetime bounds how long an issued DPoP nonce remains
	// valid. Required only when Dependencies.Nonces is non-nil — see
	// its own doc comment; New rejects a zero value in that case, but
	// leaves it unvalidated when nonce-challenge support is disabled.
	DPoPNonceLifetime time.Duration

	// BackchannelAuthenticationRequestLifetime bounds how long a
	// pending CIBA request remains pollable — reported to the client as
	// expires_in, mirroring PushedRequestLifetime's role for PAR.
	// Required only when Endpoints.BackchannelAuthentication is set.
	BackchannelAuthenticationRequestLifetime time.Duration

	// MaxBackchannelAuthenticationRequestLifetime bounds how far in the
	// future a signed backchannel authentication request's own exp claim
	// may be — mirrors MaxRequestObjectLifetime's role for PAR's request
	// object. Required only when Endpoints.BackchannelAuthentication is
	// set.
	MaxBackchannelAuthenticationRequestLifetime time.Duration

	// BackchannelAuthenticationPollInterval is the minimum time a client
	// must wait between two polls of the same auth_req_id — reported to
	// the client as "interval", and enforced server-side (a poll sooner
	// than this fails with ErrorSlowDown). Required only when
	// Endpoints.BackchannelAuthentication is set.
	BackchannelAuthenticationPollInterval time.Duration
}

// Config is this server's immutable configuration. It is copied by New;
// mutating a Config after passing it to New has no effect.
type Config struct {
	// Issuer is this server's issuer identifier — the audience client
	// assertions and request objects must be addressed to, and the token
	// audience used until per-resource-server audiences (RFC 8707
	// resource indicators) are supported.
	Issuer fapi.URL

	Endpoints  Endpoints
	Profile    Profile
	Algorithms AlgorithmPolicy
	Limits     Limits
	Assurance  AssuranceLevel

	// MTLSEndpoints are this server's mTLS-requiring alternate URLs, if
	// any — see MTLSEndpoints' own doc comment. Optional; zero value
	// omits mtls_endpoint_aliases from Metadata.
	MTLSEndpoints MTLSEndpoints

	// Extensions registers every custom authorization parameter this
	// server accepts, beyond the standard OAuth/OIDC/PKCE parameters it
	// already understands (response_type, client_id, redirect_uri,
	// scope, state, nonce, code_challenge, code_challenge_method). A
	// parameter with no registered Definition is rejected — there is no
	// permissive fallback — so nil is equivalent to an empty Registry
	// (no custom parameters accepted at all), not to "extensions
	// disabled, accept anything." See ARCHITECTURE.md design rules
	// 10-11 and extension.Registry.Parse.
	//
	// A Definition whose AllowedSources permits SourcePlainParameter
	// must use a string-shaped T: this server's plain-parameter path
	// (Profile != ProfileFAPISecurityWithMessageSigning) always
	// represents a value as a form-encoded string and re-wraps it as a
	// JSON string claim, so only SourceRequestObject carries a value's
	// native JSON shape (object, array, number, bool) losslessly.
	Extensions *extension.Registry

	// RAR registers every Rich Authorization Requests (RFC 9396) detail
	// type this server accepts in an "authorization_details" parameter,
	// on PAR, CIBA backchannel authentication requests, and
	// client_credentials token requests (RFC 9396 §6). Unlike
	// Extensions, nil is not equivalent to an empty registry accepting
	// nothing extra — it means "authorization_details" itself is
	// rejected outright as an unregistered parameter, the same
	// default-reject stance Extensions takes for any parameter without a
	// matching Definition. A registered RARRegistry's own bounds (total
	// size, nesting depth, per-type object count and size) apply
	// identically to both flows.
	RAR *extension.RARRegistry

	// ClientCredentialsGrant enables the RFC 6749 §4.4 client_credentials
	// grant at the token endpoint — false (the zero value/default)
	// disables it entirely: RequestClientCredentialsToken always fails,
	// and Metadata omits "client_credentials" from
	// grant_types_supported, the same "zero value disables the feature"
	// stance Endpoints.BackchannelAuthentication/MTLSEndpoints/RAR
	// already take. Unlike those, there's no new endpoint or parameter
	// to gate on here — client_credentials arrives at the same token
	// endpoint authorization_code already uses, distinguished only by
	// its own grant_type value — so this is a bare deployment-wide
	// switch. Which individual clients may actually use the grant is a
	// separate, per-client decision
	// (storage.RegisteredClientConfig.AllowsClientCredentialsGrant);
	// enabling it here does not implicitly permit every registered
	// client to use it.
	ClientCredentialsGrant bool

	// OAuthOnly, if set, makes this server a pure OAuth 2.0 + FAPI 2.0
	// authorization server: it never issues an ID token and never
	// advertises OIDC-only Metadata fields (subject_types_supported,
	// id_token_signing_alg_values_supported), regardless of what an
	// individual RegisteredClient's own AllowedScopes says. "openid" is
	// refused as a requested scope at PAR, CIBA and client_credentials
	// alike — see checkScope — so a client can never end up with
	// "openid" in a granted scope for containsScope's own
	// openid-gated branches (issueIDToken and friends) to act on in the
	// first place; this is what lets Metadata's own claims and this
	// server's actual behavior never diverge. False (the default)
	// preserves this package's original behavior exactly: ID token
	// issuance remains driven purely by whether a request's granted
	// scope includes "openid", with no deployment-wide switch at all.
	//
	// Algorithms.IDToken and Limits.IDTokenLifetime are not required
	// when this is true — see their own doc comments.
	OAuthOnly bool

	// Federation configures this server's OpenID Federation 1.0
	// self-issuance — see FederationConfig's own doc comment. Zero
	// value (EntityID empty) disables federation support entirely:
	// EntityConfiguration always fails, matching this package's
	// existing "zero disables the feature" precedent for
	// Endpoints.BackchannelAuthentication and friends.
	Federation FederationConfig

	// AutomaticRegistration configures OpenID Federation 1.0 §12.1
	// "Automatic Registration" — see AutomaticRegistrationConfig's own
	// doc comment. Zero value (TrustAnchors empty) disables it
	// entirely: New never wraps Dependencies.Clients/ClientKeys, and
	// this server behaves exactly as it always has, accepting only
	// statically registered clients. Independent of Federation — a
	// server can self-issue its own Entity Configuration without
	// accepting automatic registration, or vice versa.
	AutomaticRegistration AutomaticRegistrationConfig
}

// AutomaticRegistrationConfig configures this server to accept OpenID
// Federation 1.0 §12.1 "Automatic Registration": a Relying Party that
// presents its own Entity Identifier as client_id, with no prior
// registration step, is resolved on demand via
// federation.AutomaticClientRepository/AutomaticClientKeySource — see
// their own doc comments for exactly which registration shapes are (and
// are not) supported. New wraps Dependencies.Clients and
// Dependencies.ClientKeys with these when TrustAnchors is non-empty;
// every other server internal (PAR, the token endpoint, CIBA) keeps
// calling those same Dependencies fields exactly as before, unaware of
// the wrapping — statically registered clients (the original
// Dependencies.Clients/ClientKeys) always take priority over a
// federation-resolved one.
type AutomaticRegistrationConfig struct {
	// TrustAnchors is every Trust Anchor this server is willing to
	// accept an automatically-registered Relying Party's Trust Chain
	// rooted at — see federation.TrustAnchor. Required (at least one)
	// to enable automatic registration at all.
	TrustAnchors []federation.TrustAnchor

	// AllowedScopes is the scope allowlist granted to every
	// automatically-registered client, uniformly — see
	// federation.AutomaticRegistrationConfig.AllowedScopes for why this
	// deliberately never comes from an RP's own self-published
	// metadata. Required when TrustAnchors is set.
	AllowedScopes []string

	// MaxPathLength/MaxStatementLifetime/MaxClockSkew bound Trust Chain
	// resolution itself — see federation.Limits, which these configure
	// directly. All required when TrustAnchors is set.
	MaxPathLength        int
	MaxStatementLifetime time.Duration
	MaxClockSkew         time.Duration

	// MaxCacheAge bounds how long a resolved client's Trust Chain is
	// reused before it is resolved again — see
	// federation.AutomaticRegistrationConfig.MaxCacheAge. Required when
	// TrustAnchors is set.
	MaxCacheAge time.Duration

	// AllowsClientCredentialsGrant permits every automatically-registered
	// client to use the client_credentials grant — see
	// federation.AutomaticRegistrationConfig.AllowsClientCredentialsGrant
	// for why this is a config-level switch, never inferred from an RP's
	// own metadata. Still also requires Config.ClientCredentialsGrant to
	// be enabled server-wide.
	AllowsClientCredentialsGrant bool

	// AllowsCIBA permits every automatically-registered client to use
	// CIBA — see federation.AutomaticRegistrationConfig.AllowsCIBA for
	// why this is a config-level switch, never inferred from an RP's own
	// metadata.
	AllowsCIBA bool
}

// FederationConfig configures this server's OpenID Federation 1.0
// self-issuance (EntityConfiguration) — the "thin, role-specific glue"
// federation/doc.go describes this server building over
// federation.SelfIssuer. Meaningless (and left unvalidated) when
// EntityID is empty.
type FederationConfig struct {
	// EntityID is this server's own Entity Identifier (OpenID
	// Federation 1.0 §1.2) — see federation.SelfIssueConfig.EntityID.
	// Conventionally the same origin EntityConfiguration's output is
	// served from, at federation.WellKnownPath.
	EntityID string

	// AuthorityHints is this server's own "authority_hints" claim — see
	// federation.SelfIssueConfig.AuthorityHints.
	AuthorityHints []string

	// Lifetime bounds how far in the future EntityConfiguration's own
	// "exp" claim is set, relative to Dependencies.Clock. Required when
	// EntityID is set.
	Lifetime time.Duration

	// Algorithm this server signs its Entity Configuration with.
	// Dependencies.Keys must have a key registered for
	// keys.FederationEntitySigning at this algorithm — a key distinct
	// from every other purpose this server's Keys already serves
	// (JARMSigning, IDTokenSigning, UserInfoSigning), since a
	// federation identity key is never reused as a protocol key.
	// Required when EntityID is set.
	Algorithm fapi.SignatureAlgorithm
}
