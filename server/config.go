package server

import (
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/extension"
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
}
