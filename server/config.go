package server

import (
	"time"

	fapi "github.com/osanderson/go-fapi"
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

	// AccessToken is the single algorithm this server signs JWT access
	// tokens with.
	AccessToken fapi.SignatureAlgorithm

	// IDToken is the single algorithm this server signs ID tokens with.
	IDToken fapi.SignatureAlgorithm
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
}
