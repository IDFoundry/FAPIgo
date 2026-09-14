package keys

import (
	"context"
	"crypto"

	fapi "github.com/idfoundry/fapigo"
)

// VerificationPurpose is a closed set of reasons a client's verification
// key might be resolved, so an implementation can return different keys
// (or apply different trust policy) for different uses of the same
// client's key material.
type VerificationPurpose uint8

const (
	_ VerificationPurpose = iota

	// ClientAssertionVerification resolves a key to verify a
	// private_key_jwt client assertion.
	ClientAssertionVerification

	// RequestObjectVerification resolves a key to verify a signed
	// request object.
	RequestObjectVerification

	// BackchannelAuthenticationRequestVerification resolves a key to
	// verify a client's signed CIBA backchannel authentication request
	// (FAPI-CIBA mandates this always be signed, unlike PAR's request
	// object, which is signed only under some profiles).
	BackchannelAuthenticationRequestVerification

	// AttestationVerification resolves a key to verify a Client
	// Attestation JWT (OAuth 2.0 Attestation-Based Client Authentication
	// draft-07 §5.1). Unlike every other VerificationPurpose, the key
	// this resolves is not the named client's own key — it belongs to
	// the Attester that vouches for the client (storage.RegisteredClient
	// .ExpectedAttesterIssuer), a third party. ClientKeyRequest.ClientID
	// is still the right lookup key: an implementation decides how a
	// given client maps to its trusted Attester's key (e.g. by looking
	// up the client's registered Attester issuer and resolving that
	// issuer's own JWKS), the same way it already decides how to
	// resolve any other purpose's keys — this purpose only distinguishes
	// "which trust relationship" from ClientAssertionVerification's "the
	// client's own key," it doesn't change ClientKeySource's shape.
	AttestationVerification
)

// ClientKeyRequest describes which of a client's verification keys is
// needed. KeyID and Algorithm come from the unverified header of the
// assertion or request object being checked — see, for example,
// clientassertion.Assertion.KeyID, which is documented as safe to use
// only as a lookup key, never as something to trust.
type ClientKeyRequest struct {
	ClientID  fapi.ClientID
	Purpose   VerificationPurpose
	Algorithm fapi.SignatureAlgorithm
	KeyID     string // "" if the token carried no kid
}

// VerificationKey is one candidate verification key for a client. It
// deliberately holds a crypto.PublicKey rather than any JOSE-specific
// type, so an external implementation of ClientKeySource never needs to
// depend on this module's internal JWK representation.
type VerificationKey struct {
	KeyID     string
	Algorithm fapi.SignatureAlgorithm
	PublicKey crypto.PublicKey
}

// VerificationKeySet is the set of keys ResolveVerificationKeys
// returned. Ordinarily this holds exactly one key (selected by KeyID),
// but an implementation may return more than one when a client is
// mid-rotation.
type VerificationKeySet struct {
	Keys []VerificationKey
}

// ClientKeySource resolves a registered client's verification keys.
// Implementations should prefer administratively pre-resolved or
// registered keys over a live JWKS fetch in the request-handling path;
// see the package doc comment for the protections a live fetch must
// apply if one is unavoidable.
type ClientKeySource interface {
	ResolveVerificationKeys(ctx context.Context, req ClientKeyRequest) (VerificationKeySet, error)
}
