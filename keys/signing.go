package keys

import (
	"context"
	"crypto"

	fapi "github.com/idfoundry/fapigo"
)

// SigningPurpose is a closed set of reasons a party might need to sign
// something with its own key, so an implementation can select different
// keys (or apply different rotation/HSM policy) per purpose. The first
// four are server purposes; the last four are client purposes — both
// roles use the same KeyManager contract (see ARCHITECTURE.md design
// rule 5), never a crypto.Signer or raw private key.
type SigningPurpose uint8

const (
	_ SigningPurpose = iota

	// JARMSigning signs a JWT Secured Authorization Response.
	JARMSigning

	// AccessTokenSigning signs a JWT access token (RFC 9068).
	AccessTokenSigning

	// IDTokenSigning signs an OIDC ID token.
	IDTokenSigning

	// UserInfoSigning signs a UserInfo response (OIDC Core §5.3.2).
	UserInfoSigning

	// ClientAuthentication signs a private_key_jwt client assertion.
	ClientAuthentication

	// RequestObjectSigning signs a pushed authorization request object
	// (RFC 9101).
	RequestObjectSigning

	// DPoPProofSigning signs a DPoP proof (RFC 9449).
	DPoPProofSigning

	// BackchannelAuthenticationRequestSigning signs a client's CIBA
	// backchannel authentication request (CIBA §7.1) — kept distinct
	// from RequestObjectSigning even though both produce a
	// structurally similar signed JWT, since a deployment may
	// reasonably want a different key/HSM policy for a
	// backend-initiated CIBA flow than for a browser-adjacent PAR
	// request object.
	BackchannelAuthenticationRequestSigning
)

// SigningRequest describes one signature to produce. Exactly one of
// Digest or SigningInput is populated, chosen by Algorithm — never
// both, and an implementation should treat the other as absent rather
// than guess:
//
//   - Digest, for ES256/PS256: the pre-hashed signing input. This
//     module always hashes before calling Sign for these algorithms,
//     so an HSM- or remote-signing-service-backed implementation never
//     receives more of the plaintext than it needs.
//   - SigningInput, for EdDSA: the raw, unhashed JWS Signing Input.
//     RFC 8037 §3.1 requires pure EdDSA over the actual message, not a
//     digest of it — there is no equivalent "pre-hash so the
//     implementation sees less" option for this algorithm, so an
//     EdDSA-capable implementation necessarily receives the full
//     plaintext being signed. An implementation that hasn't been
//     updated to handle EdDSA sees an empty Digest for such a request
//     (not a wrong or insecure signature over the wrong bytes) and
//     should fail closed.
type SigningRequest struct {
	Purpose      SigningPurpose
	Algorithm    fapi.SignatureAlgorithm
	Digest       []byte
	SigningInput []byte
}

// NewSigningRequest builds a SigningRequest for purpose/algorithm,
// routing digestOrMessage into Digest or SigningInput as
// SigningRequest's own doc comment requires. It exists so every
// crypto.Signer-over-KeyManager adapter (client and server each keep
// their own private one) shares this one dispatch rather than
// reimplementing it — the routing decision belongs with the type it
// populates, not with each adapter that happens to call Sign.
func NewSigningRequest(purpose SigningPurpose, algorithm fapi.SignatureAlgorithm, digestOrMessage []byte) SigningRequest {
	req := SigningRequest{Purpose: purpose, Algorithm: algorithm}
	if algorithm == fapi.EdDSA {
		req.SigningInput = digestOrMessage
	} else {
		req.Digest = digestOrMessage
	}
	return req
}

// Signature is the result of a Sign call. Value must be in the format
// Go's crypto.Signer contract specifies for the algorithm's key type —
// in particular, ASN.1 DER for an ECDSA signature, not the fixed-width
// R||S concatenation JWS uses on the wire. This module's JOSE layer
// performs that conversion itself; an implementation of KeyManager
// should produce exactly what a stdlib *ecdsa.PrivateKey or *rsa.PrivateKey
// would from Sign, since that is the contract this module's internal
// crypto.Signer adapter relies on. For EdDSA, Value is simpler: an
// ed25519.PrivateKey's Sign output is already the 64-byte wire format
// RFC 8037 wants, with no equivalent DER-to-fixed-width conversion
// needed.
type Signature struct {
	KeyID string
	Value []byte
}

// PublicKeyInfo identifies the public half of the key a given purpose
// and algorithm currently sign with.
type PublicKeyInfo struct {
	KeyID     string
	PublicKey crypto.PublicKey
}

// KeyManager performs the server's own signing operations. It never
// returns a crypto.Signer or a private key — only a Sign operation and
// the corresponding public key — so an HSM- or remote-signing-service-
// backed implementation never has to hand private key material into
// this process.
type KeyManager interface {
	// Sign produces a signature over req.Digest or req.SigningInput
	// (see SigningRequest's own doc comment for which one, and why)
	// using the key currently designated for req.Purpose and
	// req.Algorithm.
	Sign(ctx context.Context, req SigningRequest) (Signature, error)

	// PublicKey returns the public key (and its kid) currently
	// designated for purpose and algorithm, so a caller can construct a
	// crypto.Signer-shaped adapter for this module's JOSE plumbing
	// without ever holding the private key itself.
	PublicKey(ctx context.Context, purpose SigningPurpose, algorithm fapi.SignatureAlgorithm) (PublicKeyInfo, error)
}

// SigningKeySet is the set of keys currently valid for a signing
// purpose and algorithm — ordinarily exactly one, but more than one
// during a rotation's overlap window. Mirrors VerificationKeySet's (and
// IssuerKeySet's, and ClientEncryptionKeySet's) own "may return more
// than one when mid-rotation" contract, applied to this party's own
// keys rather than a remote party's.
type SigningKeySet struct {
	Keys []PublicKeyInfo
}

// RotatingKeyManager is KeyManager's optional extension for a backend
// that can publish more than one currently-valid key per purpose during
// a rotation's overlap window — e.g. a KMS alias briefly holding both
// an outgoing and incoming key version, or an embedder-managed grace
// period after cutting to a new key. Sign is unaffected by this: it
// always signs with whatever single key the implementation currently
// considers active; only publication needs the wider set, so this is
// additive to KeyManager, never a replacement for anything KeyManager
// itself declares. A KeyManager that only ever has one key per purpose
// (keys/ephemeral, NewKeyManagerFromSigners) has no reason to implement
// this — server.PublicJWKS falls back to PublicKey when it isn't
// implemented.
type RotatingKeyManager interface {
	KeyManager

	// PublicKeys returns every key currently valid for purpose and
	// algorithm — normally the single key PublicKey would also return,
	// but more than one while a rotation is in its overlap window, so a
	// verifier can still validate a signature made under the outgoing
	// key until every such signature has expired.
	PublicKeys(ctx context.Context, purpose SigningPurpose, algorithm fapi.SignatureAlgorithm) (SigningKeySet, error)
}
