package keys

import (
	"context"
	"crypto"

	fapi "github.com/osanderson/go-fapi"
)

// IssuerVerificationPurpose is a closed set of reasons an authorization
// server's verification key might be resolved, so an implementation can
// return different keys (or apply different trust policy) for different
// uses of the same issuer's key material — mirroring
// VerificationPurpose's role for ClientKeyRequest.
type IssuerVerificationPurpose uint8

const (
	_ IssuerVerificationPurpose = iota

	// AccessTokenVerification resolves a key to verify a JWT access token
	// (RFC 9068) — used by resource.
	AccessTokenVerification

	// JARMVerification resolves a key to verify a JWT Secured
	// Authorization Response — used by client.
	JARMVerification

	// IDTokenVerification resolves a key to verify an OIDC ID token —
	// used by client.
	IDTokenVerification
)

// IssuerKeyRequest describes which of an authorization server's signing
// keys the caller needs to verify against. Issuer and Algorithm must be
// values the caller already trusts and expects — the server's
// registered issuer identifier and signing algorithm — never values
// read from the unverified token being checked. KeyID comes from the
// token's own (unverified) header and is safe to use only as a lookup
// hint, exactly like ClientKeyRequest.KeyID.
type IssuerKeyRequest struct {
	Issuer    string
	Purpose   IssuerVerificationPurpose
	Algorithm fapi.SignatureAlgorithm
	KeyID     string
}

// IssuerKey is one candidate verification key for an authorization
// server. It deliberately holds a crypto.PublicKey rather than any
// JOSE-specific type, for the same reason as VerificationKey.
type IssuerKey struct {
	KeyID     string
	Algorithm fapi.SignatureAlgorithm
	PublicKey crypto.PublicKey
}

// IssuerKeySet is the set of keys ResolveIssuerKeys returned.
// Ordinarily this holds exactly one key (selected by KeyID), but an
// implementation may return more than one when the issuer is
// mid-rotation.
type IssuerKeySet struct {
	Keys []IssuerKey
}

// IssuerKeySource resolves an authorization server's public
// verification keys — used by resource to verify access tokens and, in
// future, by client to verify JARM responses and ID tokens.
// Implementations should prefer a cached or administratively
// pre-resolved key set over a live JWKS fetch in the request-handling
// path; where a live fetch is unavoidable it must apply the same SSRF,
// size-limit, content-type, bounded-redirect and stale-key protections
// as any other outbound fetch — see ARCHITECTURE.md, design rule 6.
type IssuerKeySource interface {
	ResolveIssuerKeys(ctx context.Context, req IssuerKeyRequest) (IssuerKeySet, error)
}
