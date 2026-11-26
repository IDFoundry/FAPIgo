package keys

import (
	"context"
	"crypto"

	fapi "github.com/idfoundry/fapigo"
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

	// UserInfoVerification resolves a key to verify an issuer-signed
	// artifact via client.VerifyIssuerJWS — most commonly a signed (or
	// signed-then-encrypted) UserInfo response (OIDC Core §5.3.2).
	UserInfoVerification
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

// IssuerKeySet is the set of keys ResolveIssuerKeys returned, in the
// order a verifier should try them. For a request naming a KeyID it
// ordinarily holds the one key with that ID, or a few while the issuer
// rotates keys under one ID. For a request naming none (a JWS whose
// header has no "kid") it holds every key of the algorithm:
// JWKSIssuerKeySource returns as many as the issuer's JWK Set lists.
// This module's verifiers that take an IssuerKeySource try them in
// order up to a bound, and never a key past it: package client tries
// at most eight, and resource.JWTAccessTokens at most its
// MaxKeyCandidates.
type IssuerKeySet struct {
	Keys []IssuerKey
}

// IssuerKeySource resolves an authorization server's public
// verification keys — used by client to verify JARM responses, ID
// tokens and signed UserInfo responses, and by resource to verify JWT
// access tokens.
// Implementations should prefer a cached or administratively
// pre-resolved key set over a live JWKS fetch in the request-handling
// path; where a live fetch is unavoidable it must apply the same SSRF,
// size-limit, content-type, bounded-redirect and stale-key protections
// as any other outbound fetch — see ARCHITECTURE.md, design rule 6.
type IssuerKeySource interface {
	ResolveIssuerKeys(ctx context.Context, req IssuerKeyRequest) (IssuerKeySet, error)
}

// IssuerBound is the optional interface an IssuerKeySource implements
// when it serves one issuer's keys only. BoundIssuer returns that
// issuer identifier, or "" when the source isn't bound to one and serves
// any issuer that asks.
//
// It lets a verifier refuse a misconfiguration up front:
// client.New and resource.NewVerifier (and resource.NewJWTAccessTokens)
// refuse a source whose BoundIssuer is set and isn't, exactly, the
// issuer they are configured for, since such a source refuses every one
// of that issuer's lookups and so could never verify anything it signed.
// A source that doesn't implement IssuerBound, or returns "", is
// accepted as before, and is then trusted to serve the right issuer's
// keys: a source shared between verifiers of different issuers must be
// bound, or it hands one issuer's keys to a check of another's.
// LocalIssuerKeys is always bound; JWKSIssuerKeySource is bound when
// built WithIssuer.
//
// Like KeySourceAssurance, a declaration describes the declaring type's
// own behaviour, and a type embedding a bound source inherits it. A
// wrapper that changes which issuers it answers for must override
// BoundIssuer to match.
type IssuerBound interface {
	BoundIssuer() string
}
