package jarm

import (
	"crypto"
	"encoding/json"
	"fmt"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/jose"
)

// Response is a parsed, but not yet signature-verified, JARM response.
// KeyID, Algorithm, ClaimedIssuer and Parameter are available before
// Verify succeeds so a caller can look up which key to verify against —
// that is a safe use of unverified data, since it only selects what to
// check against, not what to trust. Nothing from Response, including an
// apparent error parameter, should be acted on until Verify returns a
// VerifiedResponse: an unverified "error" claim is exactly as
// untrustworthy as an unverified "code" claim.
type Response struct {
	compact jose.Compact
	claims  Claims
}

// Parse parses a JARM response without verifying its signature.
func Parse(token string) (Response, error) {
	compact, err := jose.ParseCompact(token)
	if err != nil {
		return Response{}, fmt.Errorf("jarm: %w", err)
	}
	claims, err := parseClaims(compact.Payload)
	if err != nil {
		return Response{}, err
	}
	return Response{compact: compact, claims: claims}, nil
}

// KeyID returns the response header's "kid", or "" if absent. Untrusted
// until Verify succeeds; use only to select which key to verify against.
func (r Response) KeyID() string { return r.compact.Header.KeyID }

// Algorithm returns the algorithm the response header claims to use.
// Untrusted until Verify succeeds — callers must still supply the
// algorithm they expect via VerifyPolicy rather than trusting this
// value, exactly as jose.Compact.Verify requires.
func (r Response) Algorithm() fapi.SignatureAlgorithm { return r.compact.Header.Algorithm }

// ClaimedIssuer returns the response's unverified "iss" claim, for use
// as a key-lookup hint only.
func (r Response) ClaimedIssuer() string { return r.claims.Issuer }

// Parameter returns the unverified authorization response parameter
// named name. Nothing derived from it — including an "error" or "code"
// parameter — should be acted on until Verify succeeds.
func (r Response) Parameter(name string) (json.RawMessage, bool) {
	v, ok := r.claims.Parameters[name]
	return v, ok
}

// VerifyPolicy is the set of checks Verify enforces against a Response.
type VerifyPolicy struct {
	// ExpectedIssuer is the authorization server the caller expects this
	// response to have come from. The response's iss claim must equal
	// it exactly.
	ExpectedIssuer string

	// ExpectedAudience is the caller's own client ID. The response's aud
	// claim must equal it exactly.
	ExpectedAudience string

	// Algorithm is the algorithm this authorization server is registered
	// (or discovered) to sign JARM responses with. The response header's
	// algorithm must equal it exactly — this is what prevents
	// algorithm-confusion attacks, so it must come from the server's
	// metadata, never from the response itself.
	Algorithm fapi.SignatureAlgorithm

	// Now is the time to validate exp/nbf against.
	Now time.Time

	// MaxLifetime bounds how far in the future (relative to Now) the
	// response's exp claim may be. Required — there is no implicit
	// default.
	MaxLifetime time.Duration

	// MaxClockSkew bounds how far in the future (relative to Now) an nbf
	// claim may be, and extends how long past exp a response is still
	// accepted. Zero means no tolerance.
	MaxClockSkew time.Duration
}

// VerifiedResponse is what remains once a JARM response has been
// verified: the issuer it came from and the authorization response
// parameters it carried. Correlating those parameters against the
// authorization attempt they belong to (state, PKCE, expected redirect
// URI) is the caller's responsibility — see storage.SessionStore.
type VerifiedResponse struct {
	Issuer     string
	Parameters map[string]json.RawMessage
	ExpiresAt  time.Time
}

// Verify checks r's signature against pub and its claims against policy.
func (r Response) Verify(pub crypto.PublicKey, policy VerifyPolicy) (VerifiedResponse, error) {
	if policy.ExpectedIssuer == "" {
		return VerifiedResponse{}, fmt.Errorf("jarm: ExpectedIssuer is empty")
	}
	if policy.ExpectedAudience == "" {
		return VerifiedResponse{}, fmt.Errorf("jarm: ExpectedAudience is empty")
	}
	if policy.Now.IsZero() {
		return VerifiedResponse{}, fmt.Errorf("jarm: Now is zero")
	}
	if policy.MaxLifetime <= 0 {
		return VerifiedResponse{}, fmt.Errorf("jarm: MaxLifetime must be positive")
	}

	if err := r.compact.Verify(pub, policy.Algorithm); err != nil {
		return VerifiedResponse{}, fmt.Errorf("jarm: %w", err)
	}
	c := r.claims

	if c.Issuer != policy.ExpectedIssuer {
		return VerifiedResponse{}, ErrIssuerMismatch
	}
	if c.Audience != policy.ExpectedAudience {
		return VerifiedResponse{}, ErrAudienceMismatch
	}

	if policy.Now.After(c.ExpiresAt.Add(policy.MaxClockSkew)) {
		return VerifiedResponse{}, ErrExpired
	}
	if c.ExpiresAt.Sub(policy.Now) > policy.MaxLifetime {
		return VerifiedResponse{}, ErrLifetimeExceeded
	}
	if !c.NotBefore.IsZero() && policy.Now.Before(c.NotBefore.Add(-policy.MaxClockSkew)) {
		return VerifiedResponse{}, ErrNotYetValid
	}

	// A validly signed, correctly-audienced JWT from the expected issuer
	// isn't necessarily a JARM response — an AS-signed ID token for the
	// same client would also pass every check above. Requiring at least
	// one recognised authorization-response parameter distinguishes a
	// genuine JARM response without depending on "typ", which the spec
	// doesn't mandate.
	if _, hasCode := c.Parameters["code"]; !hasCode {
		if _, hasErr := c.Parameters["error"]; !hasErr {
			return VerifiedResponse{}, ErrNotAuthorizationResponse
		}
	}

	return VerifiedResponse{Issuer: c.Issuer, Parameters: c.Parameters, ExpiresAt: c.ExpiresAt}, nil
}
