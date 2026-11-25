package client

import (
	"context"
	"crypto"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/keys"
)

// maxIssuerKeyCandidates bounds how many of the authorization server's
// keys a JWS it signed is tried against: every key Dependencies.IssuerKeys
// returns for the JWS's algorithm when it names no "kid", or for the
// "kid" it names. A conforming issuer's JWS has a single candidate:
// OpenID Connect Core §10.1 requires a "kid" once the JWK Set holds more
// than one key, and FAPI 2.0 Security Profile §5.4.2 says no two keys
// should share one. A rotation without distinct kids needs a few. Each
// candidate costs a signature verification, made before anything the
// JWS says can be trusted, so a JWK Set listing many keys for one
// algorithm would make every forged JWS cost one verification per key:
// past the bound, the rest are never tried. Package server bounds the
// keys it tries for a client the same way.
const maxIssuerKeyCandidates = 8

// resolveIssuerKeyCandidates resolves the authorization server's keys
// that may have signed a JWS with algorithm and keyID (its unverified
// "kid"), for purpose: at most maxIssuerKeyCandidates of them, in the
// order Dependencies.IssuerKeys returned them. what names the JWS in
// errors. verifyIssuerSigned uses it for every check of something the
// issuer signed (a JARM response, an ID token, and, via VerifyIssuerJWS,
// any other artifact a caller asks about), so "resolution failed" and
// "no matching key" are handled in one place. A key that is also one of
// the issuer's federation entity keys is never a candidate (see
// refuseEntityKeys).
func (c *Client) resolveIssuerKeyCandidates(ctx context.Context, what string, purpose keys.IssuerVerificationPurpose, algorithm fapi.SignatureAlgorithm, keyID string) ([]keys.IssuerKey, *Error) {
	if c.deps.IssuerKeys == nil {
		return nil, newError(ErrorInternal, "no issuer keys configured (Dependencies.IssuerKeys is nil, which Config.OAuthOnly permits only when nothing issuer-signed is verified)", nil)
	}
	set, err := c.deps.IssuerKeys.ResolveIssuerKeys(ctx, keys.IssuerKeyRequest{
		Issuer: c.cfg.Issuer.String(), Purpose: purpose, Algorithm: algorithm, KeyID: keyID,
	})
	if err != nil {
		return nil, newError(ErrorInternal, "failed to resolve issuer keys", err)
	}
	candidates, dropped := c.refuseEntityKeys(set.Keys)
	if len(candidates) == 0 {
		if dropped {
			return nil, newError(ErrorInvalidResponse, "the issuer's only matching key for "+what+" is one of its federation entity keys, which are never protocol keys", nil)
		}
		return nil, newError(ErrorInvalidResponse, "no matching issuer key for "+what, nil)
	}
	return candidates[:min(len(candidates), maxIssuerKeyCandidates)], nil
}

// verifyIssuerSigned checks a JWS the authorization server signed (what
// names it in errors) by calling verify with each of the issuer's
// candidate keys for purpose, algorithm and keyID
// (resolveIssuerKeyCandidates) in turn, until one succeeds. When none
// does, it fails with ErrorInvalidResponse, wrapping the last one's
// error. It checks ctx before each candidate: once ctx is done it tries
// no more and fails with ErrorInternal, wrapping ctx's error, so a
// caller that has given up costs no more signature verifications.
func (c *Client) verifyIssuerSigned(ctx context.Context, what string, purpose keys.IssuerVerificationPurpose, algorithm fapi.SignatureAlgorithm, keyID string, verify func(crypto.PublicKey) error) *Error {
	candidates, keyErr := c.resolveIssuerKeyCandidates(ctx, what, purpose, algorithm, keyID)
	if keyErr != nil {
		return keyErr
	}
	var verifyErr error
	for _, candidate := range candidates {
		if err := ctx.Err(); err != nil {
			return newError(ErrorInternal, "stopped verifying the "+what+": the context is done", err)
		}
		if verifyErr = verify(candidate.PublicKey); verifyErr == nil {
			return nil
		}
	}
	return newError(ErrorInvalidResponse, what+" verification failed", verifyErr)
}
