package client

import (
	"context"
	"errors"

	"github.com/idfoundry/fapigo/internal/jose"
	"github.com/idfoundry/fapigo/keys"
)

// VerifyIssuerJWS verifies compactJWS as a compact JWS produced by this
// client's configured authorization server, resolved through the same
// cached, rotation-aware Dependencies.IssuerKeys the client itself uses
// to verify an ID token — so a caller never needs a second, unhardened
// key fetch to check an issuer-signed artifact beyond the ID token. It
// is UserInfo-oriented: the key is resolved for
// keys.UserInfoVerification, and it checks the signature against
// Config.Algorithms.UserInfo, never the JWS header's own "alg" — this
// module treats a token's own algorithm header as untrusted input
// everywhere else, and this call is no exception — and returns the
// verified payload bytes unparsed: VerifyIssuerJWS makes no claim about
// what's inside beyond "the issuer signed exactly these bytes". A
// caller still owns checking whatever claims that payload carries (iss,
// aud, sub, expiry, ...) against its own policy.
//
// An issuer may sign several kinds of JWT with one key (ID tokens, JWT
// access tokens, logout tokens, ...), so VerifyIssuerJWS accepts only a
// generic one: a header "typ" that is absent or "JWT" ("application/jwt"
// too, compared case-insensitively), as FetchUserInfo does for a signed
// UserInfo response. A JWS whose typ names an explicitly typed kind —
// "at+jwt", "logout+jwt", "dc+sd-jwt", or any other — is refused with
// ErrorInvalidResponse, so one of those is never taken for the
// artifact a caller expected (RFC 8725 §3.11). A generic JWS still says
// nothing about which kind it is: the payload's claims tell them apart,
// so a caller checks the claims only the kind it expects carries — an
// "aud" naming this client, say, which an access token for a resource
// server doesn't.
func (c *Client) VerifyIssuerJWS(ctx context.Context, compactJWS string) ([]byte, error) {
	parsed, err := c.verifyIssuerJWS(ctx, compactJWS)
	if err != nil {
		return nil, err
	}
	if err := jose.RequireGenericType(parsed.Header.Type); err != nil {
		return nil, newError(ErrorInvalidResponse, "JWS is an explicitly typed kind of JWT", err)
	}
	return parsed.Payload, nil
}

// verifyIssuerJWS is VerifyIssuerJWS, returning the verified JWS whole
// so a caller can also check its header.
func (c *Client) verifyIssuerJWS(ctx context.Context, compactJWS string) (jose.Compact, error) {
	parsed, err := jose.ParseCompactMax(compactJWS, c.cfg.Limits.MaxJOSECompactBytes)
	if err != nil {
		if errors.Is(err, jose.ErrTooLarge) {
			return jose.Compact{}, newError(ErrorResponseTooLarge, "JWS exceeds the configured size limit", err)
		}
		return jose.Compact{}, newError(ErrorInvalidResponse, "malformed JWS", err)
	}

	candidates, idErr := c.resolveIssuerKeyCandidates(ctx, keys.UserInfoVerification, c.cfg.Algorithms.UserInfo, parsed.Header.KeyID)
	if idErr != nil {
		return jose.Compact{}, idErr
	}

	var verifyErr error
	for _, candidate := range candidates {
		if verifyErr = parsed.Verify(candidate.PublicKey, c.cfg.Algorithms.UserInfo); verifyErr == nil {
			return parsed, nil
		}
	}
	return jose.Compact{}, newError(ErrorInvalidResponse, "JWS verification failed", verifyErr)
}
