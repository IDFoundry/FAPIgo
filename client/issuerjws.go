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
// key fetch to check an issuer-signed artifact beyond the ID token (a
// UserInfo response, most commonly). It checks the signature against
// Config.Algorithms.UserInfo, never the JWS header's own "alg" — this
// module treats a token's own algorithm header as untrusted input
// everywhere else, and this call is no exception — and returns the
// verified payload bytes unparsed: VerifyIssuerJWS makes no claim about
// what's inside beyond "the issuer signed exactly these bytes". A
// caller still owns checking whatever claims that payload carries (iss,
// aud, sub, expiry, ...) against its own policy.
func (c *Client) VerifyIssuerJWS(ctx context.Context, compactJWS string) ([]byte, error) {
	parsed, err := jose.ParseCompactMax(compactJWS, c.cfg.Limits.MaxJOSECompactBytes)
	if err != nil {
		if errors.Is(err, jose.ErrTooLarge) {
			return nil, newError(ErrorResponseTooLarge, "JWS exceeds the configured size limit", err)
		}
		return nil, newError(ErrorInvalidResponse, "malformed JWS", err)
	}

	candidates, idErr := c.resolveIssuerKeyCandidates(ctx, keys.UserInfoVerification, c.cfg.Algorithms.UserInfo, parsed.Header.KeyID)
	if idErr != nil {
		return nil, idErr
	}

	var verifyErr error
	for _, candidate := range candidates {
		if verifyErr = parsed.Verify(candidate.PublicKey, c.cfg.Algorithms.UserInfo); verifyErr == nil {
			return parsed.Payload, nil
		}
	}
	return nil, newError(ErrorInvalidResponse, "JWS verification failed", verifyErr)
}
