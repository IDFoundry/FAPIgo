package client

import (
	"context"
	"math"
	"strings"
	"time"
)

// RefreshTokenRequest is the input to Client.RefreshTokens.
type RefreshTokenRequest struct {
	// Tokens is the TokenSet whose refresh token is redeemed — from
	// ExchangeCode, a backchannel authentication, or an earlier
	// RefreshTokens. Its ID token claims, if it has any, are what a
	// refreshed ID token is checked against.
	Tokens TokenSet

	// Scope, if set, narrows the new access token to these scopes (RFC
	// 6749 §6). It can't widen the original grant: the server refuses
	// a scope it didn't grant.
	Scope []string
}

// RefreshTokens redeems req.Tokens' refresh token (RFC 6749 §6) for a
// new access token, authenticating to the token endpoint and, under
// SenderConstrainDPoP, presenting a DPoP proof the new access token is
// bound to — whichever DPoP key Dependencies.Keys holds now, so a client
// that rotated its DPoP key gets a token bound to the new one.
//
// The result's RefreshToken is the one the server returned or, when it
// returned none, req.Tokens' own: under FAPI 2.0 the server doesn't
// rotate refresh tokens, so the same one keeps working until it expires
// or is revoked. Likewise, when the server returned no ID token, the
// result keeps req.Tokens' (IDToken, Subject and IDTokenClaims), so a
// later refresh from it still has the original to check against.
//
// req.Tokens must have come from this client's issuer (TokenSet.Issuer,
// or for a set without one, its ID token's iss): a set from another
// issuer, or one recording no issuer at all, is refused before anything
// is sent, so one issuer's refresh token is never presented to another.
//
// A returned ID token is validated as ExchangeCode validates one, and
// checked against the original (OIDC Core §12.2): the same sub, the same
// auth_time when present (the time of the original authentication, not
// of the refresh), and the same azp. No nonce is expected: a refreshed
// ID token has none to match.
func (c *Client) RefreshTokens(ctx context.Context, req RefreshTokenRequest) (TokenSet, error) {
	if !req.Tokens.HasRefreshToken || req.Tokens.RefreshToken.Reveal() == "" {
		return TokenSet{}, newError(ErrorInvalidRequest, "the token set has no refresh token", nil)
	}
	if iss := tokenSetIssuer(req.Tokens); iss != c.cfg.Issuer.String() {
		if iss == "" {
			return TokenSet{}, newError(ErrorInvalidRequest, "the token set doesn't record its issuer (TokenSet.Issuer)", nil)
		}
		return TokenSet{}, newError(ErrorInvalidRequest, "the token set was issued by a different issuer than this client's", nil)
	}
	if req.Tokens.HasIDToken && req.Tokens.IDTokenClaims.Issuer != c.cfg.Issuer.String() {
		return TokenSet{}, newError(ErrorInvalidRequest, "the token set's ID token was issued by a different issuer than this client's", nil)
	}
	assertionSigner, assertionKID, dpopSigner, err := c.resolveClientAuthAndDPoPSigners(ctx)
	if err != nil {
		return TokenSet{}, newError(ErrorInternal, "failed to resolve signing keys", err)
	}
	tokenURL := c.cfg.Endpoints.Token.URL()

	params := map[string]string{
		"grant_type":    "refresh_token",
		"refresh_token": req.Tokens.RefreshToken.Reveal(),
	}
	if len(req.Scope) > 0 {
		params["scope"] = strings.Join(req.Scope, " ")
	}
	buildTokenForm := c.tokenFormBuilder(ctx, params, assertionSigner, assertionKID)
	form, headers, err := buildTokenForm()
	if err != nil {
		return TokenSet{}, newError(ErrorInternal, "failed to build client assertion", err)
	}
	body, tokenErr := c.sendTokenRequest(ctx, dpopSigner, &tokenURL, buildTokenForm, form, headers)
	if tokenErr != nil {
		return TokenSet{}, tokenErr
	}
	// No nonce: a refreshed ID token has none to match.
	result, idErr := c.tokenSetFromResponse(ctx, body, "")
	if idErr != nil {
		return TokenSet{}, idErr
	}
	if !result.HasRefreshToken {
		result.RefreshToken, result.HasRefreshToken = req.Tokens.RefreshToken, true
	}
	if !result.HasIDToken {
		result.IDToken, result.HasIDToken = req.Tokens.IDToken, req.Tokens.HasIDToken
		result.Subject, result.IDTokenClaims = req.Tokens.Subject, req.Tokens.IDTokenClaims
		return result, nil
	}
	if idErr := checkRefreshedIDToken(req.Tokens, result.IDTokenClaims); idErr != nil {
		return TokenSet{}, idErr
	}
	return result, nil
}

// checkRefreshedIDToken applies OIDC Core §12.2's comparisons of a
// refreshed ID token with the one the original authentication issued —
// iss and aud are already checked against this client's own
// configuration. With no original ID token to compare with, there is
// nothing to check here.
func checkRefreshedIDToken(original TokenSet, refreshed IDTokenClaims) *Error {
	if !original.HasIDToken {
		return nil
	}
	was := original.IDTokenClaims
	switch {
	case refreshed.Subject != was.Subject:
		return newError(ErrorInvalidResponse, "refreshed ID token's sub differs from the original ID token's", nil)
	case !refreshed.AuthTime.IsZero() && !refreshed.AuthTime.Equal(was.AuthTime):
		return newError(ErrorInvalidResponse, "refreshed ID token's auth_time differs from the original authentication's", nil)
	case refreshed.AZP != was.AZP:
		return newError(ErrorInvalidResponse, "refreshed ID token's azp differs from the original ID token's", nil)
	}
	return nil
}

// tokenSetIssuer is the issuer t came from: its Issuer, or, for a set
// that doesn't record one (built by hand, or kept from before the field
// existed), its ID token's verified iss; "" when it has neither.
func tokenSetIssuer(t TokenSet) string {
	if t.Issuer != "" {
		return t.Issuer
	}
	if t.HasIDToken {
		return t.IDTokenClaims.Issuer
	}
	return ""
}

// maxExpiresInSeconds is the largest expires_in, in seconds, that fits
// a time.Duration.
const maxExpiresInSeconds = int64(math.MaxInt64 / int64(time.Second))

// expiresInDuration converts a token response's positive expires_in, in
// seconds, to a Duration, clamping a value too large to represent
// rather than letting it overflow into a negative or small one.
func expiresInDuration(seconds int64) time.Duration {
	if seconds > maxExpiresInSeconds {
		return time.Duration(maxExpiresInSeconds) * time.Second
	}
	return time.Duration(seconds) * time.Second
}
