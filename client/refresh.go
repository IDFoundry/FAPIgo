package client

import (
	"context"
	"math"
	"slices"
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

	// Resource, if set, narrows the new access token to these resource
	// servers (RFC 8707 §2.2), each one of Tokens.Resource: anything
	// else is refused before a request is sent. Left empty, the refresh
	// names all of Tokens.Resource again. The result's Resource is the
	// resources this refresh named.
	Resource []string
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
// aud (when the original records one), the same auth_time when present
// (the time of the original authentication, not of the refresh), the
// same azp (none when the original had none), and, when it carries a
// nonce at all — it SHOULD NOT — the original's nonce.
func (c *Client) RefreshTokens(ctx context.Context, req RefreshTokenRequest) (TokenSet, error) {
	if err := c.checkTrustChain(); err != nil {
		return TokenSet{}, err
	}
	if !req.Tokens.HasRefreshToken || req.Tokens.RefreshToken.Reveal() == "" {
		return TokenSet{}, newError(ErrorInvalidRequest, "the token set has no refresh token", nil)
	}
	if issuerErr := c.checkTokenSetIssuer(req.Tokens); issuerErr != nil {
		return TokenSet{}, issuerErr
	}
	assertionSigner, assertionKID, dpopSigner, err := c.resolveClientAuthAndDPoPSigners(ctx)
	if err != nil {
		return TokenSet{}, newError(ErrorInternal, "failed to resolve signing keys", err)
	}
	tokenURL := c.cfg.Endpoints.Token.URL()

	params, resources, paramsErr := refreshParameters(req)
	if paramsErr != nil {
		return TokenSet{}, paramsErr
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
	// No nonce to expect here: a refreshed ID token SHOULD carry none,
	// and checkRefreshedIDToken compares one it does carry with the
	// original's.
	result, idErr := c.tokenSetFromResponse(ctx, body, "")
	if idErr != nil {
		return TokenSet{}, idErr
	}
	result.Resource = slices.Clone(resources)
	// RFC 6749 §6: a refresh request without scope asks for the
	// original grant's.
	if len(req.Scope) > 0 {
		result.Scope = grantedScope(result.Scope, req.Scope)
	} else if result.Scope == "" {
		result.Scope = req.Tokens.Scope
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

// refreshParameters is the token request parameters for req, before
// client authentication, and the resource indicators among them (RFC
// 8707 §2.2): req.Resource when it narrows, req.Tokens.Resource
// otherwise.
func refreshParameters(req RefreshTokenRequest) (map[string]string, []string, *Error) {
	params := map[string]string{
		"grant_type":    "refresh_token",
		"refresh_token": req.Tokens.RefreshToken.Reveal(),
	}
	if len(req.Scope) > 0 {
		if err := checkScopeTokens(req.Scope); err != nil {
			return nil, nil, err
		}
		params["scope"] = strings.Join(req.Scope, " ")
	}
	if resourceErr := checkResources(req.Tokens.Resource); resourceErr != nil {
		return nil, nil, resourceErr
	}
	resources := req.Tokens.Resource
	if len(req.Resource) > 0 {
		if subsetErr := checkResourceSubset(req.Resource, req.Tokens.Resource); subsetErr != nil {
			return nil, nil, subsetErr
		}
		resources = req.Resource
	}
	setResources(params, resources)
	return params, resources, nil
}

// checkRefreshedIDToken applies OIDC Core §12.2's comparisons of a
// refreshed ID token with the one the original authentication issued —
// iss is already checked against this client's own configuration, and
// aud against its client_id. aud is compared as a set, and only when
// the original records one (a TokenSet built by hand may not). A nonce
// SHOULD be absent; a present one MUST equal the original's, so one the
// original didn't carry fails. With no original ID token to compare
// with, there is nothing to check here.
func checkRefreshedIDToken(original TokenSet, refreshed IDTokenClaims) *Error {
	if !original.HasIDToken {
		return nil
	}
	was := original.IDTokenClaims
	switch {
	case refreshed.Subject != was.Subject:
		return newError(ErrorInvalidResponse, "refreshed ID token's sub differs from the original ID token's", nil)
	case len(was.Audience) > 0 && !sameStringSet(refreshed.Audience, was.Audience):
		return newError(ErrorInvalidResponse, "refreshed ID token's aud differs from the original ID token's", nil)
	case refreshed.Nonce != "" && refreshed.Nonce != was.Nonce:
		return newError(ErrorInvalidResponse, "refreshed ID token's nonce differs from the original ID token's", nil)
	case !refreshed.AuthTime.IsZero() && !refreshed.AuthTime.Equal(was.AuthTime):
		return newError(ErrorInvalidResponse, "refreshed ID token's auth_time differs from the original authentication's", nil)
	case refreshed.AZP != was.AZP:
		return newError(ErrorInvalidResponse, "refreshed ID token's azp differs from the original ID token's", nil)
	}
	return nil
}

// sameStringSet reports whether a and b hold the same values, in any
// order.
func sameStringSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	sa, sb := slices.Clone(a), slices.Clone(b)
	slices.Sort(sa)
	slices.Sort(sb)
	return slices.Equal(sa, sb)
}

// grantedScope is a token response's scope: as it says, or, when it
// omits "scope", the scope requested (RFC 6749 §5.1: scope is
// "OPTIONAL, if identical to the scope requested by the client").
func grantedScope(responseScope string, requested []string) string {
	if responseScope != "" {
		return responseScope
	}
	return strings.Join(requested, " ")
}

// checkTokenSetIssuer refuses a token set this client's authorization
// server didn't issue: one whose Issuer (or, without it, its ID token's
// verified iss) isn't Config.Issuer, or whose ID token another issuer
// signed. A multi-issuer application holds sets from several, and one
// issuer's tokens must never reach another's endpoints, nor another's
// claims be taken as this one's.
func (c *Client) checkTokenSetIssuer(t TokenSet) *Error {
	if iss := tokenSetIssuer(t); iss != c.cfg.Issuer.String() {
		if iss == "" {
			return newError(ErrorInvalidRequest, "the token set doesn't record its issuer (TokenSet.Issuer)", nil)
		}
		return newError(ErrorInvalidRequest, "the token set was issued by a different issuer than this client's", nil)
	}
	if t.HasIDToken && t.IDTokenClaims.Issuer != c.cfg.Issuer.String() {
		return newError(ErrorInvalidRequest, "the token set's ID token was issued by a different issuer than this client's", nil)
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
