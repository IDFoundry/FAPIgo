package client

import (
	"context"
	"net/http"

	"github.com/idfoundry/fapigo/internal/par"
)

// RevokeToken asks the authorization server to revoke tokens' refresh
// token (RFC 7009) at Config.Endpoints.Revocation, authenticating as the token
// request does: client assertion, Client Attestation, or TLS client
// certificate. No DPoP proof is sent: revocation isn't
// sender-constrained.
//
// A nil error means the server answered 200, which it does whether or
// not the token was still live (RFC 7009 §2.2): either way the client
// can forget it. With no Config.Endpoints.Revocation, RevokeToken fails
// with ErrorRevocationNotSupported, and the token can only be forgotten
// locally. An error response from the server is ErrorInvalidResponse,
// carrying it as ServerResponse.
//
// Only refresh tokens are sent; access tokens are short-lived and expire
// on their own. tokens must have a refresh token, and must have come
// from this client's issuer, as RefreshTokens requires: a set from
// another issuer, or one recording no issuer at all (TokenSet.Issuer,
// or its ID token's iss), is refused before anything is sent, so one
// issuer's refresh token is never presented to another. An application
// that kept only the refresh token builds a TokenSet with it,
// HasRefreshToken and the Issuer it came from.
func (c *Client) RevokeToken(ctx context.Context, tokens TokenSet) error {
	if c.cfg.Endpoints.Revocation.IsZero() {
		return newError(ErrorRevocationNotSupported, "the authorization server has no revocation endpoint", nil)
	}
	if !tokens.HasRefreshToken || tokens.RefreshToken.Reveal() == "" {
		return newError(ErrorInvalidRequest, "the token set has no refresh token", nil)
	}
	if issuerErr := c.checkTokenSetIssuer(tokens); issuerErr != nil {
		return issuerErr
	}
	refreshToken := tokens.RefreshToken
	assertionSigner, assertionKID, _, err := c.resolveClientAuthAndDPoPSigners(ctx)
	if err != nil {
		return newError(ErrorInternal, "failed to resolve signing keys", err)
	}
	build := func() ([]byte, map[string]string, error) {
		form := map[string]string{
			"token":           refreshToken.Reveal(),
			"token_type_hint": "refresh_token",
		}
		headers, buildErr := c.addClientAuthentication(ctx, form, assertionSigner, assertionKID)
		return par.EncodeForm(form), headers, buildErr
	}
	form, headers, err := build()
	if err != nil {
		return newError(ErrorInternal, "failed to authenticate the revocation request", err)
	}
	body, status, header, err := c.postFormWithAttestationChallenge(ctx, c.cfg.Endpoints.Revocation.String(), form, headers, build)
	if err != nil {
		return newError(ErrorInternal, "token revocation request failed", err)
	}
	if status != http.StatusOK {
		return parErrorFromResponse(status, header, body)
	}
	return nil
}
