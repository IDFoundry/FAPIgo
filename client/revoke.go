package client

import (
	"context"
	"net/http"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/par"
)

// RevokeToken asks the authorization server to revoke refreshToken
// (RFC 7009) at Config.Endpoints.Revocation, authenticating as the token
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
// on their own.
func (c *Client) RevokeToken(ctx context.Context, refreshToken fapi.Secret) error {
	if c.cfg.Endpoints.Revocation.IsZero() {
		return newError(ErrorRevocationNotSupported, "the authorization server has no revocation endpoint", nil)
	}
	if refreshToken.Reveal() == "" {
		return newError(ErrorInvalidRequest, "refreshToken is empty", nil)
	}
	assertionSigner, assertionKID, _, err := c.resolveClientAuthAndDPoPSigners(ctx)
	if err != nil {
		return newError(ErrorInternal, "failed to resolve signing keys", err)
	}
	form := map[string]string{
		"token":           refreshToken.Reveal(),
		"token_type_hint": "refresh_token",
	}
	headers, err := c.addClientAuthentication(ctx, form, assertionSigner, assertionKID)
	if err != nil {
		return newError(ErrorInternal, "failed to authenticate the revocation request", err)
	}
	body, status, header, err := c.postForm(ctx, c.cfg.Endpoints.Revocation.String(), par.EncodeForm(form), headers)
	if err != nil {
		return newError(ErrorInternal, "token revocation request failed", err)
	}
	if status != http.StatusOK {
		return parErrorFromResponse(status, header, body)
	}
	return nil
}
