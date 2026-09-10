package client

import (
	"context"
	"crypto"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/clientassertion"
	"github.com/idfoundry/fapigo/internal/par"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/storage"
)

// ClientCredentialsTokenRequest is the input to
// Client.RequestClientCredentialsToken.
type ClientCredentialsTokenRequest struct {
	// Scope is required: RFC 6749 §4.4 itself leaves scope optional on
	// the wire, but the authorization server this package targets
	// (server.RequestClientCredentialsToken) always requires at least
	// one, so an empty value here would only ever fail at the server —
	// rejected locally instead, the same "don't build a request that can
	// only ever fail" precedent BeginAuthorizationRequest's own required
	// fields follow.
	Scope []string

	// AuthorizationDetails carries Rich Authorization Requests (RFC 9396)
	// detail objects for this request — see BeginAuthorizationRequest's
	// field of the same name for how to build one. Always sent as native
	// JSON array text (RFC 9396 §5), the same as a plain-parameter
	// authorization request: this grant has no signed-request-object
	// concept for Config.Profile to matter to.
	AuthorizationDetails []json.RawMessage
}

// ClientCredentialsTokenResult is returned by a successful
// RequestClientCredentialsToken. Unlike TokenSet, it never carries an ID
// token, subject or refresh token: RFC 6749 §4.4 has no end user for an
// ID token to identify, and §4.4.3 says a refresh token "SHOULD NOT" be
// issued for this grant — those fields would only ever go unpopulated
// here, so this is its own, smaller result type rather than reusing
// TokenSet's.
type ClientCredentialsTokenResult struct {
	AccessToken fapi.Secret
	TokenType   string
	Scope       string

	// ExpiresIn is set only when the token response actually carried
	// expires_in — see TokenSet.ExpiresIn's own doc comment for why that
	// isn't always the case.
	ExpiresIn    time.Duration
	HasExpiresIn bool

	// AuthorizationDetails is the server's granted Rich Authorization
	// Requests detail array (RFC 9396 §5), nil if the request carried
	// none or the server granted none of it.
	AuthorizationDetails json.RawMessage
}

// RequestClientCredentialsToken implements the RFC 6749 §4.4
// client_credentials grant: authenticates to the token endpoint and
// requests an access token scoped to req.Scope. There is no
// authorization code, no PAR, no end-user interaction and no session —
// unlike ExchangeCode/PollBackchannelAuthentication, this is a single
// self-contained call with no prior BeginAuthorization/
// BeginBackchannelAuthentication step to complete.
func (c *Client) RequestClientCredentialsToken(ctx context.Context, req ClientCredentialsTokenRequest) (ClientCredentialsTokenResult, error) {
	if len(req.Scope) == 0 {
		return ClientCredentialsTokenResult{}, newError(ErrorInvalidRequest, "scope is required", nil)
	}

	var authorizationDetailsJSON string
	if len(req.AuthorizationDetails) > 0 {
		encoded, err := json.Marshal(req.AuthorizationDetails)
		if err != nil {
			return ClientCredentialsTokenResult{}, newError(ErrorInternal, "failed to encode authorization_details", err)
		}
		authorizationDetailsJSON = string(encoded)
	}

	// assertionSigner stays nil (and assertionKID "") when ClientAuthMethod
	// isn't ClientAuthMethodPrivateKeyJWT — buildForm never uses them in
	// that case, since no client_assertion is ever built. Same pattern as
	// ExchangeCode's own buildTokenForm.
	var (
		assertionSigner crypto.Signer
		assertionKID    string
		err             error
	)
	if c.cfg.ClientAuthMethod == storage.ClientAuthMethodPrivateKeyJWT {
		assertionSigner, assertionKID, err = c.newSigner(ctx, keys.ClientAuthentication, c.cfg.Algorithms.ClientAuthentication)
		if err != nil {
			return ClientCredentialsTokenResult{}, newError(ErrorInternal, "failed to resolve client authentication key", err)
		}
	}
	// dpopSigner stays nil under SenderConstrainMTLS — sendTokenRequest
	// never uses it in that case, since no DPoP proof is ever built.
	var dpopSigner crypto.Signer
	if c.cfg.SenderConstrain == storage.SenderConstrainDPoP {
		dpopSigner, _, err = c.newSigner(ctx, keys.DPoPProofSigning, c.cfg.Algorithms.DPoP)
		if err != nil {
			return ClientCredentialsTokenResult{}, newError(ErrorInternal, "failed to resolve DPoP signing key", err)
		}
	}
	tokenURL := c.cfg.Endpoints.Token.URL()

	// buildForm signs a fresh client assertion (new iat and jti) every
	// time it's called, including for a retry after a use_dpop_nonce
	// challenge — see ExchangeCode's own buildTokenForm doc comment for
	// why reusing one across two requests would get the retry rejected
	// as jti replay.
	buildForm := func() ([]byte, error) {
		form := map[string]string{
			"grant_type": "client_credentials",
			"scope":      strings.Join(req.Scope, " "),
		}
		if authorizationDetailsJSON != "" {
			form[authorizationDetailsParameter] = authorizationDetailsJSON
		}
		if c.cfg.ClientAuthMethod == storage.ClientAuthMethodPrivateKeyJWT {
			assertion, err := clientassertion.CreateAssertion(clientassertion.AssertionRequest{
				Signer: assertionSigner, Algorithm: c.cfg.Algorithms.ClientAuthentication, KeyID: assertionKID,
				ClientID: c.cfg.ClientID.String(), Audience: c.cfg.Issuer.String(),
				Now: c.deps.Clock.Now(), Lifetime: c.cfg.Limits.ClientAssertionLifetime, Random: c.deps.Random,
			})
			if err != nil {
				return nil, err
			}
			form["client_assertion"] = assertion
			form["client_assertion_type"] = clientassertion.AssertionType
		} else {
			form["client_id"] = c.cfg.ClientID.String()
		}
		return par.EncodeForm(form), nil
	}

	form, err := buildForm()
	if err != nil {
		return ClientCredentialsTokenResult{}, newError(ErrorInternal, "failed to build client assertion", err)
	}
	body, tokenErr := c.sendTokenRequest(ctx, dpopSigner, &tokenURL, buildForm, form)
	if tokenErr != nil {
		return ClientCredentialsTokenResult{}, tokenErr
	}

	raw, err := decodeTokenResponse(body)
	if err != nil {
		return ClientCredentialsTokenResult{}, newError(ErrorInvalidResponse, "malformed token response", err)
	}
	wantTokenType := tokenTypeFor(c.cfg.SenderConstrain)
	if !strings.EqualFold(raw.TokenType, wantTokenType) {
		return ClientCredentialsTokenResult{}, newError(ErrorInvalidResponse, fmt.Sprintf("token response token_type is not %s", wantTokenType), nil)
	}

	result := ClientCredentialsTokenResult{
		AccessToken:          fapi.NewSecret(raw.AccessToken),
		TokenType:            wantTokenType,
		Scope:                raw.Scope,
		AuthorizationDetails: raw.AuthorizationDetails,
	}
	if raw.ExpiresIn > 0 {
		result.ExpiresIn = time.Duration(raw.ExpiresIn) * time.Second
		result.HasExpiresIn = true
	}
	return result, nil
}
