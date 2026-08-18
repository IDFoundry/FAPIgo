package client

import (
	"context"
	"encoding/json"

	"github.com/idfoundry/fapigo/internal/jarm"
	"github.com/idfoundry/fapigo/internal/par"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/storage"
)

// AuthorizationCallback is the input to Client.HandleAuthorizationResponse
// — the raw query string of the request the user agent's redirect back
// to RedirectURI carried. Passing the raw string (rather than a
// pre-parsed url.Values) means this package — not an HTTP adapter —
// detects a duplicated parameter, the same raw-request-boundary
// discipline server's FormRequest applies; see internal/par.DecodeForm.
type AuthorizationCallback struct {
	RawQuery string
}

// ValidatedAuthorizationResponse is what HandleAuthorizationResponse
// returns for a successful callback. It is opaque and can only be
// constructed by HandleAuthorizationResponse — the only way to obtain
// one is to have already passed every check HandleAuthorizationResponse
// performs, so ExchangeCode can never be called with an
// unvalidated code.
type ValidatedAuthorizationResponse struct {
	code         string
	redirectURI  string
	pkceVerifier string
	nonce        string
}

// CallbackResult is a closed sum type returned by
// HandleAuthorizationResponse, so a caller can't assume every callback
// carries a code and can't forget to branch on the error case.
type CallbackResult interface {
	callbackResult()
}

// CallbackSuccess means the authorization server granted the request.
// Response must be passed to ExchangeCode to complete the flow.
type CallbackSuccess struct {
	Response ValidatedAuthorizationResponse
}

func (CallbackSuccess) callbackResult() {}

// CallbackDenied means the authorization server (or the resource owner,
// via the authorization server) declined the request. Code and
// Description come from the authorization server's own error response
// and are safe to surface to the embedding application.
type CallbackDenied struct {
	Code        string
	Description string
}

func (CallbackDenied) callbackResult() {}

// HandleAuthorizationResponse validates an authorization callback: the
// "iss" parameter (RFC 9207 §2.4) for a plain-mode response — checked
// before anything else derived from params is trusted, including an
// "error" code, since "clients MUST NOT assume that the error
// originates from the intended authorization server" until iss itself
// checks out — correlation state (via SessionStore.Consume, which also
// prevents the same callback being processed twice), issuer, JARM
// signature and claims when Config.Profile requires one, response-mode
// consistency with what this session requested, and authorization-code
// or error-response presence.
func (c *Client) HandleAuthorizationResponse(ctx context.Context, cb AuthorizationCallback) (CallbackResult, error) {
	params, respMode, err := c.parseCallbackParams(ctx, cb)
	if err != nil {
		return nil, err
	}

	// RFC 9207 §2.4's "iss" parameter is a plain-mode-only mechanism: a
	// JARM response has no top-level "iss" query parameter to check in
	// the first place (parseCallbackParams's jarm.Verify call already
	// cryptographically ties the response to c.cfg.Issuer via its own
	// signed "iss" claim — a strictly stronger guarantee than this plain
	// comparison), and internal/jarm's Claims parsing pops "iss" out of
	// Parameters entirely, so this check would otherwise always see it
	// as "missing" for a JARM response, regardless of the actual token.
	if respMode == responseModePlain {
		// A present "iss" must equal this client's configured issuer
		// exactly (simple string comparison, no normalization); an
		// absent one is only an error when the server is known to
		// support the parameter — this client can't tell that on its
		// own, so the caller states it via
		// Config.RequireAuthorizationResponseIss.
		if iss, ok := paramString(params, "iss"); ok {
			if iss != c.cfg.Issuer.String() {
				return nil, newError(ErrorInvalidResponse, "authorization response iss does not match expected issuer", nil)
			}
		} else if c.cfg.RequireAuthorizationResponseIss {
			return nil, newError(ErrorInvalidResponse, "authorization response is missing iss", nil)
		}
	}

	state, _ := paramString(params, "state")
	if state == "" {
		return nil, newError(ErrorInvalidRequest, "callback is missing state", nil)
	}

	consumed, consumeErr := c.deps.Sessions.Consume(ctx, storage.SessionConsumption{State: state})
	if consumeErr != nil {
		return nil, newError(ErrorInvalidRequest, "session is invalid, expired, or already used", consumeErr)
	}
	now := c.deps.Clock.Now()
	if !now.Before(consumed.ExpiresAt) {
		return nil, newError(ErrorInvalidRequest, "session has expired", nil)
	}
	if respMode != consumed.ExpectedResponseMode {
		return nil, newError(ErrorInvalidResponse, "authorization response arrived in an unexpected mode", nil)
	}

	if errCode, ok := paramString(params, "error"); ok && errCode != "" {
		errDesc, _ := paramString(params, "error_description")
		return CallbackDenied{Code: errCode, Description: errDesc}, nil
	}

	code, ok := paramString(params, "code")
	if !ok || code == "" {
		return nil, newError(ErrorInvalidResponse, "authorization response carries neither code nor error", nil)
	}

	return CallbackSuccess{Response: ValidatedAuthorizationResponse{
		code:         code,
		redirectURI:  consumed.ExpectedRedirectURI,
		pkceVerifier: consumed.PKCEVerifier,
		nonce:        consumed.Nonce,
	}}, nil
}

// parseCallbackParams extracts the authorization response parameters
// from cb, either directly from its query parameters (plain mode) or
// from a verified JARM response's claims (message-signing mode) —
// selecting which by Config.Profile, never by which shape cb happens to
// contain, so a plain-mode response can't be substituted for a
// message-signed one.
func (c *Client) parseCallbackParams(ctx context.Context, cb AuthorizationCallback) (map[string]json.RawMessage, string, *Error) {
	form, err := par.DecodeForm([]byte(cb.RawQuery))
	if err != nil {
		return nil, "", newError(ErrorInvalidRequest, "callback query is malformed or contains a duplicated parameter", err)
	}

	if c.cfg.Profile != ProfileFAPISecurityWithMessageSigning {
		params := make(map[string]json.RawMessage, len(form))
		for k, v := range form {
			encoded, _ := json.Marshal(v)
			params[k] = encoded
		}
		return params, responseModePlain, nil
	}

	responseJWT, ok := form["response"]
	if !ok || responseJWT == "" {
		return nil, "", newError(ErrorInvalidResponse, "callback is missing a signed response", nil)
	}
	resp, err := jarm.Parse(responseJWT)
	if err != nil {
		return nil, "", newError(ErrorInvalidResponse, "malformed authorization response", err)
	}

	candidates, err := c.deps.IssuerKeys.ResolveIssuerKeys(ctx, keys.IssuerKeyRequest{
		Issuer: c.cfg.Issuer.String(), Purpose: keys.JARMVerification,
		Algorithm: c.cfg.Algorithms.JARM, KeyID: resp.KeyID(),
	})
	if err != nil {
		return nil, "", newError(ErrorInternal, "failed to resolve issuer keys", err)
	}

	var (
		verified  jarm.VerifiedResponse
		verifyErr error
	)
	for _, candidate := range candidates.Keys {
		verified, verifyErr = resp.Verify(candidate.PublicKey, jarm.VerifyPolicy{
			ExpectedIssuer: c.cfg.Issuer.String(), ExpectedAudience: c.cfg.ClientID.String(),
			Algorithm: c.cfg.Algorithms.JARM, Now: c.deps.Clock.Now(),
			MaxLifetime: c.cfg.Limits.MaxJARMResponseLifetime, MaxClockSkew: c.cfg.Limits.MaxClockSkew,
		})
		if verifyErr == nil {
			break
		}
	}
	if verifyErr != nil {
		return nil, "", newError(ErrorInvalidResponse, "authorization response verification failed", verifyErr)
	}

	return verified.Parameters, responseModeJARM, nil
}

func paramString(params map[string]json.RawMessage, key string) (string, bool) {
	raw, ok := params[key]
	if !ok {
		return "", false
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", false
	}
	return s, true
}
