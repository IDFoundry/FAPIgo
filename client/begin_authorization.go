package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/osanderson/go-fapi/extension"
	"github.com/osanderson/go-fapi/internal/clientassertion"
	"github.com/osanderson/go-fapi/internal/par"
	"github.com/osanderson/go-fapi/internal/pkce"
	"github.com/osanderson/go-fapi/internal/requestobject"
	"github.com/osanderson/go-fapi/keys"
	"github.com/osanderson/go-fapi/storage"
)

// BeginAuthorizationRequest is the input to Client.BeginAuthorization.
type BeginAuthorizationRequest struct {
	Scope []string

	// Extensions carries any custom authorization parameters to attach
	// to this request — set via extension.Set(&req.Extensions,
	// Definition, value). It requires
	// Config.Profile == ProfileFAPISecurityWithMessageSigning: a signed
	// request object carries a value's native JSON shape losslessly,
	// while this client's plain-parameter path would have to flatten
	// every value to a bare string, silently losing structure. A
	// non-empty Extensions under the baseline profile is rejected rather
	// than mis-encoded.
	Extensions extension.Values
}

// responseModePlain and responseModeJARM record how this session expects
// its authorization response to arrive, so HandleAuthorizationResponse
// can refuse a response that arrived a different way than requested —
// see storage.NewSession.ExpectedResponseMode.
const (
	responseModePlain = "plain"
	responseModeJARM  = "jarm"
)

// BeginAuthorization starts a new authorization attempt: it generates
// state, nonce and a PKCE verifier, builds and signs a request object
// when Config.Profile requires one, authenticates to and calls the
// pushed-authorization-request endpoint (RFC 9126), and persists
// correlation state for the eventual callback.
func (c *Client) BeginAuthorization(ctx context.Context, req BeginAuthorizationRequest) (AuthorizationSession, error) {
	state, err := generateRandomToken(c.deps.Random)
	if err != nil {
		return AuthorizationSession{}, newError(ErrorInternal, "failed to generate state", err)
	}
	nonce, err := generateRandomToken(c.deps.Random)
	if err != nil {
		return AuthorizationSession{}, newError(ErrorInternal, "failed to generate nonce", err)
	}
	verifier, err := pkce.GenerateVerifier(c.deps.Random)
	if err != nil {
		return AuthorizationSession{}, newError(ErrorInternal, "failed to generate PKCE verifier", err)
	}
	challenge, err := pkce.Challenge(verifier, pkce.S256)
	if err != nil {
		return AuthorizationSession{}, newError(ErrorInternal, "failed to derive PKCE challenge", err)
	}

	now := c.deps.Clock.Now()
	params := map[string]string{
		"response_type":         "code",
		"redirect_uri":          c.cfg.RedirectURI,
		"scope":                 strings.Join(req.Scope, " "),
		"state":                 state,
		"nonce":                 nonce,
		"code_challenge":        challenge,
		"code_challenge_method": "S256",
	}

	formParams, buildErr := c.buildPushedRequestForm(ctx, now, params, req.Extensions)
	if buildErr != nil {
		return AuthorizationSession{}, buildErr
	}

	body, status, err := c.postForm(ctx, c.cfg.Endpoints.PushedAuthorizationRequest.String(), par.EncodeForm(formParams), nil)
	if err != nil {
		return AuthorizationSession{}, newError(ErrorInternal, "pushed authorization request failed", err)
	}
	if status != http.StatusCreated && status != http.StatusOK {
		return AuthorizationSession{}, parErrorFromResponse(body)
	}

	result, err := par.DecodeResult(body)
	if err != nil {
		return AuthorizationSession{}, newError(ErrorInvalidResponse, "malformed pushed authorization request response", err)
	}

	responseMode := responseModePlain
	if c.cfg.Profile == ProfileFAPISecurityWithMessageSigning {
		responseMode = responseModeJARM
	}
	if err := c.deps.Sessions.Create(ctx, storage.NewSession{
		State:                state,
		Nonce:                nonce,
		PKCEVerifier:         verifier,
		ExpectedIssuer:       c.cfg.Issuer.String(),
		ExpectedRedirectURI:  c.cfg.RedirectURI,
		ExpectedResponseMode: responseMode,
		ExpiresAt:            now.Add(c.cfg.Limits.SessionLifetime),
	}); err != nil {
		return AuthorizationSession{}, newError(ErrorInternal, "failed to persist session", err)
	}

	q := url.Values{}
	q.Set("client_id", c.cfg.ClientID.String())
	q.Set("request_uri", result.RequestURI)
	browserURL := c.cfg.Endpoints.Authorization.WithQuery(q)

	return AuthorizationSession{url: browserURL, handle: SessionHandle{value: state}}, nil
}

// buildPushedRequestForm builds the PAR endpoint's form body: a client
// assertion for authentication, plus either a signed request object
// (ProfileFAPISecurityWithMessageSigning) or the plain authorization
// parameters directly.
func (c *Client) buildPushedRequestForm(ctx context.Context, now time.Time, params map[string]string, extensions extension.Values) (map[string]string, *Error) {
	assertionSigner, assertionKID, err := c.newSigner(ctx, keys.ClientAuthentication, c.cfg.Algorithms.ClientAuthentication)
	if err != nil {
		return nil, newError(ErrorInternal, "failed to resolve client authentication key", err)
	}
	assertion, err := clientassertion.CreateAssertion(clientassertion.AssertionRequest{
		Signer: assertionSigner, Algorithm: c.cfg.Algorithms.ClientAuthentication, KeyID: assertionKID,
		ClientID: c.cfg.ClientID.String(), Audience: c.cfg.Issuer.String(),
		Now: now, Lifetime: c.cfg.Limits.ClientAssertionLifetime, Random: c.deps.Random,
	})
	if err != nil {
		return nil, newError(ErrorInternal, "failed to build client assertion", err)
	}

	form := map[string]string{
		"client_assertion":      assertion,
		"client_assertion_type": clientassertion.AssertionType,
	}

	snapshot := extension.Snapshot(extensions)

	if c.cfg.Profile != ProfileFAPISecurityWithMessageSigning {
		if len(snapshot) > 0 {
			return nil, newError(ErrorInvalidRequest, "extension parameters require ProfileFAPISecurityWithMessageSigning", nil)
		}
		for k, v := range params {
			form[k] = v
		}
		return form, nil
	}

	objectParams := make(map[string]json.RawMessage, len(params)+1+len(snapshot))
	for k, v := range params {
		encoded, _ := json.Marshal(v) // marshaling a string cannot fail
		objectParams[k] = encoded
	}
	clientIDJSON, _ := json.Marshal(c.cfg.ClientID.String())
	objectParams["client_id"] = clientIDJSON

	for name, raw := range snapshot {
		if _, reserved := objectParams[name]; reserved {
			return nil, newError(ErrorInvalidRequest, fmt.Sprintf("extension parameter %q collides with a core parameter name", name), nil)
		}
		objectParams[name] = raw
	}

	objectSigner, objectKID, err := c.newSigner(ctx, keys.RequestObjectSigning, c.cfg.Algorithms.RequestObject)
	if err != nil {
		return nil, newError(ErrorInternal, "failed to resolve request object signing key", err)
	}
	object, err := requestobject.Create(requestobject.CreateParams{
		Signer: objectSigner, Algorithm: c.cfg.Algorithms.RequestObject, KeyID: objectKID,
		ClientID: c.cfg.ClientID.String(), Audience: c.cfg.Issuer.String(),
		Now: now, Lifetime: c.cfg.Limits.RequestObjectLifetime, Random: c.deps.Random,
		Parameters: objectParams,
	})
	if err != nil {
		return nil, newError(ErrorInternal, "failed to build request object", err)
	}
	form["request"] = object
	return form, nil
}

// parErrorFromResponse maps a non-success PAR (or token-endpoint) HTTP
// response body to a typed Error, falling back to a generic message if
// the body isn't a well-formed OAuth error response.
func parErrorFromResponse(body []byte) *Error {
	errResp, err := par.DecodeErrorResponse(body)
	if err != nil {
		return newError(ErrorInvalidResponse, "authorization server returned an error", fmt.Errorf("status body: %s", strconv.Quote(string(body))))
	}
	return newError(ErrorInvalidResponse, errResp.Description, fmt.Errorf("authorization server error: %s", errResp.Code))
}
