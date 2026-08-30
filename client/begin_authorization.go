package client

import (
	"context"
	"crypto"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/idfoundry/fapigo/extension"
	"github.com/idfoundry/fapigo/internal/clientassertion"
	"github.com/idfoundry/fapigo/internal/dpop"
	"github.com/idfoundry/fapigo/internal/jose"
	"github.com/idfoundry/fapigo/internal/par"
	"github.com/idfoundry/fapigo/internal/pkce"
	"github.com/idfoundry/fapigo/internal/requestobject"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/storage"
)

// BeginAuthorizationRequest is the input to Client.BeginAuthorization.
type BeginAuthorizationRequest struct {
	Scope []string

	// ACRValues optionally requests specific Authentication Context
	// Class Reference values (OIDC Core §3.1.2.1), most-preferred first.
	// Sent as the space-separated "acr_values" parameter only when
	// non-empty — many authorization servers reject it outright for a
	// client that hasn't been specifically provisioned for it, so this
	// is opt-in, never sent by default.
	ACRValues []string

	// Extensions carries any custom authorization parameters to attach
	// to this request — set via extension.Set(&req.Extensions,
	// Definition, value). A value whose encoded JSON shape is a bare
	// string is sent as a plain top-level authorization/PAR parameter
	// regardless of Config.Profile. Any other shape (object, array,
	// number, bool) requires
	// Config.Profile == ProfileFAPISecurityWithMessageSigning: a signed
	// request object carries a value's native JSON shape losslessly,
	// while a plain top-level parameter has no way to represent anything
	// but a bare string. A non-string value under the baseline profile
	// is rejected rather than mis-encoded.
	Extensions extension.Values

	// AuthorizationDetails carries Rich Authorization Requests (RFC 9396)
	// detail objects for this request, one entry per object — build each
	// with extension.RARSet(Definition, value), which also stamps the
	// definition's own "type" discriminator into the result, so a
	// caller's value type never needs its own redundant Type field.
	// Unlike Extensions, this is always sent as native JSON array text
	// under every profile (RFC 9396 §5's own form-encoding: a plain
	// "authorization_details" parameter's value is itself JSON array
	// text, not a bare string), so it works under the baseline profile
	// too, not just ProfileFAPISecurityWithMessageSigning.
	AuthorizationDetails []json.RawMessage
}

// responseModePlain and responseModeJARM record how this session expects
// its authorization response to arrive, so HandleAuthorizationResponse
// can refuse a response that arrived a different way than requested —
// see storage.NewSession.ExpectedResponseMode.
const (
	responseModePlain = "plain"
	responseModeJARM  = "jarm"
)

// authorizationDetailsParameter is the RFC 9396 §5 wire name — mirrors
// server.authorizationDetailsParameter (an unexported constant in a
// different package, so not literally shared, just the same string).
const authorizationDetailsParameter = "authorization_details"

// errPushedAuthorizationRequestFailed is the shared newError
// description sendPushedAuthorizationRequest's own retry sequence uses
// at every call site — the same transport-level failure regardless of
// which attempt hit it.
const errPushedAuthorizationRequestFailed = "pushed authorization request failed"

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
		// client_id (RFC 6749 §4.1.1) is a required authorization-request
		// parameter — carried here even though this client also
		// authenticates via client_assertion, since a pushed
		// authorization request (RFC 9126 §2) conveys the full
		// authorization request, not just a bare authentication call.
		"client_id":             c.cfg.ClientID.String(),
		"response_type":         "code",
		"redirect_uri":          c.cfg.RedirectURI,
		"scope":                 strings.Join(req.Scope, " "),
		"state":                 state,
		"nonce":                 nonce,
		"code_challenge":        challenge,
		"code_challenge_method": "S256",
	}
	if len(req.ACRValues) > 0 {
		params["acr_values"] = strings.Join(req.ACRValues, " ")
	}

	var (
		body   []byte
		parErr *Error
	)
	switch {
	case c.cfg.SenderConstrain == storage.SenderConstrainMTLS:
		// No PAR-time pre-commitment concept exists for mTLS (unlike
		// DPoP's optional dpop_jkt) — binding is derived purely from
		// whichever certificate authenticates the eventual token-endpoint
		// connection, so PAR here is a plain call: no DPoP proof, no
		// dpop_jkt, no nonce retry.
		body, parErr = c.pushAuthorizationRequestPlain(ctx, params, req.Extensions, req.AuthorizationDetails)
	case c.cfg.PARDPoPBinding == PARDPoPBindingJKT:
		body, parErr = c.pushAuthorizationRequestWithJKT(ctx, params, req.Extensions, req.AuthorizationDetails)
	default:
		body, parErr = c.pushAuthorizationRequestWithDPoPProof(ctx, params, req.Extensions, req.AuthorizationDetails)
	}
	if parErr != nil {
		return AuthorizationSession{}, parErr
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

// dpopKeyThumbprint returns the JWK SHA-256 thumbprint (RFC 7638) of
// this client's DPoP signing key, for the "dpop_jkt" authorization
// request parameter (RFC 9449 §10). Dependencies.Keys returns a stable
// key per SigningPurpose (see keys.KeyManager's own contract), so this
// is guaranteed to match whichever key ExchangeCode later presents a
// DPoP proof with for the same client instance.
func (c *Client) dpopKeyThumbprint(ctx context.Context) (string, error) {
	info, err := c.deps.Keys.PublicKey(ctx, keys.DPoPProofSigning, c.cfg.Algorithms.DPoP)
	if err != nil {
		return "", fmt.Errorf("resolve DPoP key: %w", err)
	}
	jwk, err := jose.NewJWK(info.PublicKey, c.cfg.Algorithms.DPoP)
	if err != nil {
		return "", fmt.Errorf("build DPoP JWK: %w", err)
	}
	thumbprint, err := jwk.Thumbprint()
	if err != nil {
		return "", fmt.Errorf("compute DPoP key thumbprint: %w", err)
	}
	return thumbprint.String(), nil
}

// pushAuthorizationRequestPlain implements PAR for a
// SenderConstrainMTLS client: no DPoP proof or dpop_jkt parameter at
// all, and no use_dpop_nonce retry — mTLS has no equivalent nonce
// challenge concept, since binding is derived purely from the TLS
// connection Dependencies.HTTP's own configured transport establishes,
// not from a signed application-layer proof.
func (c *Client) pushAuthorizationRequestPlain(ctx context.Context, params map[string]string, extensions extension.Values, authorizationDetails []json.RawMessage) ([]byte, *Error) {
	formParams, buildErr := c.buildPushedRequestForm(ctx, c.deps.Clock.Now(), params, extensions, authorizationDetails)
	if buildErr != nil {
		return nil, buildErr
	}
	body, status, _, err := c.postForm(ctx, c.cfg.Endpoints.PushedAuthorizationRequest.String(), par.EncodeForm(formParams), nil)
	if err != nil {
		return nil, newError(ErrorInternal, errPushedAuthorizationRequestFailed, err)
	}
	if status != http.StatusCreated && status != http.StatusOK {
		return nil, parErrorFromResponse(body)
	}
	return body, nil
}

// pushAuthorizationRequestWithJKT implements PARDPoPBindingJKT: declares
// this client's DPoP key via the plain "dpop_jkt" parameter (RFC 9449
// §10) — committing the authorization code to it, rather than leaving
// that binding to whichever key first shows up at the token endpoint —
// without proving possession of it until ExchangeCode presents a proof
// with the matching key.
func (c *Client) pushAuthorizationRequestWithJKT(ctx context.Context, params map[string]string, extensions extension.Values, authorizationDetails []json.RawMessage) ([]byte, *Error) {
	dpopThumbprint, err := c.dpopKeyThumbprint(ctx)
	if err != nil {
		return nil, newError(ErrorInternal, "failed to compute DPoP key thumbprint", err)
	}
	params["dpop_jkt"] = dpopThumbprint

	formParams, buildErr := c.buildPushedRequestForm(ctx, c.deps.Clock.Now(), params, extensions, authorizationDetails)
	if buildErr != nil {
		return nil, buildErr
	}
	body, status, _, err := c.postForm(ctx, c.cfg.Endpoints.PushedAuthorizationRequest.String(), par.EncodeForm(formParams), nil)
	if err != nil {
		return nil, newError(ErrorInternal, errPushedAuthorizationRequestFailed, err)
	}
	if status != http.StatusCreated && status != http.StatusOK {
		return nil, parErrorFromResponse(body)
	}
	return body, nil
}

// pushAuthorizationRequestWithDPoPProof implements PARDPoPBindingProof
// (the default): binds the authorization code to this client's DPoP key
// by presenting an actual proof at PAR — RFC 9449 §10.1's recommended
// mechanism — instead of the plain dpop_jkt parameter, retrying once on
// a use_dpop_nonce challenge. This mirrors sendTokenRequest's identical
// mechanic for the token endpoint: an authorization server that
// nonce-challenges DPoP proofs it verifies can now challenge this one
// too, since PAR is presenting one for the first time. A client
// assertion is exactly as single-use as a DPoP proof, so the retry
// rebuilds the whole form, not just the proof — same reasoning
// sendTokenRequest's own doc comment gives for the token endpoint.
func (c *Client) pushAuthorizationRequestWithDPoPProof(ctx context.Context, params map[string]string, extensions extension.Values, authorizationDetails []json.RawMessage) ([]byte, *Error) {
	dpopSigner, _, err := c.newSigner(ctx, keys.DPoPProofSigning, c.cfg.Algorithms.DPoP)
	if err != nil {
		return nil, newError(ErrorInternal, "failed to resolve DPoP signing key", err)
	}
	parURL := c.cfg.Endpoints.PushedAuthorizationRequest.URL()

	buildParForm := func() ([]byte, error) {
		formParams, buildErr := c.buildPushedRequestForm(ctx, c.deps.Clock.Now(), params, extensions, authorizationDetails)
		if buildErr != nil {
			return nil, buildErr
		}
		return par.EncodeForm(formParams), nil
	}
	form, buildErr := buildParForm()
	if buildErr != nil {
		return nil, newError(ErrorInternal, "failed to build pushed authorization request", buildErr)
	}

	body, status, header, err := c.postParRequestWithDPoP(ctx, dpopSigner, &parURL, form, c.cachedDPoPNonce(ctx, asNonceScope))
	if err != nil {
		return nil, newError(ErrorInternal, errPushedAuthorizationRequestFailed, err)
	}
	nextNonce := header.Get(dpopNonceHeader)
	c.cacheDPoPNonce(ctx, asNonceScope, nextNonce)
	if status == http.StatusCreated || status == http.StatusOK {
		return body, nil
	}

	if nextNonce == "" || !isDPoPNonceError(body) {
		return nil, parErrorFromResponse(body)
	}
	retryForm, buildErr := buildParForm()
	if buildErr != nil {
		return nil, newError(ErrorInternal, "failed to build pushed authorization request", buildErr)
	}
	body, status, header, err = c.postParRequestWithDPoP(ctx, dpopSigner, &parURL, retryForm, nextNonce)
	if err != nil {
		return nil, newError(ErrorInternal, errPushedAuthorizationRequestFailed, err)
	}
	c.cacheDPoPNonce(ctx, asNonceScope, header.Get(dpopNonceHeader))
	if status != http.StatusCreated && status != http.StatusOK {
		return nil, parErrorFromResponse(body)
	}
	return body, nil
}

// postParRequestWithDPoP signs a fresh DPoP proof (new iat and jti) for
// the pushed authorization request — no AccessToken/ath, since none
// exists yet at PAR time, matching how server/par.go's own dpop.Verify
// call never expects one either — and posts form to it.
func (c *Client) postParRequestWithDPoP(ctx context.Context, dpopSigner crypto.Signer, parURL *url.URL, form []byte, nonce string) ([]byte, int, http.Header, error) {
	proof, err := dpop.CreateProof(dpop.ProofRequest{
		Signer: dpopSigner, Algorithm: c.cfg.Algorithms.DPoP,
		Method: http.MethodPost, URL: parURL, Now: c.deps.Clock.Now(),
		Random: c.deps.Random, Nonce: nonce,
	})
	if err != nil {
		return nil, 0, nil, fmt.Errorf("build DPoP proof: %w", err)
	}
	return c.postForm(ctx, parURL.String(), form, map[string]string{"DPoP": proof})
}

// buildPushedRequestForm builds the PAR endpoint's form body: a client
// assertion for authentication, plus either a signed request object
// (ProfileFAPISecurityWithMessageSigning) or the plain authorization
// parameters directly.
func (c *Client) buildPushedRequestForm(ctx context.Context, now time.Time, params map[string]string, extensions extension.Values, authorizationDetails []json.RawMessage) (map[string]string, *Error) {
	form := map[string]string{}
	if c.cfg.ClientAuthMethod == storage.ClientAuthMethodPrivateKeyJWT {
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
		form["client_assertion"] = assertion
		form["client_assertion_type"] = clientassertion.AssertionType
	} else {
		form["client_id"] = c.cfg.ClientID.String()
	}

	snapshot := extension.Snapshot(extensions)

	var authorizationDetailsRaw json.RawMessage
	if len(authorizationDetails) > 0 {
		encoded, err := json.Marshal(authorizationDetails)
		if err != nil {
			return nil, newError(ErrorInternal, "failed to encode authorization_details", err)
		}
		authorizationDetailsRaw = encoded
	}

	if c.cfg.Profile != ProfileFAPISecurityWithMessageSigning {
		for name, raw := range snapshot {
			if _, reserved := params[name]; reserved {
				return nil, newError(ErrorInvalidRequest, fmt.Sprintf("extension parameter %q collides with a core parameter name", name), nil)
			}
			// A plain top-level parameter has no way to represent
			// anything but a bare string — unlike the signing path
			// below, which embeds raw straight into the request
			// object's JSON and so preserves any shape. Only a value
			// that is itself a bare JSON string round-trips here
			// without loss; anything else must go through the signing
			// profile instead of being silently flattened.
			var value string
			if err := json.Unmarshal(raw, &value); err != nil {
				return nil, newError(ErrorInvalidRequest,
					fmt.Sprintf("extension parameter %q is not a plain string; non-string extension values require ProfileFAPISecurityWithMessageSigning", name), nil)
			}
			params[name] = value
		}
		for k, v := range params {
			form[k] = v
		}
		if authorizationDetailsRaw != nil {
			// RFC 9396 §5: unlike an extension.Definition value, a plain
			// "authorization_details" parameter's value is itself JSON
			// array text — this is the one plain parameter this package
			// sends un-stringified, so it round-trips through
			// checkRAR/RARRegistry.Parse identically to the signed-object
			// path below, regardless of Config.Profile.
			form[authorizationDetailsParameter] = string(authorizationDetailsRaw)
		}
		return form, nil
	}

	objectParams := make(map[string]json.RawMessage, len(params)+len(snapshot)+1)
	for k, v := range params {
		encoded, _ := json.Marshal(v) // marshaling a string cannot fail
		objectParams[k] = encoded
	}

	for name, raw := range snapshot {
		if _, reserved := objectParams[name]; reserved {
			return nil, newError(ErrorInvalidRequest, fmt.Sprintf("extension parameter %q collides with a core parameter name", name), nil)
		}
		objectParams[name] = raw
	}

	if authorizationDetailsRaw != nil {
		objectParams[authorizationDetailsParameter] = authorizationDetailsRaw
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
