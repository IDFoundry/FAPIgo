package client

import (
	"context"
	"crypto"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/idfoundry/fapigo/extension"
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

	// RedirectPort, when not 0, is the port this authorization's
	// response comes back on, in place of Config.RedirectURI's own: for a
	// native app listening on loopback on a port the operating system
	// picked for this flow (RFC 8252 §7.3), against a server that
	// registered the client's loopback redirect URI to match any port.
	// BeginAuthorization refuses it unless Config.RedirectURI is loopback
	// http to the IP literal 127.0.0.1 or [::1]. The token request then
	// names the same redirect URI, port and all.
	RedirectPort uint16

	// ACRValues optionally requests specific Authentication Context
	// Class Reference values (OIDC Core §3.1.2.1), most-preferred first.
	// Sent as the space-separated "acr_values" parameter only when
	// non-empty — many authorization servers reject it outright for a
	// client that hasn't been specifically provisioned for it, so this
	// is opt-in, never sent by default.
	ACRValues []string

	// MaxAge, when HasMaxAge, is sent as "max_age" (OIDC Core §3.1.2.1):
	// the most time that may have passed since the user last actively
	// authenticated at the authorization server, which must otherwise
	// authenticate them again. It's sent in whole seconds, rounded down;
	// HasMaxAge with a zero MaxAge asks for a fresh authentication every
	// time. ExchangeCode then checks the ID token's auth_time
	// (TokenSet.IDTokenClaims.AuthTime) against it, as OIDC Core
	// §3.1.3.7 has the client do: a token without auth_time, or one
	// further back than MaxAge (plus Limits.MaxClockSkew), is refused.
	// MaxAge is at most 100 years, and never negative. HasMaxAge
	// requires "openid" in Scope, since only an ID token's auth_time can
	// meet it: BeginAuthorization refuses it otherwise, and always under
	// Config.OAuthOnly.
	MaxAge    time.Duration
	HasMaxAge bool

	// Extensions carries any custom authorization parameters to attach
	// to this request — set via extension.Set(&req.Extensions,
	// Definition, value). A value whose encoded JSON shape is a bare
	// string is sent as a plain top-level authorization/PAR parameter
	// regardless of Config.Profile. Any other shape (object, array,
	// number, bool) requires a signed request object
	// (Config.Profile == ProfileFAPISecurityWithMessageSigning, or
	// Config.PushedRequestEncoding == PushedRequestEncodingRequestObject):
	// a signed request object carries a value's native JSON shape losslessly,
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
	// under every profile (RFC 9396 §2's own form-encoding: a plain
	// "authorization_details" parameter's value is itself JSON array
	// text, not a bare string), so it works under the baseline profile
	// too, not just ProfileFAPISecurityWithMessageSigning.
	AuthorizationDetails []json.RawMessage

	// Claims requests specific identity claims with the OIDC "claims"
	// parameter (OIDC Core §5.5), by where each should be delivered —
	// sent only when at least one name is set. The authorization server
	// decides what it actually releases: a FAPIgo server releases only
	// those the resource owner approves.
	Claims RequestedClaims
}

// RequestedClaims names identity claims to request with the OIDC
// "claims" parameter, by delivery location. Each is requested as a
// voluntary claim with no particular value (OIDC Core §5.5.1's null
// request).
type RequestedClaims struct {
	IDToken  []string // claims wanted in the ID token
	UserInfo []string // claims wanted from the UserInfo endpoint
}

// claimsParameter is the OIDC Core §5.5 "claims" request parameter.
const claimsParameter = "claims"

// maxAgeParameter is the OIDC Core §3.1.2.1 "max_age" parameter.
const maxAgeParameter = "max_age"

// encode returns r as the "claims" parameter's JSON object, or nil if it
// names no claims.
func (r RequestedClaims) encode() (json.RawMessage, error) {
	location := func(names []string) (map[string]json.RawMessage, error) {
		if len(names) == 0 {
			return nil, nil
		}
		out := make(map[string]json.RawMessage, len(names))
		for _, name := range names {
			if name == "" {
				return nil, fmt.Errorf("claim name is empty")
			}
			out[name] = json.RawMessage("null")
		}
		return out, nil
	}
	idToken, err := location(r.IDToken)
	if err != nil {
		return nil, err
	}
	userinfo, err := location(r.UserInfo)
	if err != nil {
		return nil, err
	}
	if idToken == nil && userinfo == nil {
		return nil, nil
	}
	return json.Marshal(struct {
		IDToken  map[string]json.RawMessage `json:"id_token,omitempty"`
		UserInfo map[string]json.RawMessage `json:"userinfo,omitempty"`
	}{idToken, userinfo})
}

// responseModePlain and responseModeJARM record how this session expects
// its authorization response to arrive, so HandleAuthorizationResponse
// can refuse a response that arrived a different way than requested —
// see sessionRecord.ResponseMode.
const (
	responseModePlain = "plain"
	responseModeJARM  = "jarm"
)

// authorizationDetailsParameter is the RFC 9396 §2 wire name — mirrors
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
// when Config.Profile or Config.PushedRequestEncoding requires one,
// authenticates to and calls the
// pushed-authorization-request endpoint (RFC 9126), and persists
// correlation state for the eventual callback.
func (c *Client) BeginAuthorization(ctx context.Context, req BeginAuthorizationRequest) (AuthorizationSession, error) {
	redirectURI, reqErr := c.checkBeginRequest(req)
	if reqErr != nil {
		return AuthorizationSession{}, reqErr
	}
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
		"redirect_uri":          redirectURI,
		"scope":                 strings.Join(req.Scope, " "),
		"state":                 state,
		"nonce":                 nonce,
		"code_challenge":        challenge,
		"code_challenge_method": "S256",
	}
	if len(req.ACRValues) > 0 {
		params["acr_values"] = strings.Join(req.ACRValues, " ")
	}
	if req.HasMaxAge {
		seconds, err := maxAgeSeconds(req.MaxAge)
		if err != nil {
			return AuthorizationSession{}, err
		}
		params[maxAgeParameter] = strconv.FormatInt(seconds, 10)
	}
	claims, err := req.Claims.encode()
	if err != nil {
		return AuthorizationSession{}, newError(ErrorInvalidRequest, "claims request is invalid", err)
	}
	if claims != nil {
		// JSON object text: sent as-is as a plain PAR parameter, and
		// embedded as a native object in a request object (see
		// signPushedRequestForm).
		params[claimsParameter] = string(claims)
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

	if sessionErr := c.createSession(ctx, state, c.newSessionRecord(req, redirectURI, nonce, verifier), now); sessionErr != nil {
		return AuthorizationSession{}, sessionErr
	}

	q := url.Values{}
	q.Set("client_id", c.cfg.ClientID.String())
	q.Set("request_uri", result.RequestURI)
	browserURL := c.cfg.Endpoints.Authorization.WithQuery(q)

	return AuthorizationSession{url: browserURL, handle: SessionHandle{value: state}, expiresAt: now.Add(c.cfg.Limits.SessionLifetime)}, nil
}

// dpopKeyThumbprint returns the JWK SHA-256 thumbprint (RFC 7638) of
// this client's DPoP signing key, for the "dpop_jkt" authorization
// request parameter (RFC 9449 §10). Dependencies.Keys returns a stable
// key per SigningPurpose (see keys.KeyManager's own contract), so this
// is guaranteed to match whichever key ExchangeCode later presents a
// DPoP proof with for the same client instance.
func (c *Client) dpopKeyThumbprint(ctx context.Context) (string, error) {
	if c.deps.Keys == nil {
		return "", errNoSigningKeys
	}
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
	formParams, headers, buildErr := c.buildPushedRequestForm(ctx, c.deps.Clock.Now(), params, extensions, authorizationDetails)
	if buildErr != nil {
		return nil, buildErr
	}
	body, status, header, err := c.postForm(ctx, c.cfg.Endpoints.PushedAuthorizationRequest.String(), par.EncodeForm(formParams), headers)
	if err != nil {
		return nil, newError(ErrorInternal, errPushedAuthorizationRequestFailed, err)
	}
	if status != http.StatusCreated && status != http.StatusOK {
		return nil, parErrorFromResponse(status, header, body)
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

	formParams, headers, buildErr := c.buildPushedRequestForm(ctx, c.deps.Clock.Now(), params, extensions, authorizationDetails)
	if buildErr != nil {
		return nil, buildErr
	}
	body, status, header, err := c.postForm(ctx, c.cfg.Endpoints.PushedAuthorizationRequest.String(), par.EncodeForm(formParams), headers)
	if err != nil {
		return nil, newError(ErrorInternal, errPushedAuthorizationRequestFailed, err)
	}
	if status != http.StatusCreated && status != http.StatusOK {
		return nil, parErrorFromResponse(status, header, body)
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

	buildParForm := func() ([]byte, map[string]string, error) {
		formParams, headers, buildErr := c.buildPushedRequestForm(ctx, c.deps.Clock.Now(), params, extensions, authorizationDetails)
		if buildErr != nil {
			return nil, nil, buildErr
		}
		return par.EncodeForm(formParams), headers, nil
	}
	form, headers, buildErr := buildParForm()
	if buildErr != nil {
		return nil, newError(ErrorInternal, "failed to build pushed authorization request", buildErr)
	}

	body, status, header, err := c.postParRequestWithDPoP(ctx, dpopSigner, &parURL, form, c.cachedDPoPNonce(ctx, asNonceScope), headers)
	if err != nil {
		return nil, newError(ErrorInternal, errPushedAuthorizationRequestFailed, err)
	}
	nextNonce := header.Get(dpopNonceHeader)
	c.cacheDPoPNonce(ctx, asNonceScope, nextNonce)
	if status == http.StatusCreated || status == http.StatusOK {
		return body, nil
	}

	if nextNonce == "" || !isDPoPNonceError(body) {
		return nil, parErrorFromResponse(status, header, body)
	}
	retryForm, retryHeaders, buildErr := buildParForm()
	if buildErr != nil {
		return nil, newError(ErrorInternal, "failed to build pushed authorization request", buildErr)
	}
	body, status, header, err = c.postParRequestWithDPoP(ctx, dpopSigner, &parURL, retryForm, nextNonce, retryHeaders)
	if err != nil {
		return nil, newError(ErrorInternal, errPushedAuthorizationRequestFailed, err)
	}
	c.cacheDPoPNonce(ctx, asNonceScope, header.Get(dpopNonceHeader))
	if status != http.StatusCreated && status != http.StatusOK {
		return nil, parErrorFromResponse(status, header, body)
	}
	return body, nil
}

// postParRequestWithDPoP signs a fresh DPoP proof (new iat and jti) for
// the pushed authorization request — no AccessToken/ath, since none
// exists yet at PAR time, matching how server/par.go's own dpop.Verify
// call never expects one either — and posts form to it.
func (c *Client) postParRequestWithDPoP(ctx context.Context, dpopSigner crypto.Signer, parURL *url.URL, form []byte, nonce string, extraHeaders map[string]string) ([]byte, int, http.Header, error) {
	proof, err := dpop.CreateProof(dpop.ProofRequest{
		Signer: dpopSigner, Algorithm: c.cfg.Algorithms.DPoP,
		Method: http.MethodPost, URL: parURL, Now: c.deps.Clock.Now(),
		Random: c.deps.Random, Nonce: nonce,
	})
	if err != nil {
		return nil, 0, nil, fmt.Errorf("build DPoP proof: %w", err)
	}
	return c.postForm(ctx, parURL.String(), form, mergeHeaders(map[string]string{"DPoP": proof}, extraHeaders))
}

// buildPushedRequestForm builds the PAR endpoint's form body and any
// extra headers this client's authentication method requires: a client
// assertion for authentication (or, under ClientAuthMethodAttestation,
// the Attestation-Based Client Authentication headers instead — see
// addClientAuthentication's own doc comment), plus either a signed
// request object (see signsRequestObject) or the plain authorization
// parameters directly.
func (c *Client) buildPushedRequestForm(ctx context.Context, now time.Time, params map[string]string, extensions extension.Values, authorizationDetails []json.RawMessage) (map[string]string, map[string]string, *Error) {
	form := map[string]string{}
	var (
		assertionSigner crypto.Signer
		assertionKID    string
	)
	if c.cfg.ClientAuthMethod == storage.ClientAuthMethodPrivateKeyJWT {
		var err error
		assertionSigner, assertionKID, err = c.newSigner(ctx, keys.ClientAuthentication, c.cfg.Algorithms.ClientAuthentication)
		if err != nil {
			return nil, nil, newError(ErrorInternal, "failed to resolve client authentication key", err)
		}
	}
	headers, err := c.addClientAuthentication(ctx, form, assertionSigner, assertionKID)
	if err != nil {
		return nil, nil, newError(ErrorInternal, "failed to build client authentication", err)
	}

	snapshot := extension.Snapshot(extensions)

	var authorizationDetailsRaw json.RawMessage
	if len(authorizationDetails) > 0 {
		encoded, err := json.Marshal(authorizationDetails)
		if err != nil {
			return nil, nil, newError(ErrorInternal, "failed to encode authorization_details", err)
		}
		authorizationDetailsRaw = encoded
	}

	if !c.signsRequestObject() {
		if idErr := populatePlainPushedRequestForm(form, params, snapshot, authorizationDetailsRaw); idErr != nil {
			return nil, nil, idErr
		}
		return form, headers, nil
	}

	if idErr := c.signPushedRequestForm(ctx, now, form, params, snapshot, authorizationDetailsRaw); idErr != nil {
		return nil, nil, idErr
	}
	return form, headers, nil
}

// signsRequestObject reports whether pushed authorization requests carry
// a signed request object rather than plain parameters — see
// PushedRequestEncoding.
func (c *Client) signsRequestObject() bool {
	return c.cfg.Profile == ProfileFAPISecurityWithMessageSigning ||
		c.cfg.PushedRequestEncoding == PushedRequestEncodingRequestObject
}

// populatePlainPushedRequestForm fills form with params and snapshot for
// a plain (non-message-signing) PAR request — split out of
// buildPushedRequestForm purely to keep that function's own cognitive
// complexity manageable.
func populatePlainPushedRequestForm(form, params map[string]string, snapshot map[string]json.RawMessage, authorizationDetailsRaw json.RawMessage) *Error {
	// Copy params into form (never mutate the caller's own params
	// map — pushAuthorizationRequestWithDPoPProof's own DPoP-nonce
	// retry calls this twice with the *same* params map, so writing
	// an extension's value back into params here would make the
	// second call see its own first-attempt value already present
	// and misreport it as a "core parameter" collision).
	for k, v := range params {
		form[k] = v
	}
	for name, raw := range snapshot {
		if _, reserved := params[name]; reserved {
			return newError(ErrorInvalidRequest, fmt.Sprintf("extension parameter %q collides with a core parameter name", name), nil)
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
			return newError(ErrorInvalidRequest,
				fmt.Sprintf("extension parameter %q is not a plain string; non-string extension values require a signed request object (ProfileFAPISecurityWithMessageSigning or PushedRequestEncodingRequestObject)", name), nil)
		}
		form[name] = value
	}
	if authorizationDetailsRaw != nil {
		// RFC 9396 §2: unlike an extension.Definition value, a plain
		// "authorization_details" parameter's value is itself JSON
		// array text — this is the one plain parameter this package
		// sends un-stringified, so it round-trips through
		// checkRAR/RARRegistry.Parse identically to the signed-object
		// path below, regardless of Config.Profile.
		form[authorizationDetailsParameter] = string(authorizationDetailsRaw)
	}
	return nil
}

// signPushedRequestForm builds and signs a request object embedding
// params/snapshot/authorizationDetailsRaw, storing it under form's
// "request" key — split out of buildPushedRequestForm for the same
// reason populatePlainPushedRequestForm is.
func (c *Client) signPushedRequestForm(ctx context.Context, now time.Time, form, params map[string]string, snapshot map[string]json.RawMessage, authorizationDetailsRaw json.RawMessage) *Error {
	objectParams := make(map[string]json.RawMessage)
	for k, v := range params {
		encoded, _ := json.Marshal(v) // marshaling a string cannot fail
		objectParams[k] = encoded
	}

	for name, raw := range snapshot {
		if _, reserved := objectParams[name]; reserved {
			return newError(ErrorInvalidRequest, fmt.Sprintf("extension parameter %q collides with a core parameter name", name), nil)
		}
		objectParams[name] = raw
	}

	if authorizationDetailsRaw != nil {
		objectParams[authorizationDetailsParameter] = authorizationDetailsRaw
	}
	if maxAge, ok := params[maxAgeParameter]; ok {
		// A JSON number in a request object, as OIDC Core §6.1 shows it.
		objectParams[maxAgeParameter] = json.RawMessage(maxAge)
	}
	if claims, ok := params[claimsParameter]; ok {
		objectParams[claimsParameter] = json.RawMessage(claims)
	}

	objectSigner, objectKID, err := c.newSigner(ctx, keys.RequestObjectSigning, c.cfg.Algorithms.RequestObject)
	if err != nil {
		return newError(ErrorInternal, "failed to resolve request object signing key", err)
	}
	object, err := requestobject.Create(requestobject.CreateParams{
		Signer: objectSigner, Algorithm: c.cfg.Algorithms.RequestObject, KeyID: objectKID,
		ClientID: c.cfg.ClientID.String(), Audience: c.cfg.Issuer.String(),
		Now: now, Lifetime: c.cfg.Limits.RequestObjectLifetime, Random: c.deps.Random,
		Parameters: objectParams,
	})
	if err != nil {
		return newError(ErrorInternal, "failed to build request object", err)
	}
	form["request"] = object
	return nil
}

// newSessionRecord is what this authorization attempt's session keeps
// for the callback and the code exchange: under message signing, the
// response must arrive as a signed JARM response.
func (c *Client) newSessionRecord(req BeginAuthorizationRequest, redirectURI, nonce, verifier string) sessionRecord {
	responseMode := responseModePlain
	if c.cfg.Profile == ProfileFAPISecurityWithMessageSigning {
		responseMode = responseModeJARM
	}
	record := sessionRecord{
		Nonce: nonce, PKCEVerifier: verifier, Issuer: c.cfg.Issuer.String(),
		RedirectURI: redirectURI, ResponseMode: responseMode,
		OpenID: slices.Contains(req.Scope, "openid"),
	}
	if req.HasMaxAge {
		seconds := int64(req.MaxAge / time.Second) // as sent: whole seconds, rounded down
		record.MaxAgeSeconds = &seconds
	}
	return record
}

// createSession persists record as the session for state, until
// Limits.SessionLifetime after now.
func (c *Client) createSession(ctx context.Context, state string, record sessionRecord, now time.Time) *Error {
	encoded, err := encodeSessionRecord(record)
	if err != nil {
		return newError(ErrorInternal, "failed to encode session", err)
	}
	if err := c.deps.Sessions.Create(ctx, storage.NewSession{
		State: state, Record: encoded, ExpiresAt: now.Add(c.cfg.Limits.SessionLifetime),
	}); err != nil {
		return newError(ErrorInternal, "failed to persist session", err)
	}
	return nil
}

// maxAgeSeconds is the max_age parameter for maxAge, in whole seconds:
// never negative, and at most the 100 years a session record holds.
func maxAgeSeconds(maxAge time.Duration) (int64, *Error) {
	if maxAge < 0 {
		return 0, newError(ErrorInvalidRequest, "max_age must not be negative", nil)
	}
	seconds := int64(maxAge / time.Second)
	if seconds > maxSessionMaxAgeSeconds {
		return 0, newError(ErrorInvalidRequest, "max_age must be at most 100 years", nil)
	}
	return seconds, nil
}

// checkBeginRequest checks what BeginAuthorization can before it does
// anything, and returns the redirect URI this authorization goes out
// with: Config.RedirectURI, or that with req.RedirectPort.
func (c *Client) checkBeginRequest(req BeginAuthorizationRequest) (string, *Error) {
	if scopeErr := c.checkOAuthOnlyScope(req.Scope); scopeErr != nil {
		return "", scopeErr
	}
	if req.HasMaxAge && !slices.Contains(req.Scope, "openid") {
		return "", newError(ErrorInvalidRequest, `max_age requires "openid" in Scope: only an ID token's auth_time can meet it`, nil)
	}
	if req.RedirectPort == 0 {
		return c.cfg.RedirectURI, nil
	}
	// The server matches a loopback redirect URI exactly but for its
	// port, so only the port changes: the rest is spliced through as
	// configured, never re-encoded.
	// Loopback redirects are http by definition (RFC 8252 §7.3, §8.3).
	u, err := url.Parse(c.cfg.RedirectURI)
	if err != nil || u.Scheme != "http" || u.User != nil || (u.Hostname() != "127.0.0.1" && u.Hostname() != "::1") {
		return "", newError(ErrorInvalidRequest, "RedirectPort applies only to a loopback redirect URI, http://127.0.0.1/… or http://[::1]/…", nil)
	}
	prefix := u.Scheme + "://"
	if !strings.HasPrefix(c.cfg.RedirectURI, prefix+u.Host) {
		return "", newError(ErrorInvalidRequest, "RedirectPort applies only to a loopback redirect URI, http://127.0.0.1/… or http://[::1]/…", nil)
	}
	host := net.JoinHostPort(u.Hostname(), strconv.Itoa(int(req.RedirectPort)))
	return prefix + host + c.cfg.RedirectURI[len(prefix)+len(u.Host):], nil
}
