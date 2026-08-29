package client

import (
	"bytes"
	"context"
	"crypto"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/clientassertion"
	"github.com/idfoundry/fapigo/internal/dpop"
	"github.com/idfoundry/fapigo/internal/par"
	"github.com/idfoundry/fapigo/internal/requestobject"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/storage"
)

// cibaGrantType is the grant_type value CIBA's token-endpoint polling
// step uses (CIBA §10.1) — must match server.CIBAGrantType exactly.
const cibaGrantType = "urn:openid:params:grant-type:ciba"

// defaultBackchannelAuthenticationPollInterval is the minimum poll
// interval BackchannelAuthenticationSession.Interval assumes when a
// server's response omits "interval" — OpenID Connect CIBA Core 1.0
// §11's own fallback ("If the Client is not informed of the Interval
// it should assume a default of 5 seconds").
const defaultBackchannelAuthenticationPollInterval = 5 * time.Second

// BeginBackchannelAuthenticationRequest is the input to
// Client.BeginBackchannelAuthentication. Exactly one of LoginHint,
// LoginHintToken or IDTokenHint must be set — validated locally before
// any network call, mirroring the server's own
// validateBackchannelAuthenticationParameters check, so a caller gets
// an immediate ErrorInvalidRequest instead of a round trip.
type BeginBackchannelAuthenticationRequest struct {
	Scope []string

	LoginHint      string
	LoginHintToken string
	IDTokenHint    string

	// ACRValues optionally requests specific Authentication Context
	// Class Reference values (mirrors BeginAuthorizationRequest.ACRValues).
	ACRValues []string

	// BindingMessage is a human-readable string displayed on both the
	// consumption device (this client) and the authentication device,
	// to let the end user confirm the two devices are talking about
	// the same request (CIBA §7.1).
	BindingMessage string

	// RequestedExpiry optionally bounds how long the returned
	// auth_req_id remains pollable (CIBA §7.1's "requested_expiry").
	// Zero means "don't send requested_expiry" — the server applies
	// its own default.
	RequestedExpiry time.Duration
}

// BackchannelAuthenticationSession is returned by a successful
// BeginBackchannelAuthentication. Unlike AuthorizationSession (whose
// SessionHandle is deliberately opaque — the browser never needs the
// underlying value), AuthReqID's raw wire value IS what
// PollBackchannelAuthentication presents back to the server directly —
// there is no browser round trip to hide it from — so it has a plain
// string accessor, the same relationship RequestURI already has to its
// own wire value.
type BackchannelAuthenticationSession struct {
	authReqID         string
	interval          time.Duration
	expiresAt         time.Time
	notificationToken string
}

// AuthReqID is the auth_req_id the authorization server issued.
func (s BackchannelAuthenticationSession) AuthReqID() string { return s.authReqID }

// Interval is the minimum time to wait between polls (CIBA §10.3's
// "interval") — defaultBackchannelAuthenticationPollInterval if the
// server's response omitted one.
func (s BackchannelAuthenticationSession) Interval() time.Duration { return s.interval }

// ExpiresAt is when this session's auth_req_id stops being pollable.
func (s BackchannelAuthenticationSession) ExpiresAt() time.Time { return s.expiresAt }

// NotificationToken is the client_notification_token this client sent
// with its backchannel authentication request, under
// Config.BackchannelTokenDeliveryMode == storage.BackchannelTokenDeliveryModePing
// — empty under the default (Poll). This package never receives the
// resulting CIBA §10.2 ping callback itself (it has no HTTP server of
// its own); the caller is responsible for persisting this value
// alongside whatever it already tracks about the pending session, and,
// in its own webhook handler, comparing an incoming ping's bearer
// token against it (a constant-time comparison — crypto/subtle.ConstantTimeCompare)
// before calling PollBackchannelAuthentication.
func (s BackchannelAuthenticationSession) NotificationToken() string { return s.notificationToken }

// BeginBackchannelAuthentication builds and signs a CIBA backchannel
// authentication request (FAPI-CIBA always requires a signed request —
// there is no plain-parameter path, unlike PAR under the baseline
// profile), authenticates with a client assertion, presents a DPoP
// proof bound to the request, and returns the resulting
// BackchannelAuthenticationSession for the caller to poll.
func (c *Client) BeginBackchannelAuthentication(ctx context.Context, req BeginBackchannelAuthenticationRequest) (BackchannelAuthenticationSession, error) {
	hints := 0
	if req.LoginHint != "" {
		hints++
	}
	if req.LoginHintToken != "" {
		hints++
	}
	if req.IDTokenHint != "" {
		hints++
	}
	if hints != 1 {
		return BackchannelAuthenticationSession{}, newError(ErrorInvalidRequest, "exactly one of LoginHint, LoginHintToken, or IDTokenHint is required", nil)
	}
	if c.cfg.Endpoints.BackchannelAuthentication.IsZero() {
		return BackchannelAuthenticationSession{}, newError(ErrorInvalidRequest, "backchannel authentication is not configured", nil)
	}

	objectParams := map[string]json.RawMessage{}
	scope, _ := json.Marshal(strings.Join(req.Scope, " ")) // marshaling a string cannot fail
	objectParams["scope"] = scope
	switch {
	case req.LoginHint != "":
		encoded, _ := json.Marshal(req.LoginHint)
		objectParams["login_hint"] = encoded
	case req.LoginHintToken != "":
		encoded, _ := json.Marshal(req.LoginHintToken)
		objectParams["login_hint_token"] = encoded
	case req.IDTokenHint != "":
		encoded, _ := json.Marshal(req.IDTokenHint)
		objectParams["id_token_hint"] = encoded
	}
	if len(req.ACRValues) > 0 {
		encoded, _ := json.Marshal(strings.Join(req.ACRValues, " "))
		objectParams["acr_values"] = encoded
	}
	if req.BindingMessage != "" {
		encoded, _ := json.Marshal(req.BindingMessage)
		objectParams["binding_message"] = encoded
	}
	if req.RequestedExpiry > 0 {
		encoded, _ := json.Marshal(int64(req.RequestedExpiry / time.Second))
		objectParams["requested_expiry"] = encoded
	}

	// notificationToken is exposed on the returned session (see
	// BackchannelAuthenticationSession.NotificationToken's own doc
	// comment) — generated fresh per call, the same way state/nonce/
	// SessionHandle values are, never reused across requests.
	var notificationToken string
	if c.cfg.BackchannelTokenDeliveryMode == storage.BackchannelTokenDeliveryModePing {
		var err error
		notificationToken, err = generateRandomToken(c.deps.Random)
		if err != nil {
			return BackchannelAuthenticationSession{}, newError(ErrorInternal, "failed to generate client notification token", err)
		}
		encoded, _ := json.Marshal(notificationToken)
		objectParams["client_notification_token"] = encoded
	}

	objectSigner, objectKID, err := c.newSigner(ctx, keys.BackchannelAuthenticationRequestSigning, c.cfg.Algorithms.BackchannelAuthenticationRequest)
	if err != nil {
		return BackchannelAuthenticationSession{}, newError(ErrorInternal, "failed to resolve backchannel authentication request signing key", err)
	}
	assertionSigner, assertionKID, dpopSigner, err := c.resolveClientAuthAndDPoPSigners(ctx)
	if err != nil {
		return BackchannelAuthenticationSession{}, newError(ErrorInternal, "failed to resolve signing keys", err)
	}

	// buildForm signs a fresh request object and client assertion (new
	// iat/jti) every time it's called, including for a retry after a
	// use_dpop_nonce challenge — both are exactly as single-use as a
	// DPoP proof is, mirroring buildPushedRequestForm/buildTokenForm's
	// own reasoning.
	buildForm := func() ([]byte, error) {
		now := c.deps.Clock.Now()
		object, err := requestobject.Create(requestobject.CreateParams{
			Signer: objectSigner, Algorithm: c.cfg.Algorithms.BackchannelAuthenticationRequest, KeyID: objectKID,
			ClientID: c.cfg.ClientID.String(), Audience: c.cfg.Issuer.String(),
			Now: now, Lifetime: c.cfg.Limits.BackchannelAuthenticationRequestLifetime, Random: c.deps.Random,
			Parameters: objectParams,
		})
		if err != nil {
			return nil, fmt.Errorf("build backchannel authentication request object: %w", err)
		}
		form := map[string]string{"request": object}
		if c.cfg.ClientAuthMethod == storage.ClientAuthMethodPrivateKeyJWT {
			assertion, err := clientassertion.CreateAssertion(clientassertion.AssertionRequest{
				Signer: assertionSigner, Algorithm: c.cfg.Algorithms.ClientAuthentication, KeyID: assertionKID,
				ClientID: c.cfg.ClientID.String(), Audience: c.cfg.Issuer.String(),
				Now: now, Lifetime: c.cfg.Limits.ClientAssertionLifetime, Random: c.deps.Random,
			})
			if err != nil {
				return nil, fmt.Errorf("build client assertion: %w", err)
			}
			form["client_assertion"] = assertion
			form["client_assertion_type"] = clientassertion.AssertionType
		} else {
			form["client_id"] = c.cfg.ClientID.String()
		}
		return par.EncodeForm(form), nil
	}

	form, buildErr := buildForm()
	if buildErr != nil {
		return BackchannelAuthenticationSession{}, newError(ErrorInternal, "failed to build backchannel authentication request", buildErr)
	}

	endpointURL := c.cfg.Endpoints.BackchannelAuthentication.URL()
	body, sendErr := c.sendBackchannelAuthenticationRequest(ctx, dpopSigner, &endpointURL, buildForm, form)
	if sendErr != nil {
		return BackchannelAuthenticationSession{}, sendErr
	}

	raw, err := decodeBackchannelAuthenticationResponse(body)
	if err != nil {
		return BackchannelAuthenticationSession{}, newError(ErrorInvalidResponse, "malformed backchannel authentication response", err)
	}

	interval := time.Duration(raw.Interval) * time.Second
	if interval <= 0 {
		interval = defaultBackchannelAuthenticationPollInterval
	}
	return BackchannelAuthenticationSession{
		authReqID:         raw.AuthReqID,
		interval:          interval,
		expiresAt:         c.deps.Clock.Now().Add(time.Duration(raw.ExpiresIn) * time.Second),
		notificationToken: notificationToken,
	}, nil
}

// postBackchannelAuthenticationRequestWithDPoP signs a fresh DPoP proof
// (new iat and jti) for the backchannel authentication request — no
// AccessToken/ath, since none exists yet at this point, mirroring
// postParRequestWithDPoP — and posts form to it.
func (c *Client) postBackchannelAuthenticationRequestWithDPoP(ctx context.Context, dpopSigner crypto.Signer, endpointURL *url.URL, form []byte, nonce string) ([]byte, int, http.Header, error) {
	proof, err := dpop.CreateProof(dpop.ProofRequest{
		Signer: dpopSigner, Algorithm: c.cfg.Algorithms.DPoP,
		Method: http.MethodPost, URL: endpointURL, Now: c.deps.Clock.Now(),
		Random: c.deps.Random, Nonce: nonce,
	})
	if err != nil {
		return nil, 0, nil, fmt.Errorf("build DPoP proof: %w", err)
	}
	return c.postForm(ctx, endpointURL.String(), form, map[string]string{"DPoP": proof})
}

// sendBackchannelAuthenticationRequest posts form to the backchannel
// authentication endpoint. Under SenderConstrainDPoP (the default), it
// presents a DPoP-proofed request, retrying once on a use_dpop_nonce
// challenge exactly like pushAuthorizationRequestWithDPoPProof does for
// PAR. Under SenderConstrainMTLS, dpopSigner is unused (pass nil) — a
// single plain call, no proof, no nonce retry, mirroring
// pushAuthorizationRequestPlain's own reasoning.
func (c *Client) sendBackchannelAuthenticationRequest(ctx context.Context, dpopSigner crypto.Signer, endpointURL *url.URL, buildForm func() ([]byte, error), form []byte) ([]byte, *Error) {
	if c.cfg.SenderConstrain == storage.SenderConstrainMTLS {
		body, status, _, err := c.postForm(ctx, endpointURL.String(), form, nil)
		if err != nil {
			return nil, newError(ErrorInternal, "backchannel authentication request failed", err)
		}
		if status != http.StatusOK {
			return nil, parErrorFromResponse(body)
		}
		return body, nil
	}
	body, status, header, err := c.postBackchannelAuthenticationRequestWithDPoP(ctx, dpopSigner, endpointURL, form, c.cachedDPoPNonce(ctx, asNonceScope))
	if err != nil {
		return nil, newError(ErrorInternal, "backchannel authentication request failed", err)
	}
	nextNonce := header.Get("DPoP-Nonce")
	c.cacheDPoPNonce(ctx, asNonceScope, nextNonce)
	if status == http.StatusOK {
		return body, nil
	}
	if nextNonce == "" || !isDPoPNonceError(body) {
		return nil, parErrorFromResponse(body)
	}
	retryForm, buildErr := buildForm()
	if buildErr != nil {
		return nil, newError(ErrorInternal, "failed to build backchannel authentication request", buildErr)
	}
	body, status, header, err = c.postBackchannelAuthenticationRequestWithDPoP(ctx, dpopSigner, endpointURL, retryForm, nextNonce)
	if err != nil {
		return nil, newError(ErrorInternal, "backchannel authentication request failed", err)
	}
	c.cacheDPoPNonce(ctx, asNonceScope, header.Get("DPoP-Nonce"))
	if status != http.StatusOK {
		return nil, parErrorFromResponse(body)
	}
	return body, nil
}

type rawBackchannelAuthenticationResponse struct {
	AuthReqID string `json:"auth_req_id"`
	ExpiresIn int64  `json:"expires_in"`
	Interval  int64  `json:"interval,omitempty"`
}

// decodeBackchannelAuthenticationResponse parses body, tolerating any
// member beyond rawBackchannelAuthenticationResponse's own fields —
// same RFC 6749 §5.1 "ignore unrecognized parameters" reasoning
// decodeTokenResponse already applies.
func decodeBackchannelAuthenticationResponse(body []byte) (rawBackchannelAuthenticationResponse, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	var raw rawBackchannelAuthenticationResponse
	if err := dec.Decode(&raw); err != nil {
		return rawBackchannelAuthenticationResponse{}, fmt.Errorf("decode backchannel authentication response: %w", err)
	}
	if raw.AuthReqID == "" {
		return rawBackchannelAuthenticationResponse{}, fmt.Errorf("auth_req_id is missing")
	}
	if raw.ExpiresIn <= 0 {
		return rawBackchannelAuthenticationResponse{}, fmt.Errorf("expires_in must be positive")
	}
	if raw.Interval < 0 {
		return rawBackchannelAuthenticationResponse{}, fmt.Errorf("interval must not be negative")
	}
	return raw, nil
}

// BackchannelAuthenticationResult is a closed sum type returned by
// PollBackchannelAuthentication, mirroring CompletionResult's own
// shape for the browser flow.
type BackchannelAuthenticationResult interface {
	backchannelAuthenticationResult()
}

// BackchannelAuthenticationPending means no decision has been made
// yet. SlowDown reports whether this specific poll was rejected for
// being too fast (CIBA §10.3's slow_down) rather than merely still
// pending — RFC 8628's own convention is for the caller to widen its
// own interval by 5s when this is true, but this package leaves that
// policy decision to the caller rather than picking one on its
// behalf.
type BackchannelAuthenticationPending struct{ SlowDown bool }

func (BackchannelAuthenticationPending) backchannelAuthenticationResult() {}

// BackchannelAuthenticationDenied means the end user (or the
// authorization server on their behalf) declined the request.
type BackchannelAuthenticationDenied struct{ Code, Description string }

func (BackchannelAuthenticationDenied) backchannelAuthenticationResult() {}

// BackchannelAuthenticationExpired means auth_req_id's own expiry
// passed before a decision was made.
type BackchannelAuthenticationExpired struct{}

func (BackchannelAuthenticationExpired) backchannelAuthenticationResult() {}

// BackchannelAuthenticationApproved means the request was approved and
// Tokens were issued.
type BackchannelAuthenticationApproved struct{ Tokens TokenSet }

func (BackchannelAuthenticationApproved) backchannelAuthenticationResult() {}

// PollBackchannelAuthentication performs a single token-endpoint poll
// for session's auth_req_id (CIBA §10.1/§10.3). It makes exactly one
// attempt — no blocking sleep-loop — so an embedder driving CIBA from a
// job queue, cron, or event loop calls this on its own schedule rather
// than having the calling goroutine block for however long a human
// takes to approve an out-of-band request.
func (c *Client) PollBackchannelAuthentication(ctx context.Context, session BackchannelAuthenticationSession) (BackchannelAuthenticationResult, error) {
	assertionSigner, assertionKID, dpopSigner, err := c.resolveClientAuthAndDPoPSigners(ctx)
	if err != nil {
		return nil, newError(ErrorInternal, "failed to resolve signing keys", err)
	}
	tokenURL := c.cfg.Endpoints.Token.URL()

	buildPollForm := func() ([]byte, error) {
		form := map[string]string{
			"grant_type":  cibaGrantType,
			"auth_req_id": session.authReqID,
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

	form, buildErr := buildPollForm()
	if buildErr != nil {
		return nil, newError(ErrorInternal, "failed to build client assertion", buildErr)
	}
	body, status, pollErr := c.pollBackchannelAuthenticationOnce(ctx, dpopSigner, &tokenURL, buildPollForm, form)
	if pollErr != nil {
		return nil, pollErr
	}

	if status == http.StatusOK {
		raw, err := decodeTokenResponse(body)
		if err != nil {
			return nil, newError(ErrorInvalidResponse, "malformed token response", err)
		}
		wantTokenType := tokenTypeFor(c.cfg.SenderConstrain)
		if !strings.EqualFold(raw.TokenType, wantTokenType) {
			return nil, newError(ErrorInvalidResponse, fmt.Sprintf("token response token_type is not %s", wantTokenType), nil)
		}
		result := TokenSet{
			AccessToken: fapi.NewSecret(raw.AccessToken),
			TokenType:   wantTokenType,
			Scope:       raw.Scope,
		}
		if raw.ExpiresIn > 0 {
			result.ExpiresIn = time.Duration(raw.ExpiresIn) * time.Second
			result.HasExpiresIn = true
		}
		// CIBA has no browser round trip, so there is no "nonce"
		// authorization parameter to bind the ID token to — the same
		// reason server.ExchangeBackchannelAuthentication issues its
		// own ID token with an empty nonce (server/backchannel_token.go).
		if idErr := c.populateIDToken(ctx, &result, raw, ""); idErr != nil {
			return nil, idErr
		}
		if raw.RefreshToken != "" {
			result.RefreshToken = fapi.NewSecret(raw.RefreshToken)
			result.HasRefreshToken = true
		}
		return BackchannelAuthenticationApproved{Tokens: result}, nil
	}

	errResp, decodeErr := par.DecodeErrorResponse(body)
	if decodeErr != nil {
		return nil, parErrorFromResponse(body)
	}
	switch errResp.Code {
	case "authorization_pending":
		return BackchannelAuthenticationPending{}, nil
	case "slow_down":
		return BackchannelAuthenticationPending{SlowDown: true}, nil
	case "access_denied":
		return BackchannelAuthenticationDenied{Code: errResp.Code, Description: errResp.Description}, nil
	case "expired_token":
		return BackchannelAuthenticationExpired{}, nil
	default:
		return nil, parErrorFromResponse(body)
	}
}

// pollBackchannelAuthenticationOnce sends one CIBA token-endpoint poll.
// Under SenderConstrainDPoP (the default), it retries once on a
// use_dpop_nonce challenge exactly like sendTokenRequest does for the
// authorization-code flow (RFC 9449 §8); a non-200 response is
// returned to the caller for inspection rather than immediately
// converted to a terminal *Error: PollBackchannelAuthentication's own
// non-200 branch needs the raw OAuth error code (authorization_pending,
// slow_down, access_denied, expired_token are expected polling
// outcomes, not failures), which parErrorFromResponse's translation
// discards. Under SenderConstrainMTLS, dpopSigner is unused (pass
// nil) — a single plain call, no proof, no nonce retry.
func (c *Client) pollBackchannelAuthenticationOnce(ctx context.Context, dpopSigner crypto.Signer, tokenURL *url.URL, buildForm func() ([]byte, error), form []byte) ([]byte, int, *Error) {
	if c.cfg.SenderConstrain == storage.SenderConstrainMTLS {
		body, status, _, err := c.postForm(ctx, tokenURL.String(), form, nil)
		if err != nil {
			return nil, 0, newError(ErrorInternal, "token request failed", err)
		}
		return body, status, nil
	}
	body, status, header, err := c.postTokenRequestWithDPoP(ctx, dpopSigner, tokenURL, form, c.cachedDPoPNonce(ctx, asNonceScope))
	if err != nil {
		return nil, 0, newError(ErrorInternal, "token request failed", err)
	}
	nextNonce := header.Get("DPoP-Nonce")
	c.cacheDPoPNonce(ctx, asNonceScope, nextNonce)
	if status == http.StatusOK || nextNonce == "" || !isDPoPNonceError(body) {
		return body, status, nil
	}
	retryForm, buildErr := buildForm()
	if buildErr != nil {
		return nil, 0, newError(ErrorInternal, "failed to build client assertion", buildErr)
	}
	body, status, header, err = c.postTokenRequestWithDPoP(ctx, dpopSigner, tokenURL, retryForm, nextNonce)
	if err != nil {
		return nil, 0, newError(ErrorInternal, "token request failed", err)
	}
	c.cacheDPoPNonce(ctx, asNonceScope, header.Get("DPoP-Nonce"))
	return body, status, nil
}

// resolveClientAuthAndDPoPSigners resolves the pair of signers both
// BeginBackchannelAuthentication and PollBackchannelAuthentication need
// before building their own request form: assertionSigner/assertionKID
// stay nil/"" when ClientAuthMethod isn't ClientAuthMethodPrivateKeyJWT
// (no client_assertion is ever built in that case), and dpopSigner
// stays nil under SenderConstrainMTLS (no DPoP proof is ever built).
func (c *Client) resolveClientAuthAndDPoPSigners(ctx context.Context) (assertionSigner crypto.Signer, assertionKID string, dpopSigner crypto.Signer, err error) {
	if c.cfg.ClientAuthMethod == storage.ClientAuthMethodPrivateKeyJWT {
		assertionSigner, assertionKID, err = c.newSigner(ctx, keys.ClientAuthentication, c.cfg.Algorithms.ClientAuthentication)
		if err != nil {
			return nil, "", nil, fmt.Errorf("resolve client authentication key: %w", err)
		}
	}
	if c.cfg.SenderConstrain == storage.SenderConstrainDPoP {
		dpopSigner, _, err = c.newSigner(ctx, keys.DPoPProofSigning, c.cfg.Algorithms.DPoP)
		if err != nil {
			return nil, "", nil, fmt.Errorf("resolve DPoP signing key: %w", err)
		}
	}
	return assertionSigner, assertionKID, dpopSigner, nil
}
