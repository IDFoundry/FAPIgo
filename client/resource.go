package client

import (
	"bytes"
	"context"
	"crypto"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/idfoundry/fapigo/internal/dpop"
	"github.com/idfoundry/fapigo/keys"
)

var (
	// errRequestBodyNotReplayable indicates req.Body was non-nil but
	// req.GetBody was nil, so Do could not safely resend it for a DPoP
	// nonce retry.
	errRequestBodyNotReplayable = errors.New("client: request body is not replayable (GetBody is nil)")

	// errResponseBodyTooLarge indicates a protected resource's response
	// body exceeded Config.Limits.MaxHTTPResponseBytes.
	errResponseBodyTooLarge = errors.New("client: response body exceeds the configured size limit")
)

// ResourceClient performs DPoP-bound requests to a protected resource
// with one already-issued access token — most commonly the OIDC
// UserInfo endpoint, but any FAPI 2.0 protected resource sender-
// constrained to the same token follows the identical shape (RFC 9449
// §4-§9): attach the token, prove possession of the DPoP key it's bound
// to, and retry once if the resource server challenges for a fresh
// nonce. It has no public constructor — only Client.ProtectedResource
// produces one, always scoped to a specific TokenSet, so a caller can't
// assemble one detached from an actual access token.
type ResourceClient struct {
	client *Client
	token  string
}

// ProtectedResource returns a ResourceClient bound to tokens' access
// token, ready to make DPoP-bound requests to a protected resource with
// it — reusing the same DPoP key ExchangeCode originally bound the
// token to, so every proof's JWK thumbprint keeps matching the token's
// own cnf.jkt automatically, without this package ever exposing that
// key to the caller.
func (c *Client) ProtectedResource(tokens TokenSet) *ResourceClient {
	return &ResourceClient{client: c, token: tokens.AccessToken.Reveal()}
}

// Do performs req as a DPoP-bound request: it sets "Authorization: DPoP
// <token>" and a fresh signed DPoP proof (RFC 9449 §4, with "ath" bound
// to the access token per §4.3), bounded by Config.Limits.HTTPTimeout
// and Config.Limits.MaxHTTPResponseBytes — the same protections this
// client applies to its own PAR and token-endpoint calls. If the
// resource server challenges with a fresh nonce (RFC 9449 §9: HTTP 401,
// a WWW-Authenticate: DPoP challenge naming use_dpop_nonce, and a
// DPoP-Nonce header), Do retries exactly once with that nonce echoed
// into a fresh proof; any other response — including a second nonce
// challenge — is returned as-is for the caller to interpret. As with
// the token endpoint's own nonce retry, the DPoP-Nonce header alone is
// not sufficient grounds to retry: a resource server may send it
// unprompted to pre-seed a caller's next request, so the retry is
// gated on the WWW-Authenticate challenge itself too.
//
// req's body, if any, must be replayable — Do may send it twice — so
// req.GetBody must be set; http.NewRequestWithContext sets it
// automatically for the body types it accepts (e.g. *bytes.Reader,
// *strings.Reader). req's own context is replaced with one bounded by
// Config.Limits.HTTPTimeout.
func (rc *ResourceClient) Do(ctx context.Context, req *http.Request) (*http.Response, error) {
	if req == nil {
		return nil, newError(ErrorInvalidRequest, "request is nil", nil)
	}
	c := rc.client
	dpopSigner, _, err := c.newSigner(ctx, keys.DPoPProofSigning, c.cfg.Algorithms.DPoP)
	if err != nil {
		return nil, newError(ErrorInternal, "failed to resolve DPoP signing key", err)
	}

	ctx, cancel := context.WithTimeout(ctx, c.cfg.Limits.HTTPTimeout)
	defer cancel()

	res, err := rc.send(ctx, dpopSigner, req, "")
	if err != nil {
		return nil, newError(ErrorInternal, "protected resource request failed", err)
	}
	if isResourceDPoPNonceChallenge(res.StatusCode, res.Header) {
		nonce := res.Header.Get("DPoP-Nonce")
		_ = res.Body.Close()
		retryReq, retryErr := rebuildRequestBody(req)
		if retryErr != nil {
			return nil, newError(ErrorInvalidRequest, "request body is not replayable for a DPoP nonce retry", retryErr)
		}
		res, err = rc.send(ctx, dpopSigner, retryReq, nonce)
		if err != nil {
			return nil, newError(ErrorInternal, "protected resource request failed", err)
		}
	}

	bounded, err := boundResponseBody(res, c.cfg.Limits.MaxHTTPResponseBytes)
	if err != nil {
		return nil, newError(ErrorInvalidResponse, "protected resource response too large", err)
	}
	return bounded, nil
}

// send signs a fresh DPoP proof (new iat and jti — reusing one across
// two requests, including a retry, would make the retry look replayed,
// exactly as postTokenRequestWithDPoP's own doc comment explains) bound
// to req and performs it.
func (rc *ResourceClient) send(ctx context.Context, signer crypto.Signer, req *http.Request, nonce string) (*http.Response, error) {
	proof, err := dpop.CreateProof(dpop.ProofRequest{
		Signer: signer, Algorithm: rc.client.cfg.Algorithms.DPoP,
		Method: req.Method, URL: req.URL, AccessToken: rc.token,
		Nonce: nonce, Now: rc.client.deps.Clock.Now(), Random: rc.client.deps.Random,
	})
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	req.Header.Set("Authorization", "DPoP "+rc.token)
	req.Header.Set("DPoP", proof)
	return rc.client.deps.HTTP.Do(req)
}

// isResourceDPoPNonceChallenge reports whether status/header is a
// protected resource's RFC 9449 §9 nonce challenge.
func isResourceDPoPNonceChallenge(status int, header http.Header) bool {
	if status != http.StatusUnauthorized || header.Get("DPoP-Nonce") == "" {
		return false
	}
	challenge := header.Get("WWW-Authenticate")
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(challenge)), "dpop") &&
		strings.Contains(challenge, `error="use_dpop_nonce"`)
}

// rebuildRequestBody returns a copy of req with a fresh, unconsumed
// body — req.GetBody() re-invoked — so a retried request doesn't send
// an already-drained reader. A body-less request (req.Body == nil, the
// common case for a GET) is always replayable.
func rebuildRequestBody(req *http.Request) (*http.Request, error) {
	clone := req.Clone(req.Context())
	if req.Body == nil {
		return clone, nil
	}
	if req.GetBody == nil {
		return nil, errRequestBodyNotReplayable
	}
	body, err := req.GetBody()
	if err != nil {
		return nil, err
	}
	clone.Body = body
	return clone, nil
}

// boundResponseBody reads res's body up to max bytes, replacing it with
// an in-memory, replay-safe reader — the same eager-read-and-bound
// discipline postForm applies to every other outbound response this
// client reads, so a caller can't be handed an unbounded stream by
// mistake.
func boundResponseBody(res *http.Response, max int64) (*http.Response, error) {
	data, readErr := io.ReadAll(io.LimitReader(res.Body, max+1))
	closeErr := res.Body.Close()
	if readErr != nil {
		return nil, readErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if int64(len(data)) > max {
		return nil, errResponseBodyTooLarge
	}
	res.Body = io.NopCloser(bytes.NewReader(data))
	res.ContentLength = int64(len(data))
	return res, nil
}
