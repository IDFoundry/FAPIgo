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

	fapi "github.com/osanderson/go-fapi"
	"github.com/osanderson/go-fapi/internal/clientassertion"
	"github.com/osanderson/go-fapi/internal/dpop"
	"github.com/osanderson/go-fapi/internal/par"
	"github.com/osanderson/go-fapi/internal/token"
	"github.com/osanderson/go-fapi/keys"
)

// TokenSet is returned by a successful ExchangeCode.
type TokenSet struct {
	AccessToken fapi.Secret
	TokenType   string // always "DPoP", regardless of the casing the server responded with (RFC 6749 §7.1: token_type is case insensitive)
	Scope       string

	// ExpiresIn is set only when the token response actually carried
	// expires_in — RFC 6749 §5.1 marks it RECOMMENDED, not REQUIRED, and
	// explicitly permits an authorization server to omit it and
	// communicate the token's lifetime "via other means" instead. Zero
	// does not mean "expires immediately"; check HasExpiresIn first.
	ExpiresIn    time.Duration
	HasExpiresIn bool

	// IDToken and Subject are set only when the granted scope included
	// "openid". Subject comes from the validated ID token, never from an
	// unverified claim.
	IDToken    fapi.Secret
	HasIDToken bool
	Subject    string

	// RefreshToken is set only when the authorization server issued one.
	RefreshToken    fapi.Secret
	HasRefreshToken bool
}

// ExchangeCode authenticates to the token endpoint, presents a DPoP
// proof bound to this request, and redeems resp's authorization code for
// an access token — validating any returned ID token before trusting its
// subject claim.
func (c *Client) ExchangeCode(ctx context.Context, resp ValidatedAuthorizationResponse) (TokenSet, error) {
	assertionSigner, assertionKID, err := c.newSigner(ctx, keys.ClientAuthentication, c.cfg.Algorithms.ClientAuthentication)
	if err != nil {
		return TokenSet{}, newError(ErrorInternal, "failed to resolve client authentication key", err)
	}
	dpopSigner, _, err := c.newSigner(ctx, keys.DPoPProofSigning, c.cfg.Algorithms.DPoP)
	if err != nil {
		return TokenSet{}, newError(ErrorInternal, "failed to resolve DPoP signing key", err)
	}
	tokenURL := c.cfg.Endpoints.Token.URL()

	// buildTokenForm signs a fresh client assertion (new iat and jti)
	// every time it's called, including for a retry after a
	// use_dpop_nonce challenge: a client assertion is exactly as
	// single-use as a DPoP proof is, and reusing one across two token
	// requests gets the retry rejected as jti replay even though the
	// first request never actually succeeded — confirmed live against
	// the OIDF conformance suite's own DPoP-nonce-requiring RP test,
	// which reports it as CheckForClientAssertionJtiReuse.
	buildTokenForm := func() ([]byte, error) {
		assertion, err := clientassertion.CreateAssertion(clientassertion.AssertionRequest{
			Signer: assertionSigner, Algorithm: c.cfg.Algorithms.ClientAuthentication, KeyID: assertionKID,
			ClientID: c.cfg.ClientID.String(), Audience: c.cfg.Issuer.String(),
			Now: c.deps.Clock.Now(), Lifetime: c.cfg.Limits.ClientAssertionLifetime, Random: c.deps.Random,
		})
		if err != nil {
			return nil, err
		}
		return par.EncodeForm(map[string]string{
			"grant_type":            "authorization_code",
			"code":                  resp.code,
			"redirect_uri":          resp.redirectURI,
			"code_verifier":         resp.pkceVerifier,
			"client_assertion":      assertion,
			"client_assertion_type": clientassertion.AssertionType,
		}), nil
	}

	form, err := buildTokenForm()
	if err != nil {
		return TokenSet{}, newError(ErrorInternal, "failed to build client assertion", err)
	}
	body, status, header, err := c.postTokenRequestWithDPoP(ctx, dpopSigner, &tokenURL, form, "")
	if err != nil {
		return TokenSet{}, newError(ErrorInternal, "token request failed", err)
	}
	if status != http.StatusOK {
		// RFC 9449 §8: an authorization server that requires a
		// server-provided DPoP nonce rejects a proof lacking one (or
		// carrying a stale one) with use_dpop_nonce and a DPoP-Nonce
		// response header naming the value to use — the client is
		// expected to retry once with a fresh proof carrying it, not
		// treat this as a terminal failure.
		if nonce := header.Get("DPoP-Nonce"); nonce != "" && isDPoPNonceError(body) {
			retryForm, buildErr := buildTokenForm()
			if buildErr != nil {
				return TokenSet{}, newError(ErrorInternal, "failed to build client assertion", buildErr)
			}
			body, status, _, err = c.postTokenRequestWithDPoP(ctx, dpopSigner, &tokenURL, retryForm, nonce)
			if err != nil {
				return TokenSet{}, newError(ErrorInternal, "token request failed", err)
			}
		}
		if status != http.StatusOK {
			return TokenSet{}, parErrorFromResponse(body)
		}
	}

	raw, err := decodeTokenResponse(body)
	if err != nil {
		return TokenSet{}, newError(ErrorInvalidResponse, "malformed token response", err)
	}
	if !strings.EqualFold(raw.TokenType, "DPoP") {
		return TokenSet{}, newError(ErrorInvalidResponse, "token response token_type is not DPoP", nil)
	}

	result := TokenSet{
		AccessToken: fapi.NewSecret(raw.AccessToken),
		TokenType:   "DPoP",
		Scope:       raw.Scope,
	}
	if raw.ExpiresIn > 0 {
		result.ExpiresIn = time.Duration(raw.ExpiresIn) * time.Second
		result.HasExpiresIn = true
	}

	if raw.IDToken != "" {
		subject, idErr := c.validateIDToken(ctx, raw.IDToken, resp.nonce)
		if idErr != nil {
			return TokenSet{}, idErr
		}
		result.IDToken = fapi.NewSecret(raw.IDToken)
		result.HasIDToken = true
		result.Subject = subject
	}
	if raw.RefreshToken != "" {
		result.RefreshToken = fapi.NewSecret(raw.RefreshToken)
		result.HasRefreshToken = true
	}

	return result, nil
}

// postTokenRequestWithDPoP signs a fresh DPoP proof for the token
// request — bound to POST tokenURL, carrying nonce if the authorization
// server previously challenged for one (RFC 9449 §8) — and posts form to
// it. A fresh proof (new iat and jti) is built on every call, including
// a retry after a use_dpop_nonce challenge: reusing the first proof's
// timestamp/jti for the retry would make it look replayed.
func (c *Client) postTokenRequestWithDPoP(ctx context.Context, dpopSigner crypto.Signer, tokenURL *url.URL, form []byte, nonce string) ([]byte, int, http.Header, error) {
	proof, err := dpop.CreateProof(dpop.ProofRequest{
		Signer: dpopSigner, Algorithm: c.cfg.Algorithms.DPoP,
		Method: http.MethodPost, URL: tokenURL, Now: c.deps.Clock.Now(),
		Random: c.deps.Random, Nonce: nonce,
	})
	if err != nil {
		return nil, 0, nil, fmt.Errorf("build DPoP proof: %w", err)
	}
	return c.postForm(ctx, tokenURL.String(), form, map[string]string{"DPoP": proof})
}

// isDPoPNonceError reports whether body is an OAuth error response whose
// code is "use_dpop_nonce" (RFC 9449 §8). A DPoP-Nonce response header
// alone isn't sufficient grounds to retry — a server may also send that
// header on an unrelated error, or even on success, to pre-seed the
// nonce for a caller's *next* request — so the retry is gated on both
// signals being present together, not just the header.
func isDPoPNonceError(body []byte) bool {
	errResp, err := par.DecodeErrorResponse(body)
	return err == nil && errResp.Code == "use_dpop_nonce"
}

func (c *Client) validateIDToken(ctx context.Context, raw, nonce string) (string, *Error) {
	parsed, err := token.ParseIDToken(raw)
	if err != nil {
		return "", newError(ErrorInvalidResponse, "malformed ID token", err)
	}

	candidates, err := c.deps.IssuerKeys.ResolveIssuerKeys(ctx, keys.IssuerKeyRequest{
		Issuer: c.cfg.Issuer.String(), Purpose: keys.IDTokenVerification,
		Algorithm: c.cfg.Algorithms.IDToken, KeyID: parsed.KeyID(),
	})
	if err != nil {
		return "", newError(ErrorInternal, "failed to resolve issuer keys", err)
	}
	if len(candidates.Keys) == 0 {
		return "", newError(ErrorInvalidResponse, "no matching issuer key for ID token", nil)
	}

	var (
		validated token.ValidatedIDToken
		verifyErr error
	)
	for _, candidate := range candidates.Keys {
		validated, verifyErr = parsed.Validate(candidate.PublicKey, token.IDTokenValidatePolicy{
			ExpectedIssuer: c.cfg.Issuer.String(), ExpectedAudience: c.cfg.ClientID.String(),
			Algorithm: c.cfg.Algorithms.IDToken, ExpectedNonce: nonce,
			Now: c.deps.Clock.Now(), MaxLifetime: c.cfg.Limits.MaxIDTokenLifetime, MaxClockSkew: c.cfg.Limits.MaxClockSkew,
		})
		if verifyErr == nil {
			break
		}
	}
	if verifyErr != nil {
		return "", newError(ErrorInvalidResponse, "ID token verification failed", verifyErr)
	}
	return validated.Subject, nil
}

type rawTokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	Scope        string `json:"scope,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

func decodeTokenResponse(body []byte) (rawTokenResponse, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	var raw rawTokenResponse
	if err := dec.Decode(&raw); err != nil {
		return rawTokenResponse{}, fmt.Errorf("decode token response: %w", err)
	}
	if raw.AccessToken == "" {
		return rawTokenResponse{}, fmt.Errorf("access_token is missing")
	}
	if raw.TokenType == "" {
		return rawTokenResponse{}, fmt.Errorf("token_type is missing")
	}
	// expires_in is RECOMMENDED, not REQUIRED (RFC 6749 §5.1) — an
	// authorization server may omit it and document a default lifetime
	// out of band instead, so its absence (Go's int64 zero value, same
	// as if the field were present and 0) is not malformed. A negative
	// value has no valid meaning under either reading, so that alone is
	// rejected.
	if raw.ExpiresIn < 0 {
		return rawTokenResponse{}, fmt.Errorf("expires_in must not be negative")
	}
	return raw, nil
}
