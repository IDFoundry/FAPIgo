package client

import (
	"bytes"
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/clientassertion"
	"github.com/idfoundry/fapigo/internal/dpop"
	"github.com/idfoundry/fapigo/internal/jose"
	"github.com/idfoundry/fapigo/internal/jwe"
	"github.com/idfoundry/fapigo/internal/par"
	"github.com/idfoundry/fapigo/internal/token"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/storage"
)

// TokenSet is returned by a successful ExchangeCode.
type TokenSet struct {
	AccessToken fapi.Secret

	// TokenType is "DPoP" under SenderConstrainDPoP (the default) or
	// "Bearer" under SenderConstrainMTLS (RFC 8705 §3.4) — see
	// tokenTypeFor's own doc comment. Always this canonical casing,
	// regardless of the casing the server responded with (RFC 6749
	// §7.1: token_type is case insensitive).
	TokenType string
	Scope     string

	// ExpiresIn is set only when the token response actually carried
	// expires_in — RFC 6749 §5.1 marks it RECOMMENDED, not REQUIRED, and
	// explicitly permits an authorization server to omit it and
	// communicate the token's lifetime "via other means" instead. Zero
	// does not mean "expires immediately"; check HasExpiresIn first.
	ExpiresIn    time.Duration
	HasExpiresIn bool

	// IDToken, Subject and IDTokenClaims are set only when the granted
	// scope included "openid". Both Subject and IDTokenClaims come from
	// the same validated ID token, never from an unverified claim.
	// Subject is kept as its own field for backward compatibility;
	// IDTokenClaims.Subject carries the identical value.
	IDToken       fapi.Secret
	HasIDToken    bool
	Subject       string
	IDTokenClaims IDTokenClaims

	// RefreshToken is set only when the authorization server issued one.
	RefreshToken    fapi.Secret
	HasRefreshToken bool
}

// IDTokenClaims is the validated set of standard ID token claims beyond
// the bare Subject — every value here has already been checked against
// Config's issuer, audience, algorithm, nonce and clock-skew policy,
// exactly like Subject. Parameters holds every other claim the token
// carried (custom identity claims, extension claims, etc.) — anything
// not already surfaced as one of the named fields or implicitly
// verified (iss, aud, nonce).
//
// For an encrypted ID token, this is the only way to reach anything
// beyond Subject at all: decryption happens entirely inside client, so
// an embedding application has no way to recover the plaintext (and
// therefore no other claim) on its own — Dependencies.Decryption may
// be backed by an HSM or remote service that never exposes decrypted
// bytes outside this call.
type IDTokenClaims struct {
	Subject string

	// AuthTime is the zero time if the token carried no auth_time claim.
	AuthTime   time.Time
	ACR        string
	AMR        []string
	Parameters map[string]json.RawMessage
	ExpiresAt  time.Time

	// IssuedAt is the token's "iat" — required to be present and
	// well-formed for validation to succeed at all, but not itself
	// checked against any policy here (unlike ExpiresAt). Exposed for a
	// caller's own telemetry or cross-checks, not something this
	// package enforces a bound on.
	IssuedAt time.Time
}

// AsMap returns c's claims as a single map keyed by their JSON claim
// names — Subject/ExpiresAt/IssuedAt/AuthTime/ACR/AMR merged into a
// copy of Parameters — for a caller that wants the full validated
// claim set as one document (display, logging, forwarding) instead of
// re-deriving this merge by hand, which risks silently dropping one of
// the typed fields (there is nothing about Parameters that reminds a
// caller iat, say, needs to be re-added).
//
// exp, iat and auth_time come back as Unix seconds, matching how OIDC
// Core §2 actually defines these claims on the wire — not time.Time's
// own JSON encoding, which would silently produce the wrong shape.
// auth_time, acr and amr are omitted entirely when absent (AuthTime
// zero, ACR "", AMR nil) rather than included as an empty value, the
// same convention internal/token's own issuing side already uses when
// producing these claims (see internal/token/issue.go).
//
// AsMap cannot fail: every Parameters value already round-tripped
// through json.Unmarshal once when the token was first parsed, so
// re-decoding it here into any is guaranteed to succeed.
func (c IDTokenClaims) AsMap() map[string]any {
	out := make(map[string]any, len(c.Parameters)+6)
	for k, v := range c.Parameters {
		var val any
		_ = json.Unmarshal(v, &val)
		out[k] = val
	}
	out["sub"] = c.Subject
	out["exp"] = c.ExpiresAt.Unix()
	out["iat"] = c.IssuedAt.Unix()
	if !c.AuthTime.IsZero() {
		out["auth_time"] = c.AuthTime.Unix()
	}
	if c.ACR != "" {
		out["acr"] = c.ACR
	}
	if len(c.AMR) > 0 {
		out["amr"] = c.AMR
	}
	return out
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
	// dpopSigner stays nil under SenderConstrainMTLS — sendTokenRequest
	// never uses it in that case, since no DPoP proof is ever built.
	var dpopSigner crypto.Signer
	if c.cfg.SenderConstrain == storage.SenderConstrainDPoP {
		dpopSigner, _, err = c.newSigner(ctx, keys.DPoPProofSigning, c.cfg.Algorithms.DPoP)
		if err != nil {
			return TokenSet{}, newError(ErrorInternal, "failed to resolve DPoP signing key", err)
		}
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
	body, tokenErr := c.sendTokenRequest(ctx, dpopSigner, &tokenURL, buildTokenForm, form)
	if tokenErr != nil {
		return TokenSet{}, tokenErr
	}

	raw, err := decodeTokenResponse(body)
	if err != nil {
		return TokenSet{}, newError(ErrorInvalidResponse, "malformed token response", err)
	}
	wantTokenType := tokenTypeFor(c.cfg.SenderConstrain)
	if !strings.EqualFold(raw.TokenType, wantTokenType) {
		return TokenSet{}, newError(ErrorInvalidResponse, fmt.Sprintf("token response token_type is not %s", wantTokenType), nil)
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

	if idErr := c.populateIDToken(ctx, &result, raw, resp.nonce); idErr != nil {
		return TokenSet{}, idErr
	}
	if raw.RefreshToken != "" {
		result.RefreshToken = fapi.NewSecret(raw.RefreshToken)
		result.HasRefreshToken = true
	}

	return result, nil
}

// sendTokenRequest posts form to the token endpoint. Under
// SenderConstrainDPoP (the default), it presents a DPoP-proofed
// request, retrying once with a freshly-built form if the server
// challenges for a DPoP nonce (RFC 9449 §8: a server requiring one
// rejects a proof lacking it — or carrying a stale one — with
// use_dpop_nonce and a DPoP-Nonce response header naming the value to
// use; the client is expected to retry once with a fresh proof
// carrying it, not treat this as a terminal failure) — factored out of
// ExchangeCode purely to keep that function's own branching manageable.
// buildTokenForm is called again for the retry, not reused, since a
// client assertion is exactly as single-use as a DPoP proof is (see
// ExchangeCode's own comment on buildTokenForm). Under
// SenderConstrainMTLS, dpopSigner is unused (pass nil) — this is a
// single plain call relying entirely on Dependencies.HTTP's own
// configured transport to present this client's certificate; mTLS has
// no equivalent nonce-challenge/retry concept.
func (c *Client) sendTokenRequest(ctx context.Context, dpopSigner crypto.Signer, tokenURL *url.URL, buildTokenForm func() ([]byte, error), form []byte) ([]byte, *Error) {
	if c.cfg.SenderConstrain == storage.SenderConstrainMTLS {
		body, status, _, err := c.postForm(ctx, tokenURL.String(), form, nil)
		if err != nil {
			return nil, newError(ErrorInternal, "token request failed", err)
		}
		if status != http.StatusOK {
			return nil, parErrorFromResponse(body)
		}
		return body, nil
	}
	body, status, header, err := c.postTokenRequestWithDPoP(ctx, dpopSigner, tokenURL, form, c.cachedDPoPNonce(ctx, asNonceScope))
	if err != nil {
		return nil, newError(ErrorInternal, "token request failed", err)
	}
	nextNonce := header.Get("DPoP-Nonce")
	c.cacheDPoPNonce(ctx, asNonceScope, nextNonce)
	if status == http.StatusOK {
		return body, nil
	}

	if nextNonce == "" || !isDPoPNonceError(body) {
		return nil, parErrorFromResponse(body)
	}
	retryForm, buildErr := buildTokenForm()
	if buildErr != nil {
		return nil, newError(ErrorInternal, "failed to build client assertion", buildErr)
	}
	body, status, header, err = c.postTokenRequestWithDPoP(ctx, dpopSigner, tokenURL, retryForm, nextNonce)
	if err != nil {
		return nil, newError(ErrorInternal, "token request failed", err)
	}
	c.cacheDPoPNonce(ctx, asNonceScope, header.Get("DPoP-Nonce"))
	if status != http.StatusOK {
		return nil, parErrorFromResponse(body)
	}
	return body, nil
}

// populateIDToken validates raw.IDToken, if present, and fills in
// result's IDToken/HasIDToken/Subject/IDTokenClaims fields — factored
// out of ExchangeCode purely to keep that function's own branching
// manageable, not because this logic is reused elsewhere.
func (c *Client) populateIDToken(ctx context.Context, result *TokenSet, raw rawTokenResponse, nonce string) *Error {
	if raw.IDToken == "" {
		return nil
	}
	validated, idErr := c.validateIDToken(ctx, raw.IDToken, nonce)
	if idErr != nil {
		return idErr
	}
	result.IDToken = fapi.NewSecret(raw.IDToken)
	result.HasIDToken = true
	result.Subject = validated.Subject
	result.IDTokenClaims = IDTokenClaims{
		Subject: validated.Subject, AuthTime: validated.AuthTime,
		ACR: validated.ACR, AMR: validated.AMR,
		Parameters: validated.Parameters, ExpiresAt: validated.ExpiresAt,
		IssuedAt: validated.IssuedAt,
	}
	return nil
}

// tokenTypeFor returns the token_type value (RFC 6749 §7.1) this
// client expects a token response to declare — "DPoP" under
// SenderConstrainDPoP, or "Bearer" under SenderConstrainMTLS (RFC 8705
// §3.4), mirroring server.tokenTypeFor's identical contract on the
// issuing side.
func tokenTypeFor(senderConstrain storage.SenderConstrain) string {
	if senderConstrain == storage.SenderConstrainMTLS {
		return "Bearer"
	}
	return "DPoP"
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

// validateIDToken accepts either an ordinary signed-only ID token (3
// compact-serialization segments) or an encrypted one — always
// signed-then-encrypted (OIDC Core §2), producing a Nested JWT (RFC
// 7519 §5.2) — which has 5 segments, dispatched purely on segment
// count. Which shape is acceptable is a caller policy decision, never
// inferred from what a given token happens to look like:
// Config.Algorithms.IDTokenKeyManagement being set means an encrypted
// ID token is the only acceptable shape, and a plain one arriving
// instead is rejected outright rather than silently accepted — the
// downgrade this check exists to close. Symmetrically, an encrypted ID
// token arriving when encryption was never configured is also
// rejected: this client has no configured algorithm (and, per
// client.New's own validation, no Decryption dependency) to process it
// with, and trusting whatever the token's own header claims would be
// exactly the "never treat an untrusted alg header as policy" mistake
// this module avoids everywhere else.
func (c *Client) validateIDToken(ctx context.Context, raw, nonce string) (token.ValidatedIDToken, *Error) {
	expectEncrypted := c.cfg.Algorithms.IDTokenKeyManagement != 0
	switch strings.Count(raw, ".") + 1 {
	case 3:
		if expectEncrypted {
			return token.ValidatedIDToken{}, newError(ErrorInvalidResponse, "ID token is not encrypted, but this client is configured to require an encrypted ID token", nil)
		}
		return c.validateSignedIDToken(ctx, raw, nonce)
	case 5:
		if !expectEncrypted {
			return token.ValidatedIDToken{}, newError(ErrorInvalidResponse, "ID token is encrypted, but this client is not configured to expect an encrypted ID token", nil)
		}
		innerJWT, decErr := c.decryptIDToken(ctx, raw)
		if decErr != nil {
			return token.ValidatedIDToken{}, decErr
		}
		return c.validateSignedIDToken(ctx, innerJWT, nonce)
	default:
		return token.ValidatedIDToken{}, newError(ErrorInvalidResponse, "malformed ID token", nil)
	}
}

// decryptIDToken opens an encrypted ID token and returns the inner
// signed JWT for validateSignedIDToken to verify exactly as it would an
// ordinary signed-only one — decrypting removes a confidentiality
// wrapper, it never substitutes for signature/claims verification, all
// of which still happens on the recovered JWT afterward.
func (c *Client) decryptIDToken(ctx context.Context, raw string) (string, *Error) {
	unwrapper := decrypterUnwrapper{decrypter: c.deps.Decryption, purpose: keys.IDTokenDecryption}
	result, err := jwe.Decrypt(ctx, jwe.DecryptRequest{
		Algorithm:       c.cfg.Algorithms.IDTokenKeyManagement,
		Encryption:      c.cfg.Algorithms.IDTokenContentEncryption,
		RecipientKey:    unwrapper,
		Compact:         raw,
		MaxCompactBytes: c.cfg.Limits.MaxJOSECompactBytes,
	})
	if err != nil {
		if errors.Is(err, jwe.ErrTooLarge) {
			return "", newError(ErrorResponseTooLarge, "ID token exceeds the configured size limit", err)
		}
		return "", newError(ErrorInvalidResponse, "ID token decryption failed", err)
	}
	// RFC 7519 §5.2 requires a producer of a nested JWT to set cty to
	// "JWT", but that obligation falls on the party that built the JWE,
	// not on this module as its consumer — and real-world encrypters
	// routinely omit cty in practice. Since this call site only ever
	// asks for a JWE it already expects to hold an ID token, an absent
	// cty doesn't itself mean the payload isn't one; only a
	// present-but-different cty does. When cty is present, it's
	// compared per RFC 7515 §4.1.10's media-type rules (case
	// insensitive, an "application/"-prefixed form is equivalent),
	// exactly the rule this module's own request-object "typ" check
	// already applies for the same reason.
	if !isAcceptableNestedJWTContentType(result.Header.ContentType) {
		return "", newError(ErrorInvalidResponse, `decrypted ID token is not a nested JWT (cty, if present, must be "JWT")`, nil)
	}
	return string(result.Plaintext), nil
}

// isAcceptableNestedJWTContentType reports whether cty, a JWE header's
// optional "cty" value, is consistent with identifying a nested JWT
// payload — see decryptIDToken's own doc comment for why an empty cty
// is accepted rather than rejected, and for the RFC basis of the
// case-insensitive, "application/"-prefix-tolerant comparison applied
// when cty is present.
func isAcceptableNestedJWTContentType(cty string) bool {
	if cty == "" {
		return true
	}
	return strings.TrimPrefix(strings.ToLower(cty), "application/") == "jwt"
}

// validateSignedIDToken verifies an ordinary signed-only ID token —
// either one that arrived that way directly, or the inner JWT
// decryptIDToken recovered from an encrypted one.
func (c *Client) validateSignedIDToken(ctx context.Context, raw, nonce string) (token.ValidatedIDToken, *Error) {
	parsed, err := token.ParseIDTokenMax(raw, c.cfg.Limits.MaxJOSECompactBytes)
	if err != nil {
		if errors.Is(err, jose.ErrTooLarge) {
			return token.ValidatedIDToken{}, newError(ErrorResponseTooLarge, "ID token exceeds the configured size limit", err)
		}
		return token.ValidatedIDToken{}, newError(ErrorInvalidResponse, "malformed ID token", err)
	}

	candidates, idErr := c.resolveIssuerKeyCandidates(ctx, keys.IDTokenVerification, c.cfg.Algorithms.IDToken, parsed.KeyID())
	if idErr != nil {
		return token.ValidatedIDToken{}, idErr
	}

	var (
		validated token.ValidatedIDToken
		verifyErr error
	)
	for _, candidate := range candidates {
		validated, verifyErr = parsed.Validate(candidate.PublicKey, token.IDTokenValidatePolicy{
			ExpectedIssuer: c.cfg.Issuer.String(), ExpectedAudience: c.cfg.ClientID.String(),
			TrustedAudiences: c.cfg.TrustedIDTokenAudiences,
			Algorithm:        c.cfg.Algorithms.IDToken, ExpectedNonce: nonce,
			Now: c.deps.Clock.Now(), MaxLifetime: c.cfg.Limits.MaxIDTokenLifetime, MaxClockSkew: c.cfg.Limits.MaxClockSkew,
		})
		if verifyErr == nil {
			break
		}
	}
	if verifyErr != nil {
		return token.ValidatedIDToken{}, newError(ErrorInvalidResponse, "ID token verification failed", verifyErr)
	}
	return validated, nil
}

// resolveIssuerKeyCandidates resolves the authorization server's
// candidate verification keys for purpose/algorithm/keyID — shared by
// every check that verifies something the issuer signed (an ID token,
// and, via VerifyIssuerJWS, any other issuer-signed artifact a caller
// asks about), so "resolution failed" and "no matching key" error
// handling lives in exactly one place rather than being re-derived per
// caller.
func (c *Client) resolveIssuerKeyCandidates(ctx context.Context, purpose keys.IssuerVerificationPurpose, algorithm fapi.SignatureAlgorithm, keyID string) ([]keys.IssuerKey, *Error) {
	candidates, err := c.deps.IssuerKeys.ResolveIssuerKeys(ctx, keys.IssuerKeyRequest{
		Issuer: c.cfg.Issuer.String(), Purpose: purpose, Algorithm: algorithm, KeyID: keyID,
	})
	if err != nil {
		return nil, newError(ErrorInternal, "failed to resolve issuer keys", err)
	}
	if len(candidates.Keys) == 0 {
		return nil, newError(ErrorInvalidResponse, "no matching issuer key", nil)
	}
	return candidates.Keys, nil
}

type rawTokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	Scope        string `json:"scope,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

// decodeTokenResponse parses body, tolerating any member beyond
// rawTokenResponse's own fields: RFC 6749 §5.1 requires it — "The
// client MUST ignore unrecognized value names and extra parameters
// received in the response" — since a real authorization server
// routinely adds parameters this module has no reason to model (e.g.
// refresh_token_expires_in, authorization_details).
func decodeTokenResponse(body []byte) (rawTokenResponse, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
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
