package client

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"

	"github.com/idfoundry/fapigo/internal/jwe"
	"github.com/idfoundry/fapigo/keys"
)

// UserInfo is the validated set of OIDC UserInfo claims (OIDC Core
// §5.3). Subject is always the ID token's own already-verified
// subject, not necessarily the UserInfo response's own sub claim
// verbatim — the two normally carry the same value (FetchUserInfo has
// already checked that), but see
// Config.TolerateUserInfoSubjectEqualsClientID for the one narrow case
// where they're allowed to differ, in which this is still the trusted
// value, never the client_id. Parameters holds every other claim the
// response carried (profile-defined claims such as name or email, or
// any deployment-specific extension claim).
type UserInfo struct {
	Subject    string
	Parameters map[string]json.RawMessage
}

// FetchUserInfo calls Config.Endpoints.UserInfo with tokens' DPoP-bound
// access token (via ProtectedResource) and returns the validated
// claims. The response may be plain JSON, a signed-only JWT, or a
// signed-then-encrypted nested JWT (OIDC Core §5.3.2) — dispatched on
// the response's own Content-Type header, never guessed from its
// shape. A signed component is verified through VerifyIssuerJWS, using
// the same issuer keys and Config.Algorithms.UserInfo this client
// already verifies an ID token with; an encrypted component is opened
// through Dependencies.Decryption under keys.UserInfoDecryption, using
// Config.Algorithms.UserInfoKeyManagement/UserInfoContentEncryption —
// exactly the same shape ExchangeCode already applies to an encrypted
// ID token, reused here rather than reinvented.
//
// tokens must carry a validated ID token (HasIDToken): OIDC Core §5.3.2
// requires the UserInfo Response's sub Claim to be verified against the
// ID Token's sub Claim, to guard against a token-substitution attack —
// there is nothing to check it against otherwise.
func (c *Client) FetchUserInfo(ctx context.Context, tokens TokenSet) (UserInfo, error) {
	if c.cfg.Endpoints.UserInfo.IsZero() {
		return UserInfo{}, newError(ErrorInvalidRequest, "userinfo endpoint is not configured", nil)
	}
	if !tokens.HasIDToken {
		return UserInfo{}, newError(ErrorInvalidRequest, "tokens has no validated ID token to check the UserInfo response's subject against", nil)
	}

	endpoint := c.cfg.Endpoints.UserInfo.URL()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return UserInfo{}, newError(ErrorInternal, "failed to build UserInfo request", err)
	}
	req.Header.Set("Accept", "application/json")

	res, err := c.ProtectedResource(tokens).Do(ctx, req)
	if err != nil {
		return UserInfo{}, err
	}
	defer func() { _ = res.Body.Close() }()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return UserInfo{}, newError(ErrorInvalidResponse, "failed to read UserInfo response", err)
	}
	if res.StatusCode != http.StatusOK {
		return UserInfo{}, newError(ErrorInvalidResponse, fmt.Sprintf("UserInfo endpoint returned status %d", res.StatusCode), nil)
	}

	claims, idErr := c.decodeUserInfoResponse(ctx, res.Header.Get("Content-Type"), body)
	if idErr != nil {
		return UserInfo{}, idErr
	}
	return c.checkUserInfoSubject(claims, tokens)
}

// decodeUserInfoResponse dispatches on contentType exactly as OIDC Core
// §5.3.2 defines: application/json for a plain claims object,
// application/jwt for a signed and/or signed-then-encrypted one. Which
// shape is acceptable is a caller policy decision, never inferred from
// what a given response happens to look like — Config.Algorithms.UserInfoKeyManagement
// being set means an encrypted response is the only acceptable shape,
// mirroring validateIDToken's own anti-downgrade discipline exactly.
func (c *Client) decodeUserInfoResponse(ctx context.Context, contentType string, body []byte) (map[string]json.RawMessage, *Error) {
	expectEncrypted := c.cfg.Algorithms.UserInfoKeyManagement != 0

	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return nil, newError(ErrorInvalidResponse, "UserInfo response has no valid Content-Type", err)
	}
	switch {
	case strings.EqualFold(mediaType, "application/json"):
		if expectEncrypted {
			return nil, newError(ErrorInvalidResponse, "UserInfo response is plain JSON, but this client is configured to require an encrypted UserInfo response", nil)
		}
		return decodeUserInfoJSON(body)
	case strings.EqualFold(mediaType, "application/jwt"):
		return c.decodeUserInfoJWT(ctx, string(body), expectEncrypted)
	default:
		return nil, newError(ErrorInvalidResponse, "UserInfo response has an unexpected content type", nil)
	}
}

func decodeUserInfoJSON(body []byte) (map[string]json.RawMessage, *Error) {
	var claims map[string]json.RawMessage
	if err := json.Unmarshal(body, &claims); err != nil {
		return nil, newError(ErrorInvalidResponse, "malformed UserInfo response", err)
	}
	return claims, nil
}

// decodeUserInfoJWT accepts either a signed-only UserInfo response (3
// compact-serialization segments) or a signed-then-encrypted one
// (always signed-then-encrypted, producing a Nested JWT — RFC 7519
// §5.2 — which has 5 segments), dispatched purely on segment count,
// exactly as validateIDToken dispatches an ID token.
func (c *Client) decodeUserInfoJWT(ctx context.Context, raw string, expectEncrypted bool) (map[string]json.RawMessage, *Error) {
	switch strings.Count(raw, ".") + 1 {
	case 3:
		if expectEncrypted {
			return nil, newError(ErrorInvalidResponse, "UserInfo response is not encrypted, but this client is configured to require an encrypted UserInfo response", nil)
		}
		return c.verifyUserInfoJWS(ctx, raw)
	case 5:
		if !expectEncrypted {
			return nil, newError(ErrorInvalidResponse, "UserInfo response is encrypted, but this client is not configured to expect an encrypted UserInfo response", nil)
		}
		inner, decErr := c.decryptUserInfoJWE(ctx, raw)
		if decErr != nil {
			return nil, decErr
		}
		return c.verifyUserInfoJWS(ctx, inner)
	default:
		return nil, newError(ErrorInvalidResponse, "malformed UserInfo JWT", nil)
	}
}

// decryptUserInfoJWE opens an encrypted UserInfo response and returns
// the inner signed JWT for verifyUserInfoJWS to verify exactly as it
// would a signed-only one — the same decrypt-then-verify shape
// decryptIDToken already applies to an encrypted ID token.
func (c *Client) decryptUserInfoJWE(ctx context.Context, raw string) (string, *Error) {
	unwrapper := decrypterUnwrapper{decrypter: c.deps.Decryption, purpose: keys.UserInfoDecryption}
	result, err := jwe.Decrypt(ctx, jwe.DecryptRequest{
		Algorithm:    c.cfg.Algorithms.UserInfoKeyManagement,
		Encryption:   c.cfg.Algorithms.UserInfoContentEncryption,
		RecipientKey: unwrapper,
		Compact:      raw,
	})
	if err != nil {
		return "", newError(ErrorInvalidResponse, "UserInfo response decryption failed", err)
	}
	if !isAcceptableNestedJWTContentType(result.Header.ContentType) {
		return "", newError(ErrorInvalidResponse, `decrypted UserInfo response is not a nested JWT (cty, if present, must be "JWT")`, nil)
	}
	return string(result.Plaintext), nil
}

func (c *Client) verifyUserInfoJWS(ctx context.Context, raw string) (map[string]json.RawMessage, *Error) {
	payload, err := c.VerifyIssuerJWS(ctx, raw)
	if err != nil {
		if cerr, ok := err.(*Error); ok {
			return nil, cerr
		}
		return nil, newError(ErrorInvalidResponse, "UserInfo response verification failed", err)
	}
	return decodeUserInfoJSON(payload)
}

// checkUserInfoSubject enforces OIDC Core §5.3.2: "The sub (subject)
// Claim in the UserInfo Response MUST be verified to exactly match the
// sub Claim in the ID Token" — the check that stops a resource server
// (or a network attacker sitting in front of it) from substituting
// another subject's claims into a response this flow would otherwise
// trust. See Config.TolerateUserInfoSubjectEqualsClientID's own doc
// comment for the one narrow, opt-in exception to that exact match.
func (c *Client) checkUserInfoSubject(claims map[string]json.RawMessage, tokens TokenSet) (UserInfo, error) {
	subRaw, ok := claims["sub"]
	if !ok {
		return UserInfo{}, newError(ErrorInvalidResponse, "UserInfo response has no sub claim", nil)
	}
	var sub string
	if err := json.Unmarshal(subRaw, &sub); err != nil {
		return UserInfo{}, newError(ErrorInvalidResponse, "UserInfo response sub claim is malformed", err)
	}
	if sub != tokens.IDTokenClaims.Subject {
		if !c.cfg.TolerateUserInfoSubjectEqualsClientID || sub != c.cfg.ClientID.String() {
			return UserInfo{}, newError(ErrorInvalidResponse, "UserInfo response sub does not match the ID token's sub", nil)
		}
	}

	params := make(map[string]json.RawMessage, len(claims))
	for k, v := range claims {
		if k == "sub" {
			continue
		}
		params[k] = v
	}
	// Always the ID token's own already-verified subject, never the
	// UserInfo response's "sub" value verbatim — when
	// TolerateUserInfoSubjectEqualsClientID accepted a mismatched sub
	// above, that value is the client_id, not the end-user, and would
	// be actively wrong to surface as this UserInfo's Subject.
	return UserInfo{Subject: tokens.IDTokenClaims.Subject, Parameters: params}, nil
}
