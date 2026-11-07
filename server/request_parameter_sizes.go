package server

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/idfoundry/fapigo/internal/jose"
	"github.com/idfoundry/fapigo/storage"
)

// Bounds on the core authorization request parameters a pushed request
// stores and every later step reads again: each GET of the
// authorization endpoint and completion decode the whole stored
// request. Without them, the 1 MiB form limit was the only bound, so a
// plain-parameter pushed request could carry a state (say) hundreds of
// kilobytes long.
//
// maxAuthorizationTextParameterBytes covers the free-form values —
// state, nonce, login_hint and acr_values. Real ones are tens to
// hundreds of bytes (an opaque random value, an e-mail address, a few
// acr URIs); 4 KiB is generous above that and still fits in the
// redirect URL and the browser cookie they often travel with. It is
// also the least scope bound (scopeBound): a scope travels in neither,
// and a server with fine-grained scopes, one per data item, can
// register a client for well over 4 KiB of them.
// id_token_hint is an ID token, which this server only reads as a
// compact JWS no longer than jose.DefaultMaxCompactBytes. A
// code_challenge is a base64url SHA-256 digest (43 characters, RFC 7636
// §4.2) and a dpop_jkt a base64url SHA-256 JWK thumbprint (RFC 9449
// §10, 43 characters), so 128 bytes leaves room for any longer hash; a
// max_age that parses (max_age.go) is at most 10 digits, plus any
// leading zeros a client might send.
const (
	maxAuthorizationTextParameterBytes = 4 << 10
	maxIDTokenHintBytes                = jose.DefaultMaxCompactBytes
	maxCodeChallengeBytes              = 128
	maxDPoPJKTBytes                    = 128
	maxMaxAgeBytes                     = 32
)

// parameterSize is the most bytes one core parameter may hold: a
// string's decoded value, any other JSON value's encoding.
type parameterSize struct {
	name     string
	maxBytes int
}

// authorizationParameterSizes are the bounds checkParameterSizes
// applies to a pushed authorization request
// (checkAuthorizationParameterSizes). The parameters not listed are
// bounded otherwise: scope by scopeBound, response_type, response_mode,
// code_challenge_method and redirect_uri must equal one fixed or
// registered value, prompt (maxPromptBytes) and claims
// (maxClaimsParameterBytes) have bounds of their own, ui_locales,
// claims_locales and display are trimmed rather than refused
// (boundPresentationPreferences), and authorization_details and
// extension parameters are bounded by Config.RAR and Config.Extensions.
var authorizationParameterSizes = []parameterSize{
	{name: "state", maxBytes: maxAuthorizationTextParameterBytes},
	{name: "nonce", maxBytes: maxAuthorizationTextParameterBytes},
	{name: "login_hint", maxBytes: maxAuthorizationTextParameterBytes},
	{name: "acr_values", maxBytes: maxAuthorizationTextParameterBytes},
	{name: "id_token_hint", maxBytes: maxIDTokenHintBytes},
	{name: "code_challenge", maxBytes: maxCodeChallengeBytes},
	{name: "dpop_jkt", maxBytes: maxDPoPJKTBytes},
	{name: "max_age", maxBytes: maxMaxAgeBytes},
}

// checkParameterSizes refuses params when one of sizes is present and
// longer than its bound.
func checkParameterSizes(params map[string]json.RawMessage, sizes []parameterSize) error {
	for _, ps := range sizes {
		raw, ok := params[ps.name]
		if !ok {
			continue
		}
		if parameterLength(raw) > ps.maxBytes {
			return fmt.Errorf("%s must not be longer than %d bytes", ps.name, ps.maxBytes)
		}
	}
	return nil
}

// scopeBound is the most bytes a scope from client may hold:
// maxAuthorizationTextParameterBytes, or client's allowed scopes joined
// with single spaces (storage.RegisteredClient.AllowedScopesLength)
// when that is longer, so a client registered for many fine-grained
// scopes can request every one of them at once. Each scope value must
// be one the client is allowed, so a scope past the second is only
// repeats or extra whitespace, and refusing it keeps what a stored
// request, grant or opaque access token record holds no larger than
// the client's own registration needs.
func scopeBound(client storage.RegisteredClient) int {
	return max(maxAuthorizationTextParameterBytes, client.AllowedScopesLength())
}

// checkScopeLength refuses a scope of length bytes from client when it
// is longer than scopeBound(client).
func checkScopeLength(length int, client storage.RegisteredClient) error {
	if bound := scopeBound(client); length > bound {
		return fmt.Errorf("scope must not be longer than %d bytes", bound)
	}
	return nil
}

// checkAuthorizationParameterSizes refuses a pushed authorization
// request from client whose core parameters exceed
// authorizationParameterSizes, or whose scope, measured as
// parameterLength measures it, exceeds scopeBound(client).
func checkAuthorizationParameterSizes(params map[string]json.RawMessage, client storage.RegisteredClient) error {
	if err := checkParameterSizes(params, authorizationParameterSizes); err != nil {
		return err
	}
	if raw, ok := params["scope"]; ok {
		return checkScopeLength(parameterLength(raw), client)
	}
	return nil
}

// parameterLength is the length of raw's decoded value when it is a
// JSON string, so an escaped character counts once, and of its encoding
// otherwise.
func parameterLength(raw json.RawMessage) int {
	if kind, ok := jsonKindOf(raw); ok && kind == jsonStringKind {
		if s, err := jsonStringValue(raw); err == nil {
			return len(s)
		}
	}
	return len(bytes.TrimSpace(raw))
}
