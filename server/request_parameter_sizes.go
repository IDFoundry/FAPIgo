package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

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
//
// Two core parameters are a backchannel authentication request's alone.
// A login_hint_token is a token, as an id_token_hint is (CIBA Core
// §7.1), and has the same bound. A requested_expiry that parses
// (parseRequestedExpiry) is an int64, at most 19 digits and a sign,
// plus any leading zeros.
const (
	maxAuthorizationTextParameterBytes = 4 << 10
	maxIDTokenHintBytes                = jose.DefaultMaxCompactBytes
	maxLoginHintTokenBytes             = jose.DefaultMaxCompactBytes
	maxCodeChallengeBytes              = 128
	maxDPoPJKTBytes                    = 128
	maxMaxAgeBytes                     = 32
	maxRequestedExpiryBytes            = 32
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

// backchannelParameterSizes are the bounds checkParameterSizes applies
// to a backchannel authentication request
// (checkBackchannelParameterSizes). It is stored as a pushed request is,
// and every lookup of it and every listing of its user's inbox
// (ListBackchannelInteractions) decodes it again, so the parameters it
// shares with a pushed request have the same bounds, and acr_values
// also names at most maxACRValues values. The parameters not listed are
// bounded otherwise: scope by scopeBound, binding_message by
// maxBindingMessageLength, client_notification_token by
// maxClientNotificationTokenLength, claims by maxClaimsParameterBytes,
// and authorization_details and extension parameters by Config.RAR and
// Config.Extensions.
var backchannelParameterSizes = []parameterSize{
	{name: "login_hint", maxBytes: maxAuthorizationTextParameterBytes},
	{name: "acr_values", maxBytes: maxAuthorizationTextParameterBytes},
	{name: "id_token_hint", maxBytes: maxIDTokenHintBytes},
	{name: "login_hint_token", maxBytes: maxLoginHintTokenBytes},
	{name: "dpop_jkt", maxBytes: maxDPoPJKTBytes},
	{name: "requested_expiry", maxBytes: maxRequestedExpiryBytes},
}

// maxACRValues is the most values a backchannel authentication
// request's acr_values may name. Bounding its bytes isn't enough: 4 KiB
// holds 2,048 one-character values, and each lookup of the request, and
// each listing of its user's inbox, splits them into
// BackchannelInteractionRequest.ACRValues afresh. A real request names
// a few acr URIs; 32 is as many as an essential acr claim may name
// (maxEssentialACRValues).
const maxACRValues = 32

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

// checkBackchannelParameterSizes is checkAuthorizationParameterSizes'
// CIBA counterpart: it refuses a backchannel authentication request from
// client whose core parameters exceed backchannelParameterSizes, whose
// scope exceeds scopeBound(client), or whose acr_values names more than
// maxACRValues values.
func checkBackchannelParameterSizes(params map[string]json.RawMessage, client storage.RegisteredClient) error {
	if err := checkParameterSizes(params, backchannelParameterSizes); err != nil {
		return err
	}
	if raw, ok := params["scope"]; ok {
		if err := checkScopeLength(parameterLength(raw), client); err != nil {
			return err
		}
	}
	return checkACRValuesCount(params)
}

// checkACRValuesCount refuses an acr_values naming more than
// maxACRValues values, counted the way backchannelInteractionRequestFrom
// splits them (strings.Fields), without building the list.
func checkACRValuesCount(params map[string]json.RawMessage) error {
	// "" when absent; one that isn't a string was refused with the
	// request's other parameters (backchannelParameterTypes).
	acrValues, _ := jsonString(params, "acr_values")
	count := 0
	for range strings.FieldsSeq(acrValues) {
		count++
		if count > maxACRValues {
			return fmt.Errorf("acr_values must not name more than %d values", maxACRValues)
		}
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
