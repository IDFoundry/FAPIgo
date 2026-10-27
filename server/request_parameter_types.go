package server

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// jsonKinds is a set of JSON value types a core request parameter may
// take.
type jsonKinds uint8

const (
	jsonStringKind jsonKinds = 1 << iota
	jsonNumberKind
	jsonObjectKind
)

// parameterType is the JSON type a core request parameter is defined
// with: the kinds it may take and, for a string, whether it may be
// empty.
type parameterType struct {
	name     string
	kinds    jsonKinds
	nonEmpty bool
}

// authorizationParameterTypes are the types of the core authorization
// request parameters (coreAuthorizationParameters). A form parameter is
// always a string; a request object's member can be any JSON value, and
// without this check one of the wrong type was read as absent — a
// dpop_jkt array left the code unbound, a numeric nonce gave an ID token
// with no nonce, an object state was left out of the response. max_age
// is a number in a request object and a string as a form parameter
// (requestedMaxAge reads both); claims an object, or as a form
// parameter a string holding one (validateClaimsParameter). dpop_jkt
// names a key, so it can't be empty (RFC 9449 §10).
//
// Not listed: client_id, which requestobject.Parse checks;
// authorization_details, whose type parseRequestedAuthorizationDetails
// checks, refusing a wrong one with invalid_authorization_details as
// RFC 9396 §5 requires; and ui_locales, claims_locales and display,
// preferences OIDC Core §15.1 has never fail a request (one of the wrong
// type is ignored).
var authorizationParameterTypes = []parameterType{
	{name: "response_type", kinds: jsonStringKind},
	{name: "redirect_uri", kinds: jsonStringKind},
	{name: "scope", kinds: jsonStringKind},
	{name: "state", kinds: jsonStringKind},
	{name: "nonce", kinds: jsonStringKind},
	{name: "code_challenge", kinds: jsonStringKind},
	{name: "code_challenge_method", kinds: jsonStringKind},
	{name: "response_mode", kinds: jsonStringKind},
	{name: "prompt", kinds: jsonStringKind},
	{name: "acr_values", kinds: jsonStringKind},
	{name: "login_hint", kinds: jsonStringKind},
	{name: "id_token_hint", kinds: jsonStringKind},
	{name: "dpop_jkt", kinds: jsonStringKind, nonEmpty: true},
	{name: "max_age", kinds: jsonStringKind | jsonNumberKind},
	{name: "claims", kinds: jsonStringKind | jsonObjectKind},
}

// backchannelParameterTypes are authorizationParameterTypes' CIBA
// counterpart, for coreBackchannelAuthenticationParameters.
// requested_expiry is a number or a numeric string, as
// parseRequestedExpiry reads it.
var backchannelParameterTypes = []parameterType{
	{name: "scope", kinds: jsonStringKind},
	{name: "login_hint", kinds: jsonStringKind},
	{name: "login_hint_token", kinds: jsonStringKind},
	{name: "id_token_hint", kinds: jsonStringKind},
	{name: "acr_values", kinds: jsonStringKind},
	{name: "binding_message", kinds: jsonStringKind},
	{name: "client_notification_token", kinds: jsonStringKind},
	{name: "dpop_jkt", kinds: jsonStringKind, nonEmpty: true},
	{name: "requested_expiry", kinds: jsonStringKind | jsonNumberKind},
	{name: "claims", kinds: jsonStringKind | jsonObjectKind},
}

// checkParameterTypes refuses params, a signed request's members, when
// one of types is present with a JSON type it isn't defined with. Each
// parameter's reader then takes its type as given.
func checkParameterTypes(params map[string]json.RawMessage, types []parameterType) error {
	for _, pt := range types {
		raw, ok := params[pt.name]
		if !ok {
			continue
		}
		if err := pt.check(raw); err != nil {
			return fmt.Errorf("%s %w", pt.name, err)
		}
	}
	return nil
}

func (pt parameterType) check(raw json.RawMessage) error {
	kind, ok := jsonKindOf(raw)
	if !ok || pt.kinds&kind == 0 {
		return fmt.Errorf("must be %s", pt.kinds)
	}
	if kind == jsonStringKind && pt.nonEmpty {
		if s, err := jsonStringValue(raw); err != nil || s == "" {
			return fmt.Errorf("must be a non-empty string")
		}
	}
	return nil
}

// jsonKindOf returns raw's JSON type, which its first byte decides: raw
// came from decoding a JSON object, so it is one valid value. ok is
// false for a type no core parameter takes (an array, a boolean, null).
func jsonKindOf(raw json.RawMessage) (jsonKinds, bool) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return 0, false
	}
	switch c := trimmed[0]; {
	case c == '"':
		return jsonStringKind, true
	case c == '{':
		return jsonObjectKind, true
	case c == '-' || ('0' <= c && c <= '9'):
		return jsonNumberKind, true
	}
	return 0, false
}

func (k jsonKinds) String() string {
	switch k {
	case jsonStringKind:
		return "a string"
	case jsonStringKind | jsonNumberKind:
		return "a number or a string"
	case jsonStringKind | jsonObjectKind:
		return "a JSON object or a string"
	}
	return "of another type"
}
