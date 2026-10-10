package server

import (
	"encoding/json"
	"testing"
)

func TestValidateClaimsParameter(t *testing.T) {
	str := func(s string) json.RawMessage { b, _ := json.Marshal(s); return b }
	for name, tc := range map[string]struct {
		raw   json.RawMessage
		valid bool
	}{
		"object":                           {json.RawMessage(`{"id_token":{"email":null,"acr":{"essential":true,"values":["a"]}}}`), true},
		"object as a form string":          {str(`{"userinfo":{"name":null}}`), true},
		"empty object":                     {json.RawMessage(`{}`), true},
		"null member":                      {json.RawMessage(`{"id_token":null}`), true},
		"unknown top-level member ignored": {json.RawMessage(`{"other":1}`), true},
		"not JSON":                         {str(`{id_token`), false},
		// A JSON string that doesn't decode: never produced by the
		// form or request-object paths, which always hand over valid
		// JSON, but refused rather than read as some other value.
		"unterminated string":         {json.RawMessage(`"{\"id_token\":{}}`), false},
		"array":                       {json.RawMessage(`[]`), false},
		"number":                      {json.RawMessage(`42`), false},
		"string that isn't an object": {str(`"x"`), false},
		"id_token not an object":      {json.RawMessage(`{"id_token":"email"}`), false},
		"userinfo an array":           {json.RawMessage(`{"userinfo":["email"]}`), false},
		"claim request a string":      {json.RawMessage(`{"id_token":{"email":"yes"}}`), false},
		"claim request true":          {json.RawMessage(`{"id_token":{"email":true}}`), false},
		// Members are case-sensitive: a case variant of id_token or
		// userinfo, which encoding/json's struct decoding would match,
		// is refused rather than silently honoured or ignored.
		"ID_TOKEN with an essential acr": {json.RawMessage(`{"ID_TOKEN":{"acr":{"essential":true,"values":["gold"]}}}`), false},
		"ID_TOKEN not an object":         {json.RawMessage(`{"ID_TOKEN":5}`), false},
		"UserInfo":                       {json.RawMessage(`{"UserInfo":{"name":null}}`), false},
		"Id_Token as a form string":      {str(`{"Id_Token":{"email":null}}`), false},
	} {
		t.Run(name, func(t *testing.T) {
			err := validateClaimsParameter(map[string]json.RawMessage{"claims": tc.raw})
			if (err == nil) != tc.valid {
				t.Fatalf("validateClaimsParameter(%s) = %v, want valid=%v", tc.raw, err, tc.valid)
			}
		})
	}
	if err := validateClaimsParameter(map[string]json.RawMessage{}); err != nil {
		t.Fatalf("no claims parameter: %v", err)
	}
}

// TestRequestedClaimNamesReadExactMembers: the claim-name reader sees
// the same members validation does, so a case variant validation would
// refuse is never read as a request for claims.
func TestRequestedClaimNamesReadExactMembers(t *testing.T) {
	idToken, userinfo := parseRequestedClaimNames(json.RawMessage(`{"ID_TOKEN":{"email":null},"UserInfo":{"name":null}}`))
	if idToken != nil || userinfo != nil {
		t.Fatalf("parseRequestedClaimNames(case variants) = %q, %q; want no claims", idToken, userinfo)
	}
	idToken, userinfo = parseRequestedClaimNames(json.RawMessage(`{"id_token":{"email":null},"userinfo":{"name":null}}`))
	if len(idToken) != 1 || idToken[0] != "email" || len(userinfo) != 1 || userinfo[0] != "name" {
		t.Fatalf("parseRequestedClaimNames(exact) = %q, %q; want [email], [name]", idToken, userinfo)
	}
}

// TestClaimsObjectRefusesUndecodableString: an undecodable JSON string
// isn't the claims parameter's text, so claimsObject reports it, and
// claimsMembers, which every reader shares, yields no members for it.
func TestClaimsObjectRefusesUndecodableString(t *testing.T) {
	raw := json.RawMessage(`"{\"id_token\":{}}`)
	if object, ok := claimsObject(raw); ok || object != nil {
		t.Fatalf("claimsObject(unterminated string) = %s, %v; want nil, false", object, ok)
	}
	if top, ok := claimsMembers(raw); ok || top != nil {
		t.Fatalf("claimsMembers(unterminated string) = %v, %v; want nil, false", top, ok)
	}
}
