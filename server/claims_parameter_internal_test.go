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
		"array":                            {json.RawMessage(`[]`), false},
		"number":                           {json.RawMessage(`42`), false},
		"string that isn't an object":      {str(`"x"`), false},
		"id_token not an object":           {json.RawMessage(`{"id_token":"email"}`), false},
		"userinfo an array":                {json.RawMessage(`{"userinfo":["email"]}`), false},
		"claim request a string":           {json.RawMessage(`{"id_token":{"email":"yes"}}`), false},
		"claim request true":               {json.RawMessage(`{"id_token":{"email":true}}`), false},
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
