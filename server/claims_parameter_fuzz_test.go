package server

import (
	"encoding/json"
	"reflect"
	"slices"
	"testing"
)

// FuzzClaimsReadersAgree checks the three readers of the "claims"
// request parameter against each other, and the two encodings a request
// can carry it in (a request object's nested JSON object, and a plain
// form parameter's JSON string holding the object) against each other:
//
//   - validation, essential acr and the requested claim names never
//     panic;
//   - when validation accepts both, an object and the same object
//     wrapped as a JSON string give identical results from all three
//     readers. (Validation may refuse one encoding and not the other,
//     e.g. under a size bound the escaped string form exceeds first;
//     that's a refusal, not a disagreement.)
//   - when validation and the essential-acr reader both accept, every
//     essential acr value is non-empty and unique, and "acr" is among
//     the ID token's requested claim names;
//   - requested claim names are sorted and unique.
func FuzzClaimsReadersAgree(f *testing.F) {
	for _, s := range []string{
		`{"id_token":{"acr":{"essential":true,"values":["gold","silver"]}}}`,
		`{"id_token":{"acr":{"essential":true,"value":"gold"}},"userinfo":{"email":null}}`,
		`{"ID_TOKEN":{"acr":{"essential":true,"values":["gold"]}}}`,
		`{"id_token":{"acr":{"Essential":true,"values":["gold"]}}}`,
		`{"id_token":{"acr":{"essential":true,"values":["gold"]},"acr":null}}`,
		`{"id_token":null,"id_token":{"acr":{"essential":true,"value":"x"}}}`,
		`{"id_token":5}`, `[]`, `"{}"`, `null`, `{"id_token":{"a\u0063r":{"essential":true,"value":"x"}}}`,
		`{"id_token":{"acr":{"essential":true,"values":["a","a"]}}}`,
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, claims string) {
		if !json.Valid([]byte(claims)) {
			return
		}
		asObject := map[string]json.RawMessage{"claims": json.RawMessage(claims)}
		wrapped, err := json.Marshal(claims)
		if err != nil {
			return
		}
		asString := map[string]json.RawMessage{"claims": json.RawMessage(wrapped)}

		type result struct {
			valid             bool
			essential         []string
			essentialErr      bool
			idToken, userInfo []string
		}
		read := func(params map[string]json.RawMessage) result {
			ess, essErr := essentialACRValues(params)
			idt, ui := parseRequestedClaimNames(params["claims"])
			return result{
				valid:        validateClaimsParameter(params) == nil,
				essential:    ess,
				essentialErr: essErr != nil,
				idToken:      idt,
				userInfo:     ui,
			}
		}
		obj := read(asObject)
		// Only a JSON object (not a string) is a meaningful request
		// object member; compare encodings only when the raw value is
		// an object, since a raw string is already the form encoding.
		var probe any
		_ = json.Unmarshal([]byte(claims), &probe)
		if _, isObject := probe.(map[string]any); isObject {
			str := read(asString)
			if obj.valid && str.valid && !reflect.DeepEqual(obj, str) {
				t.Fatalf("object vs form-string encodings disagree for %q:\n object %+v\n string %+v", claims, obj, str)
			}
		}
		for _, names := range [][]string{obj.idToken, obj.userInfo} {
			if !slices.IsSorted(names) || len(slices.Compact(slices.Clone(names))) != len(names) {
				t.Fatalf("requested names not sorted/unique: %q", names)
			}
		}
		if obj.valid && !obj.essentialErr && len(obj.essential) > 0 {
			if !slices.Contains(obj.idToken, "acr") {
				t.Fatalf("essential acr %q enforced, but acr not among requested ID token claims %q (claims %q)", obj.essential, obj.idToken, claims)
			}
			seen := map[string]bool{}
			for _, v := range obj.essential {
				if v == "" || seen[v] {
					t.Fatalf("essential acr values %q contain an empty or duplicate value", obj.essential)
				}
				seen[v] = true
			}
		}
	})
}
