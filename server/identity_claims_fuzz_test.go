package server

import (
	"encoding/json"
	"slices"
	"testing"
)

// FuzzParseRequestedClaimNames exercises parseRequestedClaimNames
// against an arbitrary OIDC "claims" request parameter — client-supplied
// input that decides which identity claims a token may carry. Beyond
// "does not panic": a name is never returned twice, and the two shapes
// the parameter arrives in (a request object's nested JSON object, or a
// plain form parameter's JSON string containing that object — see
// parseRequestedClaimNames' doc comment) always yield the same names.
func FuzzParseRequestedClaimNames(f *testing.F) {
	f.Add([]byte(`{"id_token":{"name":null},"userinfo":{"email":{"essential":true}}}`))
	f.Add([]byte(`{"id_token":{"name":null,"name":null}}`))
	f.Add([]byte(`{"id_token":null,"userinfo":[]}`))
	f.Add([]byte(`"{\"id_token\":{\"acr\":{\"values\":[\"a\"]}}}"`))
	f.Add([]byte(`"not json"`))
	f.Add([]byte(`[]`))
	f.Add([]byte(``))

	f.Fuzz(func(t *testing.T, raw []byte) {
		idToken, userinfo := parseRequestedClaimNames(raw)
		for _, names := range [][]string{idToken, userinfo} {
			sorted := slices.Clone(names)
			slices.Sort(sorted)
			if len(slices.Compact(sorted)) != len(names) {
				t.Fatalf("duplicate claim names %v for input %q", names, raw)
			}
		}

		var obj map[string]json.RawMessage
		if json.Unmarshal(raw, &obj) != nil {
			return
		}
		asString, err := json.Marshal(string(raw))
		if err != nil {
			return
		}
		idToken2, userinfo2 := parseRequestedClaimNames(asString)
		if !sameNames(idToken, idToken2) || !sameNames(userinfo, userinfo2) {
			t.Fatalf("object and string-wrapped shapes disagree for %q: (%v, %v) vs (%v, %v)", raw, idToken, userinfo, idToken2, userinfo2)
		}
	})
}

func sameNames(a, b []string) bool {
	a, b = slices.Clone(a), slices.Clone(b)
	slices.Sort(a)
	slices.Sort(b)
	return slices.Equal(a, b)
}
