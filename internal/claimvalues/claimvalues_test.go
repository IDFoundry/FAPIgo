package claimvalues

import (
	"encoding/json"
	"testing"
)

func TestFromRequest(t *testing.T) {
	for _, tc := range []struct {
		request     string
		constrained bool
		allows      map[string]bool
	}{
		{`null`, false, map[string]bool{`"a"`: true}},
		{`{"essential":true}`, false, map[string]bool{`"a"`: true}},
		{`{"value":"a"}`, true, map[string]bool{`"a"`: true, `"b"`: false}},
		{`{"values":["a","b"]}`, true, map[string]bool{`"a"`: true, `"b"`: true, `"c"`: false}},
		{`{"value":"a","values":["a","b"]}`, true, map[string]bool{`"a"`: true, `"b"`: false}},
		{`{"value":"c","values":["a","b"]}`, true, map[string]bool{`"a"`: false, `"c"`: false}},
		{`{"values":"a"}`, true, map[string]bool{`"a"`: false}},
		{`{"values":[]}`, true, map[string]bool{`"a"`: false}},
		{`{"value":1}`, true, map[string]bool{`1.0`: true, `"1"`: false}},
		{`{"value":{"x":1,"y":2}}`, true, map[string]bool{`{"y":2,"x":1}`: true, `{"x":1}`: false}},
		{`{"Value":"a"}`, false, map[string]bool{`"b"`: true}},
	} {
		acceptable, constrained := FromRequest(json.RawMessage(tc.request))
		if constrained != tc.constrained {
			t.Fatalf("FromRequest(%s) constrained = %v, want %v", tc.request, constrained, tc.constrained)
		}
		a := Acceptable{}
		if constrained {
			a["c"] = acceptable
		}
		for value, want := range tc.allows {
			if got := a.Allows("c", json.RawMessage(value)); got != want {
				t.Errorf("request %s: Allows(%s) = %v, want %v", tc.request, value, got, want)
			}
		}
	}
}

// TestEqualNumbersExactly covers OIDC Core §5.5.1's equality comparison
// for numbers: by the value the text denotes, exactly, so integers
// above 2^53 that float64 would round together stay distinct, while
// different spellings of one value are equal.
func TestEqualNumbersExactly(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want bool
	}{
		{`9007199254740993`, `9007199254740992`, false},
		{`9007199254740993`, `9007199254740993`, true},
		{`[9007199254740993]`, `[9007199254740992]`, false},
		{`{"n":9007199254740993}`, `{"n":9007199254740992}`, false},
		{`0.1000000000000000000001`, `0.1`, false},
		{`1`, `1.0`, true},
		{`100`, `1e2`, true},
		{`100`, `1E+2`, true},
		{`0.01`, `1e-2`, true},
		{`1.50`, `15e-1`, true},
		{`-1`, `1`, false},
		{`0`, `-0.0`, true},
		{`0`, `0e5`, true},
		{`1e400`, `1e400`, true},
		{`1e400`, `1e401`, false},
		{`1e99999999999999999999`, `10e99999999999999999998`, true},
		{`1`, `"1"`, false},
		{`"A"`, `"A"`, true},
		{`{"x":[1,{"y":2}]}`, `{"x":[1.0,{"y":2e0}]}`, true},
		{`[1,2]`, `[1,2,3]`, false},
		{`null`, `null`, true},
		{`1 2`, `1`, false},
		{`1x`, `1`, false},
	} {
		if got := Equal(json.RawMessage(tc.a), json.RawMessage(tc.b)); got != tc.want {
			t.Errorf("Equal(%s, %s) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
		if got := Equal(json.RawMessage(tc.b), json.RawMessage(tc.a)); got != tc.want {
			t.Errorf("Equal(%s, %s) = %v, want %v", tc.b, tc.a, got, tc.want)
		}
	}
	a := Acceptable{"account_no": {json.RawMessage(`9007199254740993`)}}
	if a.Allows("account_no", json.RawMessage(`9007199254740992`)) {
		t.Error("Allows released 9007199254740992 for a request of value 9007199254740993")
	}
}
