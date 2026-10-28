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
