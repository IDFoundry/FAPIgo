package federation

import (
	"encoding/json"
	"slices"
	"testing"
)

// TestPermittedStrings pins which policy shapes restrict a
// single-valued parameter's values, and to what.
func TestPermittedStrings(t *testing.T) {
	for _, tc := range []struct {
		ops             string
		want            []string
		wantConstrained bool
	}{
		{`{}`, nil, false},
		{`{"default":"PS256"}`, nil, false},
		{`{"essential":true}`, nil, false},
		{`{"value":null}`, nil, false},
		{`{"value":"PS256"}`, []string{"PS256"}, true},
		{`{"value":"PS256","one_of":["PS256","ES256"]}`, []string{"PS256"}, true},
		{`{"one_of":["PS256","ES256"]}`, []string{"PS256", "ES256"}, true},
		{`{"value":1}`, nil, true},
	} {
		var ops PolicyOperators
		if err := json.Unmarshal([]byte(tc.ops), &ops); err != nil {
			t.Fatal(err)
		}
		got, constrained, err := PermittedStrings(ops)
		if err != nil || constrained != tc.wantConstrained || !slices.Equal(got, tc.want) {
			t.Errorf("PermittedStrings(%s) = %v, %v, %v; want %v, %v", tc.ops, got, constrained, err, tc.want, tc.wantConstrained)
		}
	}
}
