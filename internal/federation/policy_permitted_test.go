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

// TestPermittedArrayStrings pins which policy shapes restrict the values
// an array parameter may hold whether or not it is present, and to what:
// subset_of, a value other than null and one_of (the values its options
// list between them), never an operator that only adds to a parameter or
// checks it.
func TestPermittedArrayStrings(t *testing.T) {
	for _, tc := range []struct {
		ops             string
		want            []string
		wantConstrained bool
	}{
		{`{}`, nil, false},
		{`{"add":["a"]}`, nil, false},
		{`{"default":["a"]}`, nil, false},
		{`{"superset_of":["a"]}`, nil, false},
		{`{"essential":true}`, nil, false},
		{`{"value":null}`, nil, false},
		{`{"subset_of":["a","b"]}`, []string{"a", "b"}, true},
		{`{"subset_of":["a","b"],"superset_of":["a"]}`, []string{"a", "b"}, true},
		{`{"subset_of":["a","b"],"value":null}`, []string{"a", "b"}, true},
		{`{"subset_of":[]}`, []string{}, true},
		{`{"subset_of":null}`, []string{}, true},
		{`{"subset_of":["a",1,null,{"b":"c"}]}`, []string{"a"}, true},
		{`{"value":["a"]}`, []string{"a"}, true},
		{`{"value":[]}`, []string{}, true},
		{`{"value":"a"}`, []string{}, true},
		{`{"value":["a"],"subset_of":["a","b"]}`, []string{"a"}, true},
		// ValidatePolicy refuses a value outside subset_of; what the two
		// permit is still only what both name.
		{`{"value":["b","c"],"subset_of":["a","b"]}`, []string{"b"}, true},
		{`{"one_of":["a","b"]}`, []string{"a", "b"}, true},
		{`{"one_of":[["a","b"],["c"]]}`, []string{"a", "b", "c"}, true},
		{`{"one_of":[]}`, []string{}, true},
		{`{"one_of":[1,null,{"b":"c"},"a"]}`, []string{"a"}, true},
		{`{"one_of":[["a"],["b"]],"value":["a"]}`, []string{"a"}, true},
		{`{"one_of":[["a"]],"value":null}`, []string{"a"}, true},
		// ValidatePolicy refuses a value outside one_of; what the two
		// permit is still only what both name, in value's order.
		{`{"one_of":["a","b"],"value":["c","b"]}`, []string{"b"}, true},
		{`{"one_of":["a","b"],"subset_of":["b","c"]}`, []string{"b"}, true},
	} {
		var ops PolicyOperators
		if err := json.Unmarshal([]byte(tc.ops), &ops); err != nil {
			t.Fatal(err)
		}
		got, constrained, err := PermittedArrayStrings(ops)
		// A constrained result permitting nothing is empty, not nil.
		if err != nil || constrained != tc.wantConstrained || !slices.Equal(got, tc.want) || (constrained && got == nil) {
			t.Errorf("PermittedArrayStrings(%s) = %#v, %v, %v; want %v, %v", tc.ops, got, constrained, err, tc.want, tc.wantConstrained)
		}
	}
	for _, ops := range []string{`{"subset_of":"a"}`, `{"one_of":"a"}`} {
		var parsed PolicyOperators
		if err := json.Unmarshal([]byte(ops), &parsed); err != nil {
			t.Fatal(err)
		}
		if _, _, err := PermittedArrayStrings(parsed); err == nil {
			t.Errorf("PermittedArrayStrings(%s) = nil error, want an error", ops)
		}
	}
}

// TestPermittedSpaceDelimitedStrings checks the values a scope policy
// lets scope hold: subset_of and value as for an array parameter, with
// value and one_of options given as space-delimited strings, and one_of
// bounding it to the values its options list between them.
func TestPermittedSpaceDelimitedStrings(t *testing.T) {
	for _, tc := range []struct {
		ops             string
		want            []string
		wantConstrained bool
	}{
		{`{}`, nil, false},
		{`{"add":["a"]}`, nil, false},
		{`{"default":"a b"}`, nil, false},
		{`{"value":null}`, nil, false},
		{`{"subset_of":["a","b"]}`, []string{"a", "b"}, true},
		{`{"value":"a b"}`, []string{"a", "b"}, true},
		{`{"value":["a","b"]}`, []string{"a", "b"}, true},
		{`{"value":"a c","subset_of":["a","b"]}`, []string{"a"}, true},
		{`{"one_of":["a","a b"]}`, []string{"a", "a", "b"}, true},
		{`{"one_of":[["a"],"c"]}`, []string{"a", "c"}, true},
		{`{"one_of":[]}`, []string{}, true},
		{`{"one_of":[1,"a"]}`, []string{"a"}, true},
		{`{"one_of":["a c"],"subset_of":["a","b"]}`, []string{"a"}, true},
	} {
		var ops PolicyOperators
		if err := json.Unmarshal([]byte(tc.ops), &ops); err != nil {
			t.Fatal(err)
		}
		got, constrained, err := PermittedSpaceDelimitedStrings(ops)
		if err != nil || constrained != tc.wantConstrained || !slices.Equal(got, tc.want) || (constrained && got == nil) {
			t.Errorf("PermittedSpaceDelimitedStrings(%s) = %#v, %v, %v; want %v, %v", tc.ops, got, constrained, err, tc.want, tc.wantConstrained)
		}
	}
	for _, ops := range []string{`{"subset_of":"a"}`, `{"one_of":"a"}`} {
		var parsed PolicyOperators
		if err := json.Unmarshal([]byte(ops), &parsed); err != nil {
			t.Fatal(err)
		}
		if _, _, err := PermittedSpaceDelimitedStrings(parsed); err == nil {
			t.Errorf("PermittedSpaceDelimitedStrings(%s) = nil error, want an error", ops)
		}
	}
}
