package federation

import (
	"encoding/json"
	"errors"
	"testing"
)

func ops(t *testing.T, raw string) PolicyOperators {
	t.Helper()
	var o PolicyOperators
	if err := json.Unmarshal([]byte(raw), &o); err != nil {
		t.Fatalf("unmarshal %s: %v", raw, err)
	}
	return o
}

// TestValidateCombination covers each §6.1.3.1 combination rule, with an
// allowed and a disallowed case for each.
func TestValidateCombination(t *testing.T) {
	for _, tc := range []struct {
		name  string
		ops   string
		valid bool
	}{
		// value + add: add ⊆ value.
		{"value+add subset", `{"value":["a","b"],"add":["a"]}`, true},
		{"value+add not subset", `{"value":["a"],"add":["b"]}`, false},
		{"null value+empty add", `{"value":null,"add":[]}`, true},
		{"null value+add", `{"value":null,"add":["a"]}`, false},
		// value + default: value not null.
		{"value+default", `{"value":"a","default":"b"}`, true},
		{"null value+default", `{"value":null,"default":"b"}`, false},
		// value + one_of: value among one_of.
		{"value in one_of", `{"value":"a","one_of":["a","b"]}`, true},
		{"value not in one_of", `{"value":"c","one_of":["a","b"]}`, false},
		{"null value+one_of", `{"value":null,"one_of":["a"]}`, false},
		// value + subset_of: value ⊆ subset_of.
		{"value subset of subset_of", `{"value":["a"],"subset_of":["a","b"]}`, true},
		{"value not subset of subset_of", `{"value":["a","c"],"subset_of":["a","b"]}`, false},
		{"null value+subset_of", `{"value":null,"subset_of":["a"]}`, true},
		{"scalar value+subset_of", `{"value":"a","subset_of":["a"]}`, false},
		// value + superset_of: value ⊇ superset_of.
		{"value superset of superset_of", `{"value":["a","b"],"superset_of":["a"]}`, true},
		{"value not superset of superset_of", `{"value":["a"],"superset_of":["a","b"]}`, false},
		{"null value+empty superset_of", `{"value":null,"superset_of":[]}`, true},
		{"null value+superset_of", `{"value":null,"superset_of":["a"]}`, false},
		// value + essential: not null with true.
		{"null value+essential false", `{"value":null,"essential":false}`, true},
		{"null value+essential true", `{"value":null,"essential":true}`, false},
		// add + subset_of: add ⊆ subset_of.
		{"add subset of subset_of", `{"add":["a"],"subset_of":["a","b"]}`, true},
		{"add not subset of subset_of", `{"add":["c"],"subset_of":["a","b"]}`, false},
		// subset_of + superset_of: subset_of ⊇ superset_of.
		{"subset_of superset of superset_of", `{"subset_of":["a","b"],"superset_of":["a"]}`, true},
		{"subset_of not superset of superset_of", `{"subset_of":["a"],"superset_of":["a","b"]}`, false},
		// one_of combines only with value, default and essential.
		{"one_of+default+essential", `{"one_of":["a"],"default":"a","essential":true}`, true},
		{"one_of+add", `{"one_of":["a"],"add":["a"]}`, false},
		{"one_of+subset_of", `{"one_of":["a"],"subset_of":["a"]}`, false},
		{"one_of+superset_of", `{"one_of":["a"],"superset_of":["a"]}`, false},
		// Operand types.
		{"add not array", `{"add":"a"}`, false},
		{"one_of not array", `{"one_of":"a"}`, false},
		{"subset_of not array", `{"subset_of":"a"}`, false},
		{"superset_of not array", `{"superset_of":"a"}`, false},
		{"essential not boolean", `{"essential":"yes"}`, false},
		{"default null", `{"default":null}`, false},
		// Everything the spec allows together.
		{"all compatible", `{"value":["a","b"],"add":["a"],"default":["a"],"subset_of":["a","b","c"],"superset_of":["a"],"essential":true}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateCombination(ops(t, tc.ops), nil)
			if tc.valid && err != nil {
				t.Errorf("validateCombination(%s) = %v, want nil", tc.ops, err)
			}
			if !tc.valid {
				if err == nil {
					t.Errorf("validateCombination(%s) = nil, want a policy error", tc.ops)
				} else if !errors.Is(err, ErrPolicyError) {
					t.Errorf("validateCombination(%s) = %v, want ErrPolicyError", tc.ops, err)
				}
			}
		})
	}
}

// TestSubordinateCannotLoosenSuperiorPolicy covers the chain-level
// consequence: an intermediate's policy merged under a Trust Anchor's
// must not undo what the Trust Anchor fixed.
func TestSubordinateCannotLoosenSuperiorPolicy(t *testing.T) {
	for _, tc := range []struct {
		name, superior, subordinate string
	}{
		{"add to a fixed value", `{"openid_relying_party":{"grant_types":{"value":["authorization_code"]}}}`, `{"openid_relying_party":{"grant_types":{"add":["client_credentials"]}}}`},
		{"default for a removed parameter", `{"openid_relying_party":{"x":{"value":null}}}`, `{"openid_relying_party":{"x":{"default":"d"}}}`},
		{"add outside subset_of", `{"openid_relying_party":{"grant_types":{"subset_of":["authorization_code"]}}}`, `{"openid_relying_party":{"grant_types":{"add":["client_credentials"]}}}`},
		{"value outside one_of", `{"openid_relying_party":{"x":{"one_of":["a","b"]}}}`, `{"openid_relying_party":{"x":{"value":"c"}}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var superior, subordinate MetadataPolicy
			if err := json.Unmarshal([]byte(tc.superior), &superior); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal([]byte(tc.subordinate), &subordinate); err != nil {
				t.Fatal(err)
			}
			merged, err := MergePolicy(nil, nil, superior, nil)
			if err != nil {
				t.Fatalf("superior policy alone: %v", err)
			}
			if _, err := MergePolicy(merged, nil, subordinate, nil); !errors.Is(err, ErrPolicyError) {
				t.Errorf("merging the subordinate policy = %v, want ErrPolicyError", err)
			}
		})
	}
}

// TestPolicyValidatedWithoutMerge covers a disallowed combination within
// a single statement's policy — the first one the chain meets (§6.1.4.1)
// and a parameter only one statement constrains — which never reaches an
// operator merge.
func TestPolicyValidatedWithoutMerge(t *testing.T) {
	var bad MetadataPolicy
	if err := json.Unmarshal([]byte(`{"openid_relying_party":{"x":{"value":["a"],"add":["b"]}}}`), &bad); err != nil {
		t.Fatal(err)
	}
	if _, err := MergePolicy(nil, nil, bad, nil); !errors.Is(err, ErrPolicyError) {
		t.Errorf("MergePolicy(nil, bad) = %v, want ErrPolicyError", err)
	}
	var other MetadataPolicy
	if err := json.Unmarshal([]byte(`{"openid_relying_party":{"y":{"value":"v"}}}`), &other); err != nil {
		t.Fatal(err)
	}
	if _, err := MergePolicy(other, nil, bad, nil); !errors.Is(err, ErrPolicyError) {
		t.Errorf("MergePolicy(other, bad) = %v, want ErrPolicyError", err)
	}
	if _, err := ApplyPolicy(bad, nil, map[string]json.RawMessage{"openid_relying_party": json.RawMessage(`{}`)}); !errors.Is(err, ErrPolicyError) {
		t.Errorf("ApplyPolicy(bad) = %v, want ErrPolicyError", err)
	}
}
