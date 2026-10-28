package federation

import (
	"encoding/json"
	"errors"
	"testing"
)

// TestApplyPolicyTreatsScopeAsStringArray checks every standard
// operator on a scope published as RFC 7591's space-separated string:
// OpenID Federation 1.0 §6.1.3.1.8 has operators process it as a string
// array and the result be a space-separated string again.
func TestApplyPolicyTreatsScopeAsStringArray(t *testing.T) {
	for _, tc := range []struct {
		name, ops, metadata, want string
		wantErr                   bool
	}{
		{name: "subset_of narrows", ops: `{"subset_of":["openid","profile","email"]}`, metadata: `{"scope":"openid profile address"}`, want: `"openid profile"`},
		{name: "subset_of with no common value", ops: `{"subset_of":["email"]}`, metadata: `{"scope":"openid"}`, want: `""`},
		{name: "superset_of satisfied", ops: `{"superset_of":["openid"]}`, metadata: `{"scope":"openid profile"}`, want: `"openid profile"`},
		{name: "superset_of unsatisfied", ops: `{"superset_of":["email"]}`, metadata: `{"scope":"openid profile"}`, wantErr: true},
		{name: "add to present", ops: `{"add":["email"]}`, metadata: `{"scope":"openid profile"}`, want: `"openid profile email"`},
		{name: "add to absent", ops: `{"add":["openid"]}`, metadata: `{}`, want: `"openid"`},
		{name: "default array on absent", ops: `{"default":["openid"]}`, metadata: `{}`, want: `"openid"`},
		{name: "default string on absent", ops: `{"default":"openid profile"}`, metadata: `{}`, want: `"openid profile"`},
		{name: "default leaves present", ops: `{"default":["openid"]}`, metadata: `{"scope":"openid  email"}`, want: `"openid email"`},
		{name: "value string", ops: `{"value":"openid email"}`, metadata: `{"scope":"openid"}`, want: `"openid email"`},
		{name: "value array", ops: `{"value":["openid","email"]}`, metadata: `{"scope":"openid"}`, want: `"openid email"`},
		{name: "value null removes", ops: `{"value":null}`, metadata: `{"scope":"openid"}`},
		{name: "one_of string option matches", ops: `{"one_of":["openid","openid profile"]}`, metadata: `{"scope":"openid profile"}`, want: `"openid profile"`},
		{name: "one_of no option matches", ops: `{"one_of":["openid"]}`, metadata: `{"scope":"openid profile"}`, wantErr: true},
		{name: "essential present", ops: `{"essential":true}`, metadata: `{"scope":"openid"}`, want: `"openid"`},
		{name: "essential absent", ops: `{"essential":true}`, metadata: `{}`, wantErr: true},
		{name: "value with subset_of as string", ops: `{"value":"openid","subset_of":["openid","email"]}`, metadata: `{}`, want: `"openid"`},
		{name: "non-string value is refused", ops: `{"add":[1]}`, metadata: `{"scope":"openid"}`, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			policy := mustPolicy(t, `{"openid_relying_party":{"scope":`+tc.ops+`}}`)
			out, err := ApplyPolicy(policy, nil, map[string]json.RawMessage{"openid_relying_party": json.RawMessage(tc.metadata)})
			checkScopeResult(t, out, err, tc.want, tc.wantErr)
		})
	}
}

func checkScopeResult(t *testing.T, out map[string]json.RawMessage, err error, want string, wantErr bool) {
	t.Helper()
	if wantErr {
		if !errors.Is(err, ErrPolicyError) {
			t.Fatalf("ApplyPolicy err = %v, want a policy error", err)
		}
		return
	}
	if err != nil {
		t.Fatalf("ApplyPolicy: %v", err)
	}
	var rp map[string]json.RawMessage
	if err := json.Unmarshal(out["openid_relying_party"], &rp); err != nil {
		t.Fatal(err)
	}
	got, present := rp["scope"]
	if want == "" {
		if present {
			t.Fatalf("scope = %s, want absent", got)
		}
		return
	}
	if string(got) != want {
		t.Fatalf("scope = %s, want %s", got, want)
	}
}

// TestMergePolicyScopeStringAndArrayOperands checks that a superior's
// scope value given as a string and a subordinate's given as the
// equivalent array merge as equal (§6.1.3.1.1 "The operator values MUST
// be equal"), since both state the same string array.
func TestMergePolicyScopeStringAndArrayOperands(t *testing.T) {
	superior := mustPolicy(t, `{"openid_relying_party":{"scope":{"value":"openid email"}}}`)
	subordinate := mustPolicy(t, `{"openid_relying_party":{"scope":{"value":["openid","email"]}}}`)
	merged, err := MergePolicy(superior, nil, subordinate, nil)
	if err != nil {
		t.Fatalf("MergePolicy: %v", err)
	}
	out, err := ApplyPolicy(merged, nil, map[string]json.RawMessage{"openid_relying_party": json.RawMessage(`{"scope":"openid"}`)})
	checkScopeResult(t, out, err, `"openid email"`, false)
}

// TestValidatePolicyScopeStringValueWithSubsetOf checks ValidatePolicy
// compares a string scope value with subset_of as a set of values.
func TestValidatePolicyScopeStringValueWithSubsetOf(t *testing.T) {
	if err := ValidatePolicy(mustPolicy(t, `{"openid_relying_party":{"scope":{"value":"openid email","subset_of":["openid","email"]}}}`), nil); err != nil {
		t.Fatalf("ValidatePolicy: %v", err)
	}
	if err := ValidatePolicy(mustPolicy(t, `{"openid_relying_party":{"scope":{"value":"openid address","subset_of":["openid","email"]}}}`), nil); !errors.Is(err, ErrPolicyError) {
		t.Fatalf("ValidatePolicy err = %v, want a policy error", err)
	}
}

// TestApplyPolicyScopeWithoutPolicyIsUnchanged checks a scope no policy
// names is passed through as published.
func TestApplyPolicyScopeWithoutPolicyIsUnchanged(t *testing.T) {
	out, err := ApplyPolicy(mustPolicy(t, `{"openid_relying_party":{"contacts":{"add":["a@example.org"]}}}`), nil,
		map[string]json.RawMessage{"openid_relying_party": json.RawMessage(`{"scope":"openid  profile"}`)})
	checkScopeResult(t, out, err, `"openid  profile"`, false)
}

// TestSpaceDelimitedHelpersLeaveOtherShapesAlone covers the shapes the
// split and join steps don't rewrite, and the arrays they can't join.
func TestSpaceDelimitedHelpersLeaveOtherShapesAlone(t *testing.T) {
	if got := splitSpaceDelimitedOperators(nil); got != nil {
		t.Errorf("splitSpaceDelimitedOperators(nil) = %v", got)
	}
	if got := string(splitOneOfOptions(json.RawMessage(`"not an array"`))); got != `"not an array"` {
		t.Errorf("splitOneOfOptions(non-array) = %s", got)
	}
	if got := string(splitSpaceDelimited(json.RawMessage(`["a"]`))); got != `["a"]` {
		t.Errorf("splitSpaceDelimited(array) = %s", got)
	}
	if got, err := joinSpaceDelimited(json.RawMessage(`"a b"`)); err != nil || string(got) != `"a b"` {
		t.Errorf("joinSpaceDelimited(string) = %s, %v", got, err)
	}
	for _, bad := range []string{`["a b"]`, `[""]`, `[1]`} {
		if _, err := joinSpaceDelimited(json.RawMessage(bad)); !errors.Is(err, ErrPolicyError) {
			t.Errorf("joinSpaceDelimited(%s) = %v, want a policy error", bad, err)
		}
	}
}
