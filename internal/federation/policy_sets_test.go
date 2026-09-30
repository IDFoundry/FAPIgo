package federation

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestJSONEqual(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want bool
	}{
		{`1`, `1.0`, true},
		{`0`, `-0`, true},
		{`[0]`, `[-0.0]`, true},
		{`{"a":1,"b":[1,2]}`, `{"b":[1,2],"a":1}`, true},
		{`"x"`, `"x"`, true},
		{`[1,2]`, `[2,1]`, false},
		{`1`, `"1"`, false},
		{`null`, `false`, false},
		{`{"a":{"b":1}}`, `{"a":{"b":2}}`, false},
	} {
		got, err := jsonEqual(json.RawMessage(tc.a), json.RawMessage(tc.b))
		if err != nil || got != tc.want {
			t.Errorf("jsonEqual(%s, %s) = %v, %v; want %v", tc.a, tc.b, got, err, tc.want)
		}
	}
	if _, err := jsonEqual(json.RawMessage(`1`), json.RawMessage(`{`)); err == nil {
		t.Error("jsonEqual(malformed) = nil error, want error")
	}
}

func TestUnionAndIntersectArrays(t *testing.T) {
	union, err := unionArrays(json.RawMessage(`["a",1,"a"]`), json.RawMessage(`[1.0,"b","b",{"x":1}]`))
	if err != nil || string(union) != `["a",1,"a","b",{"x":1}]` {
		t.Errorf("unionArrays = %s, %v", union, err)
	}
	intersection, err := intersectArrays(json.RawMessage(`["a",1,"c"]`), json.RawMessage(`[1.0,"a"]`))
	if err != nil || string(intersection) != `["a",1]` {
		t.Errorf("intersectArrays = %s, %v", intersection, err)
	}
	if _, err := unionArrays(json.RawMessage(`["a"]`), json.RawMessage(`[{]`)); err == nil {
		t.Error("unionArrays(malformed) = nil error, want error")
	}
}

// TestPolicySetOperationsAreNotQuadratic covers policies with large
// arrays. A Trust Chain's superiors choose them, and chains are resolved
// before a client authenticates, so comparing every pair of values let
// one ~300 KB policy take minutes (and one of this test's 5000-value checks over 8 seconds) to validate, merge or apply.
func TestPolicySetOperationsAreNotQuadratic(t *testing.T) {
	const n = 5000
	values := make([]string, n)
	for i := range values {
		values[i] = fmt.Sprintf(`"https://rp.example/cb/%d"`, i)
	}
	arr := "[" + strings.Join(values, ",") + "]"
	policy := mustPolicy(t, fmt.Sprintf(`{"openid_relying_party":{"redirect_uris":{"value":%[1]s,"subset_of":%[1]s,"superset_of":%[1]s}}}`, arr))
	next := mustPolicy(t, fmt.Sprintf(`{"openid_relying_party":{"redirect_uris":{"subset_of":%[1]s,"superset_of":%[1]s},"contacts":{"one_of":%[1]s}}}`, arr))
	crit := make([]string, n)
	for i := range crit {
		crit[i] = fmt.Sprintf("op_%d", i)
	}

	start := time.Now()
	merged, err := MergePolicy(policy, crit, next, crit)
	if err != nil {
		t.Fatalf("MergePolicy: %v", err)
	}
	if _, err := ApplyPolicy(merged, crit, map[string]json.RawMessage{
		"openid_relying_party": json.RawMessage(`{"redirect_uris":` + arr + `,"contacts":` + values[n-1] + `}`),
	}); err != nil {
		t.Fatalf("ApplyPolicy: %v", err)
	}
	// Linear work takes well under a second; the quadratic version took minutes.
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Errorf("merging and applying %d-value policies took %v", n, elapsed)
	}
}

// TestPolicySetOperationsRejectUndecodableValues covers array elements
// that are valid JSON but can't be decoded for comparison (a number out
// of float64's range): each set operation reports a policy error.
func TestPolicySetOperationsRejectUndecodableValues(t *testing.T) {
	const huge = `1e400`
	for name, policy := range map[string]string{
		"subset check":      `{"x":{"y":{"add":[1],"subset_of":[` + huge + `]}}}`,
		"value in one_of":   `{"x":{"y":{"value":1,"one_of":[` + huge + `]}}}`,
		"undecodable value": `{"x":{"y":{"value":` + huge + `,"one_of":[1]}}}`,
	} {
		if err := ValidatePolicy(mustPolicy(t, policy), nil); !errors.Is(err, ErrPolicyError) {
			t.Errorf("ValidatePolicy(%s) = %v, want ErrPolicyError", name, err)
		}
	}

	for name, tc := range map[string]struct{ policy, metadata string }{
		"superset_of":         {`{"x":{"y":{"superset_of":[1]}}}`, `{"x":{"y":[` + huge + `]}}`},
		"subset_of intersect": {`{"x":{"y":{"subset_of":[` + huge + `]}}}`, `{"x":{"y":[1]}}`},
		"add union":           {`{"x":{"y":{"add":[1]}}}`, `{"x":{"y":[` + huge + `]}}`},
		"one_of":              {`{"x":{"y":{"one_of":[` + huge + `]}}}`, `{"x":{"y":1}}`},
	} {
		var md map[string]json.RawMessage
		if err := json.Unmarshal([]byte(tc.metadata), &md); err != nil {
			t.Fatal(err)
		}
		if _, err := ApplyPolicy(mustPolicy(t, tc.policy), nil, md); !errors.Is(err, ErrPolicyError) {
			t.Errorf("ApplyPolicy(%s) = %v, want ErrPolicyError", name, err)
		}
	}

	if _, err := unionArrays(json.RawMessage(`[1]`), json.RawMessage(`[`+huge+`]`)); !errors.Is(err, ErrPolicyError) {
		t.Errorf("unionArrays(undecodable) = %v, want ErrPolicyError", err)
	}
	if _, err := jsonEqual(json.RawMessage(huge), json.RawMessage(`1`)); !errors.Is(err, ErrPolicyError) {
		t.Errorf("jsonEqual(undecodable) = %v, want ErrPolicyError", err)
	}
}
