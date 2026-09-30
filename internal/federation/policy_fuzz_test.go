package federation

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"
)

// FuzzMetadataPolicy exercises MergePolicy and ApplyPolicy with two
// arbitrary policies and arbitrary metadata — all chosen by federation
// participants: each superior in a Trust Chain supplies a policy, and
// the subject its metadata. Beyond never panicking, every failure must
// be a policy error, and jsonEqual (which compares canonical encodings,
// so set operations run in linear time) must agree with comparing the
// decoded values directly.
func FuzzMetadataPolicy(f *testing.F) {
	f.Add(`{"openid_relying_party":{"redirect_uris":{"subset_of":["https://a/cb","https://b/cb"]},"token_endpoint_auth_method":{"one_of":["private_key_jwt"],"essential":true}}}`,
		`{"openid_relying_party":{"redirect_uris":{"superset_of":["https://a/cb"]},"contacts":{"add":["ops@a"],"value":["ops@a"]}}}`,
		`{"openid_relying_party":{"redirect_uris":["https://a/cb"],"token_endpoint_auth_method":"private_key_jwt"}}`,
		`[1,-0,{"b":1,"a":[]}]`, `[1.0,0,{"a":[],"b":1}]`)
	f.Add(`{"x":{"y":{"value":null,"subset_of":[]}}}`, `{"x":{"y":{"default":1,"custom_op":2}}}`, `{"x":{"y":1}}`, `"x"`, `"x"`)

	f.Fuzz(func(t *testing.T, first, second, metadata, a, b string) {
		var p1, p2 MetadataPolicy
		var md map[string]json.RawMessage
		if json.Unmarshal([]byte(first), &p1) != nil || json.Unmarshal([]byte(second), &p2) != nil || json.Unmarshal([]byte(metadata), &md) != nil {
			return
		}
		crit := []string{"custom_op"}
		merged, err := MergePolicy(p1, crit, p2, nil)
		if err == nil {
			_, err = ApplyPolicy(merged, crit, md)
		}
		if err != nil && !errors.Is(err, ErrPolicyError) {
			t.Fatalf("error %v is not an ErrPolicyError", err)
		}

		var av, bv any
		if json.Unmarshal([]byte(a), &av) != nil || json.Unmarshal([]byte(b), &bv) != nil {
			return
		}
		equal, err := jsonEqual(json.RawMessage(a), json.RawMessage(b))
		if err != nil {
			t.Fatalf("jsonEqual(%s, %s): %v", a, b, err)
		}
		if want := reflect.DeepEqual(av, bv); equal != want {
			t.Fatalf("jsonEqual(%s, %s) = %v, want %v", a, b, equal, want)
		}
	})
}
