package client

import (
	"errors"
	"testing"

	"github.com/idfoundry/fapigo/internal/strictjson"
)

// TestDecodeUserInfoJSONRefusesDuplicateMembers: a UserInfo response,
// plain JSON or a signed JWT's payload, whose sub is compared with the
// ID token's, may not repeat a member: encoding/json keeps the last
// copy, where another reader of the same response (a gateway, a log
// processor) may keep the first, so the two would see different users.
// RFC 7519 §4 requires unique claim names in a JWT, and RFC 8259 §4 has
// a JSON object's names unique.
func TestDecodeUserInfoJSONRefusesDuplicateMembers(t *testing.T) {
	if _, err := decodeUserInfoJSON([]byte(`{"sub":"alice","email":"a@example.com"}`)); err != nil {
		t.Fatalf("decodeUserInfoJSON(valid) = %v, want nil", err)
	}
	for _, body := range []string{
		`{"sub":"mallory","sub":"alice"}`,
		`{"sub":"alice","address":{"country":"A","country":"B"}}`,
		`{"sub":"alice","SUB":"mallory"}`,
	} {
		_, err := decodeUserInfoJSON([]byte(body))
		if err == nil || err.Code() != ErrorInvalidResponse || !errors.Is(err, strictjson.ErrDuplicateMember) {
			t.Errorf("decodeUserInfoJSON(%s) = %v, want invalid_response for a duplicate member", body, err)
		}
	}
}
