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
// a JSON object's names unique. A member repeated with identical copies
// reads alike to every reader, so it is accepted.
func TestDecodeUserInfoJSONRefusesDuplicateMembers(t *testing.T) {
	for _, body := range []string{
		`{"sub":"alice","email":"a@example.com"}`,
		`{"sub":"alice","email":"a@example.com","sub":"alice"}`,
		`{"sub":"alice","address":{"country":"A","country":"A"}}`,
	} {
		if _, err := decodeUserInfoJSON([]byte(body)); err != nil {
			t.Fatalf("decodeUserInfoJSON(%s) = %v, want nil", body, err)
		}
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
