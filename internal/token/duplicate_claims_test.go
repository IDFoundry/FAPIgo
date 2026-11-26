package token

import (
	"errors"
	"strings"
	"testing"
)

// TestParseClaimsRefuseDuplicateMembers: RFC 7519 §4 requires a JWT's
// claim names to be unique. encoding/json keeps the last copy of a
// repeated one, where a first-wins reader of the same token (a gateway,
// a log processor) keeps the first, so the two would disagree on who
// the token is for. An ID token or JWT access token that repeats a
// member with differing copies, at any depth, or as a case variant, is
// refused; one whose copies are identical, which every reader reads
// alike, is accepted.
func TestParseClaimsRefuseDuplicateMembers(t *testing.T) {
	const idToken = `"iss":"https://as.example.com","aud":"client-1","exp":2,"iat":1`
	const accessToken = `"iss":"https://as.example.com","aud":"https://rs.example.com","exp":2,"iat":1,"jti":"j","client_id":"c"`
	for name, tc := range map[string]struct {
		parse   func([]byte) error
		payload string
		wantErr bool
	}{
		"ID token":                       {parseID, `{` + idToken + `,"sub":"alice"}`, false},
		"ID token, sub twice, same":      {parseID, `{"sub":"alice",` + idToken + `,"sub":"alice"}`, false},
		"ID token, sub twice":            {parseID, `{"sub":"mallory",` + idToken + `,"sub":"alice"}`, true},
		"ID token, nested repeat":        {parseID, `{` + idToken + `,"sub":"alice","address":{"country":"A","country":"B"}}`, true},
		"ID token, case variant":         {parseID, `{` + idToken + `,"sub":"alice","SUB":"mallory"}`, true},
		"access token":                   {parseAT, `{` + accessToken + `,"sub":"alice"}`, false},
		"access token, sub twice":        {parseAT, `{"sub":"mallory",` + accessToken + `,"sub":"alice"}`, true},
		"access token, scope twice":      {parseAT, `{` + accessToken + `,"sub":"alice","scope":"admin","scope":"read"}`, true},
		"access token, cnf twice, same":  {parseAT, `{` + accessToken + `,"sub":"alice","cnf":{"jkt":"a"},"cnf":{ "jkt": "a" }}`, false},
		"access token, cnf twice":        {parseAT, `{` + accessToken + `,"sub":"alice","cnf":{"jkt":"a"},"cnf":{"jkt":"b"}}`, true},
		"access token, jkt twice in cnf": {parseAT, `{` + accessToken + `,"sub":"alice","cnf":{"jkt":"a","jkt":"b"}}`, true},
	} {
		t.Run(name, func(t *testing.T) {
			checkDuplicateRefusal(t, tc.parse([]byte(tc.payload)), tc.wantErr)
		})
	}
}

func parseID(p []byte) error { _, err := parseIDTokenClaims(p); return err }
func parseAT(p []byte) error { _, err := parseAccessTokenClaims(p); return err }

// checkDuplicateRefusal checks err is nil, or, when wantErr, that it is
// ErrMalformedClaims naming a duplicate member.
func checkDuplicateRefusal(t *testing.T, err error, wantErr bool) {
	t.Helper()
	switch {
	case !wantErr && err != nil:
		t.Fatalf("parse = %v, want nil", err)
	case wantErr && (!errors.Is(err, ErrMalformedClaims) || !strings.Contains(err.Error(), "duplicate member name")):
		t.Fatalf("parse = %v, want ErrMalformedClaims for a duplicate member", err)
	}
}
