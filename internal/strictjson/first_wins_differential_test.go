package strictjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
)

// TestCheckDuplicateMembersClosesFirstWinsDifferential models the
// intermediary RFC 7515 §10.12 warns about: a reader that keeps the
// first copy of a repeated member (as some streaming JSON path readers
// do) and encoding/json, which keeps the last, take different values
// from one claims set. CheckDuplicateMembers and CheckConflictingMembers,
// one of which every JWT claims parser runs, refuse the claims set, so
// neither reading is acted on.
func TestCheckDuplicateMembersClosesFirstWinsDifferential(t *testing.T) {
	for _, tc := range []struct{ payload, member, first, last string }{
		{`{"sub":"alice","aud":"rs","sub":"admin"}`, "sub", `"alice"`, `"admin"`},
		{`{"aud":"https://evil.example","iss":"c","aud":"https://as.example"}`, "aud", `"https://evil.example"`, `"https://as.example"`},
		{`{"alg":"ES256","kid":"a","kid":"b"}`, "kid", `"a"`, `"b"`},
	} {
		var lastWins map[string]json.RawMessage
		if err := json.Unmarshal([]byte(tc.payload), &lastWins); err != nil {
			t.Fatal(err)
		}
		if got := string(lastWins[tc.member]); got != tc.last {
			t.Fatalf("encoding/json read %s = %s, want %s", tc.member, got, tc.last)
		}
		if got := firstWins(t, tc.payload, tc.member); got != tc.first {
			t.Fatalf("first-wins reader read %s = %s, want %s", tc.member, got, tc.first)
		}
		if err := CheckDuplicateMembers([]byte(tc.payload)); !errors.Is(err, ErrDuplicateMember) {
			t.Errorf("CheckDuplicateMembers(%s) = %v, want ErrDuplicateMember", tc.payload, err)
		}
		if err := CheckConflictingMembers([]byte(tc.payload)); !errors.Is(err, ErrDuplicateMember) {
			t.Errorf("CheckConflictingMembers(%s) = %v, want ErrDuplicateMember", tc.payload, err)
		}
	}
}

// TestCheckConflictingMembersAcceptsNoDifferential: a claims set that
// repeats a member with identical copies, as an authorization server
// writing iss both as the JWT claim and as the RFC 9207 response
// parameter does, reads the same to a first-wins reader and to
// encoding/json, so CheckConflictingMembers, which the JWT claims
// parsers run, accepts it.
func TestCheckConflictingMembersAcceptsNoDifferential(t *testing.T) {
	for _, tc := range []struct{ payload, member, value string }{
		{`{"iss":"https://as.example","code":"c","iss":"https://as.example"}`, "iss", `"https://as.example"`},
		{`{"sub":"alice","aud":"rs","sub":"alice"}`, "sub", `"alice"`},
	} {
		var lastWins map[string]json.RawMessage
		if err := json.Unmarshal([]byte(tc.payload), &lastWins); err != nil {
			t.Fatal(err)
		}
		if got := string(lastWins[tc.member]); got != tc.value {
			t.Fatalf("encoding/json read %s = %s, want %s", tc.member, got, tc.value)
		}
		if got := firstWins(t, tc.payload, tc.member); got != tc.value {
			t.Fatalf("first-wins reader read %s = %s, want %s", tc.member, got, tc.value)
		}
		if err := CheckConflictingMembers([]byte(tc.payload)); err != nil {
			t.Errorf("CheckConflictingMembers(%s) = %v, want nil", tc.payload, err)
		}
	}
}

// firstWins returns the first copy of member in payload, a flat JSON
// object of scalar members, as a first-wins reader would.
func firstWins(t *testing.T, payload, member string) string {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader([]byte(payload)))
	if _, err := dec.Token(); err != nil { // "{"
		t.Fatal(err)
	}
	for dec.More() {
		name, err := dec.Token()
		if err != nil {
			t.Fatal(err)
		}
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			t.Fatal(err)
		}
		if name == member {
			return string(value)
		}
	}
	return ""
}
