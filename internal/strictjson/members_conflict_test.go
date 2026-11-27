package strictjson

import (
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
)

// TestCheckConflictingMembersAcceptsIdenticalRepeats: a member repeated
// with the same value, at the top level or nested, gives every reader
// that value, so it is accepted, as is everything CheckDuplicateMembers
// accepts. Whitespace inside or around a copy's value is not part of it.
func TestCheckConflictingMembersAcceptsIdenticalRepeats(t *testing.T) {
	for name, data := range map[string]string{
		"unique names":           `{"alg":"ES256","kid":"a"}`,
		"top level":              `{"iss":"https://as.example","code":"c","iss":"https://as.example"}`,
		"three copies":           `{"a":1,"a":1,"a":1}`,
		"nested":                 `{"cnf":{"jkt":"a","jkt":"a"}}`,
		"object value":           `{"cnf":{"jkt":"a","x":[1,2]},"cnf":{"jkt":"a","x":[1,2]}}`,
		"in an array":            `[{"a":null,"a":null}]`,
		"whitespace differs":     "{\"cnf\":{\"jkt\":\"a\"},\"cnf\" :\n\t{ \"jkt\" : \"a\" } }",
		"escaped name, same":     "{\"kid\":\"a\",\"\x5cu006bid\":\"a\"}",
		"only the first value":   `{"a":1,"a":1} {"a":1,"a":2}`,
		"repeat with whitespace": `{"a" : true , "a" : true}`,
	} {
		if err := CheckConflictingMembers([]byte(data)); err != nil {
			t.Errorf("%s: CheckConflictingMembers(%s) = %v, want nil", name, data, err)
		}
	}
}

// TestCheckConflictingMembersRefusesConflicts: a repeat whose copies
// differ, at any depth, or whose copies are spelled differently even
// if some reader would take them as equal; two names that differ only
// in case, whatever their values; and a repeat inside each of two
// identical copies, are all refused.
func TestCheckConflictingMembersRefusesConflicts(t *testing.T) {
	for name, data := range map[string]string{
		"top level":                  `{"iss":"https://evil.example","iss":"https://as.example"}`,
		"third copy differs":         `{"a":1,"a":1,"a":2}`,
		"nested":                     `{"cnf":{"jkt":"a","jkt":"b"}}`,
		"object copies differ":       `{"cnf":{"jkt":"a"},"cnf":{"jkt":"b"}}`,
		"object copies merge":        `{"cnf":{"jkt":"a"},"cnf":{}}`,
		"in an array":                `{"keys":[{"kid":"a"},{"kid":"b","kid":"c"}]}`,
		"string spelled differently": "{\"a\":\"a\",\"a\":\"\x5cu0061\"}",
		"number spelled differently": `{"a":1,"a":1.0}`,
		"member order differs":       `{"o":{"x":1,"y":2},"o":{"y":2,"x":1}}`,
		"case variant, same value":   `{"kid":"a","KID":"a"}`,
		"case variant, nested":       `{"cnf":{"jkt":"a","Jkt":"a"}}`,
		"case variant of a repeat":   `{"kid":"a","kid":"a","Kid":"a"}`,
		"Kelvin sign, same value":    "{\"kid\":\"a\",\"\xe2\x84\xaaid\":\"a\"}",
		"repeat inside identical":    `{"cnf":{"jkt":"a","jkt":"b"},"cnf":{"jkt":"a","jkt":"b"}}`,
		"case variant inside copies": `{"cnf":{"jkt":"a","JKT":"a"},"cnf":{"jkt":"a","JKT":"a"}}`,
	} {
		if err := CheckConflictingMembers([]byte(data)); !errors.Is(err, ErrDuplicateMember) {
			t.Errorf("%s: CheckConflictingMembers(%s) = %v, want ErrDuplicateMember", name, data, err)
		}
	}
}

func TestCheckConflictingMembersNamesTheMembers(t *testing.T) {
	err := CheckConflictingMembers([]byte(`{"iss":"a","iss":"b"}`))
	if err == nil || err.Error() != `strictjson: duplicate member name "iss", whose copies differ` {
		t.Errorf("differing copies: err = %v", err)
	}
	err = CheckConflictingMembers([]byte(`{"kid":"a","KID":"a"}`))
	if err == nil || !strings.Contains(err.Error(), `"kid" and "KID" differ only in case`) {
		t.Errorf("case variant: err = %v", err)
	}
}

// TestCheckConflictingMembersBoundsNesting: the walk that compares
// copies has CheckDuplicateMembers' nesting bound, including inside a
// repeated member.
func TestCheckConflictingMembersBoundsNesting(t *testing.T) {
	deep := func(n int) string { return strings.Repeat("[", n) + strings.Repeat("]", n) }
	atBound := `{"a":` + deep(MaxNestingDepth-1) + `,"a":` + deep(MaxNestingDepth-1) + `}`
	if err := CheckConflictingMembers([]byte(atBound)); err != nil {
		t.Errorf("at the bound: CheckConflictingMembers = %v, want nil", err)
	}
	for name, data := range map[string]string{
		"past the bound":                  deep(MaxNestingDepth + 1),
		"repeated, past the bound":        `{"a":` + deep(MaxNestingDepth) + `,"a":` + deep(MaxNestingDepth) + `}`,
		"identical repeat past the bound": strings.Repeat("[", MaxNestingDepth) + `{"a":1,"a":1}` + strings.Repeat("]", MaxNestingDepth),
	} {
		if err := CheckConflictingMembers([]byte(data)); !errors.Is(err, errNestedTooDeep) {
			t.Errorf("%s: CheckConflictingMembers = %v, want errNestedTooDeep", name, err)
		}
	}
}

func TestCheckConflictingMembersReportsMalformedJSON(t *testing.T) {
	for _, data := range []string{``, `{`, `{"a":1,"a":1`, `{"a":1,"a":}`, `{"a":1,"a":1,}`, `{1:2}`, `not json`} {
		err := CheckConflictingMembers([]byte(data))
		if err == nil || errors.Is(err, ErrDuplicateMember) {
			t.Errorf("CheckConflictingMembers(%q) = %v, want a syntax error", data, err)
		}
	}
	if err := CheckConflictingMembers([]byte(``)); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("CheckConflictingMembers(``) = %v, want io.ErrUnexpectedEOF", err)
	}
	err := CheckConflictingMembers([]byte(`{"a":1,"a":1`))
	var syntax *json.SyntaxError
	if !errors.Is(err, io.ErrUnexpectedEOF) && !errors.As(err, &syntax) {
		t.Errorf("cut off: CheckConflictingMembers = %v, want io.ErrUnexpectedEOF or a *json.SyntaxError", err)
	}
}

// TestUnmarshalNoConflicts: UnmarshalNoConflicts refuses what Unmarshal
// does and a conflicting repeat, and decodes an identical one.
func TestUnmarshalNoConflicts(t *testing.T) {
	type target struct {
		A string         `json:"a"`
		M map[string]int `json:"m"`
	}
	for body, ok := range map[string]bool{
		`{"a":"x"}`:                   true,
		`{"a":"x","a":"x"}`:           true,
		`{"a":"x","m":{"k":1,"k":1}}`: true,
		`{"a":"x","a":"y"}`:           false,
		`{"a":"x","A":"x"}`:           false,
		`{"A":"x"}`:                   false,
		`{"a":"x","m":{"k":1,"k":2}}`: false,
		`{"a":"x"} {}`:                false,
	} {
		var v target
		err := UnmarshalNoConflicts([]byte(body), &v)
		if (err == nil) != ok {
			t.Errorf("UnmarshalNoConflicts(%s) = %v, want ok %v", body, err, ok)
		}
		if ok && v.A != "x" {
			t.Errorf("UnmarshalNoConflicts(%s): A = %q, want x", body, v.A)
		}
	}
}

// TestCheckConflictingObject: CheckConflictingObject refuses, naming the
// member at fault, the objects whose encoding CheckConflictingMembers
// refuses — a value repeating a member with differing copies or as a
// case variant, at any depth; two member names that differ only in
// case; a value nesting too deep once inside the object; and a value
// that isn't JSON — and accepts the rest, an identical repeat included.
func TestCheckConflictingObject(t *testing.T) {
	deep := strings.Repeat("[", MaxNestingDepth) + strings.Repeat("]", MaxNestingDepth)
	if err := CheckConflictingMembers([]byte(deep)); err != nil {
		t.Fatalf("CheckConflictingMembers(%d nested arrays) = %v, want nil on its own", MaxNestingDepth, err)
	}
	for name, tc := range map[string]struct {
		members map[string]json.RawMessage
		fault   string
	}{
		"no members":        {members: map[string]json.RawMessage{}},
		"plain":             {members: map[string]json.RawMessage{"a": json.RawMessage(`1`), "b": json.RawMessage(`{"c":[1,{"d":2}]}`)}},
		"identical repeat":  {members: map[string]json.RawMessage{"act": json.RawMessage(`{"sub":"a", "sub" : "a"}`)}},
		"differing repeat":  {members: map[string]json.RawMessage{"a": json.RawMessage(`1`), "act": json.RawMessage(`{"sub":"a","sub":"b"}`)}, fault: "act"},
		"empty-name repeat": {members: map[string]json.RawMessage{"0": json.RawMessage(`{"":0,"":1}`)}, fault: "0"},
		"nested repeat":     {members: map[string]json.RawMessage{"x": json.RawMessage(`[{"y":{"z":1,"z":2}}]`)}, fault: "x"},
		"case variant":      {members: map[string]json.RawMessage{"x": json.RawMessage(`{"kid":"a","KID":"a"}`)}, fault: "x"},
		"top-level case":    {members: map[string]json.RawMessage{"roles": json.RawMessage(`1`), "Roles": json.RawMessage(`1`)}, fault: "roles"},
		"too deep inside":   {members: map[string]json.RawMessage{"x": json.RawMessage(deep)}, fault: "x"},
		"not JSON":          {members: map[string]json.RawMessage{"x": json.RawMessage(`1],[2`)}, fault: "x"},
	} {
		t.Run(name, func(t *testing.T) {
			fault, err := CheckConflictingObject(tc.members)
			if (err != nil) != (tc.fault != "") || fault != tc.fault {
				t.Fatalf("CheckConflictingObject = %q, %v; want fault %q", fault, err, tc.fault)
			}
			if tc.fault == "" {
				return
			}
			if encoded, merr := MarshalUnescaped(tc.members); merr == nil && CheckConflictingMembers(encoded) == nil {
				t.Fatalf("CheckConflictingObject refuses %s, which CheckConflictingMembers accepts", encoded)
			}
		})
	}
}
