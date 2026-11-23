package strictjson

import (
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestCheckDuplicateMembersAcceptsUniqueNames(t *testing.T) {
	for _, data := range []string{
		`{}`, `[]`, `"s"`, `1e400`, `null`, ` {"a":1} `,
		`{"alg":"ES256","kid":"a","typ":"JWT"}`,
		`{"a":{"a":{"a":1}}}`, // one name at each depth
		`[{"a":1},{"a":2}]`,   // one name in each of two objects
		`{"a":[{"b":1},{"b":2}],"b":{"a":1}}`,
		`{"x5t":1,"x5t#S256":2}`,                       // names alike, but not under FoldKey
		`{"alg":"ES256"} {"alg":"ES256","alg":"none"}`, // only the first value is walked
	} {
		if err := CheckDuplicateMembers([]byte(data)); err != nil {
			t.Errorf("CheckDuplicateMembers(%s) = %v, want nil", data, err)
		}
	}
}

func TestCheckDuplicateMembersRefusesRepeatedNames(t *testing.T) {
	for name, data := range map[string]string{
		"top level":                       `{"alg":"ES256","alg":"none"}`,
		"escaped copy":                    "{\"kid\":\"a\",\"\x5cu006bid\":\"b\"}",
		"inside an object":                `{"epk":{"kty":"EC","x":"a","x":"b"}}`,
		"object in an array":              `{"keys":[{"kid":"a"},{"kid":"b","kid":"c"}]}`,
		"object in nested arrays":         `[[[{"a":1,"a":2}]]]`,
		"object repeated":                 `{"epk":{"x":"a"},"epk":{"y":"b"}}`,
		"non-last copy of a case variant": `{"epk":{"X":"a"},"epk":{}}`,
		"case variant":                    `{"kid":"a","KID":"b"}`,
		"case variant first":              `{"KID":"a","kid":"b"}`,
		"case variant inside":             `{"cnf":{"jkt":"a","Jkt":"b"}}`,
		"Kelvin sign":                     "{\"kid\":\"a\",\"\xe2\x84\xaaid\":\"b\"}",
		"long s":                          "{\"s\":1,\"\xc5\xbf\":2}",
	} {
		if err := CheckDuplicateMembers([]byte(data)); !errors.Is(err, ErrDuplicateMember) {
			t.Errorf("%s: CheckDuplicateMembers(%s) = %v, want ErrDuplicateMember", name, data, err)
		}
	}
}

func TestCheckDuplicateMembersNamesTheMembers(t *testing.T) {
	err := CheckDuplicateMembers([]byte(`{"epk":{},"epk":{}}`))
	if err == nil || err.Error() != `strictjson: duplicate member name "epk"` {
		t.Errorf("repeated name: err = %v", err)
	}
	err = CheckDuplicateMembers([]byte(`{"kid":"a","KID":"b"}`))
	if err == nil || !strings.Contains(err.Error(), `"kid" and "KID" differ only in case`) || !strings.Contains(err.Error(), "case-sensitive") {
		t.Errorf("case variant: err = %v", err)
	}
}

// The top-level value is at depth 0, so MaxNestingDepth nested arrays
// or objects are walked, and one more is refused, duplicate or not.
func TestCheckDuplicateMembersBoundsNesting(t *testing.T) {
	arrays := func(n int) string { return strings.Repeat("[", n) + strings.Repeat("]", n) }
	objects := func(n int) string { return strings.Repeat(`{"a":`, n-1) + "{}" + strings.Repeat("}", n-1) }
	for name, data := range map[string]string{
		"arrays at the bound":  arrays(MaxNestingDepth),
		"objects at the bound": objects(MaxNestingDepth),
	} {
		if err := CheckDuplicateMembers([]byte(data)); err != nil {
			t.Errorf("%s: CheckDuplicateMembers = %v, want nil", name, err)
		}
	}
	for name, data := range map[string]string{
		"arrays past the bound":   arrays(MaxNestingDepth + 1),
		"objects past the bound":  objects(MaxNestingDepth + 1),
		"a repeat past the bound": strings.Repeat("[", MaxNestingDepth) + `{"a":1,"a":2}` + strings.Repeat("]", MaxNestingDepth),
		"far past the bound":      arrays(10 * MaxNestingDepth),
	} {
		if err := CheckDuplicateMembers([]byte(data)); !errors.Is(err, errNestedTooDeep) {
			t.Errorf("%s: CheckDuplicateMembers = %v, want errNestedTooDeep", name, err)
		}
	}
}

func TestCheckDuplicateMembersReportsMalformedJSON(t *testing.T) {
	for _, data := range []string{``, ` `, `{`, `{"a"`, `{"a":`, `{"a":1`, `[1,`, `{"a":1,}`, `{1:2}`, `not json`} {
		err := CheckDuplicateMembers([]byte(data))
		if err == nil || errors.Is(err, ErrDuplicateMember) {
			t.Errorf("CheckDuplicateMembers(%q) = %v, want a syntax error", data, err)
		}
	}
	// Empty input is io.EOF to every json.Decoder, and
	// CheckDuplicateMembers reports it as io.ErrUnexpectedEOF.
	if err := CheckDuplicateMembers([]byte(``)); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("CheckDuplicateMembers(``) = %v, want io.ErrUnexpectedEOF", err)
	}
	// A value cut off part-way is reported as encoding/json reports it.
	// Go 1.26's json.Decoder returns io.EOF there, which becomes
	// io.ErrUnexpectedEOF; Go 1.27's returns a *json.SyntaxError.
	for _, data := range []string{`{"a":1`, `[{"a":[1`, `[1,`} {
		err := CheckDuplicateMembers([]byte(data))
		var syntax *json.SyntaxError
		if !errors.Is(err, io.ErrUnexpectedEOF) && !errors.As(err, &syntax) {
			t.Errorf("CheckDuplicateMembers(%q) = %v, want io.ErrUnexpectedEOF or a *json.SyntaxError", data, err)
		}
	}
}
