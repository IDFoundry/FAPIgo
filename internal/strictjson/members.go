package strictjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// MaxNestingDepth is how deeply CheckDuplicateMembers descends: an
// object or array nested inside MaxNestingDepth others is refused, not
// walked. No JOSE header, JWT claims set or metadata document nests
// anywhere near that deep, and the bound keeps the walk's recursion
// small whatever it is given.
const MaxNestingDepth = 64

// ErrDuplicateMember is the error CheckDuplicateMembers wraps when an
// object repeats a member name.
var ErrDuplicateMember = errors.New("strictjson: duplicate member name")

// errNestedTooDeep is CheckDuplicateMembers' error for a value nested
// more than MaxNestingDepth deep.
var errNestedTooDeep = fmt.Errorf("strictjson: JSON nested more than %d deep", MaxNestingDepth)

// CheckDuplicateMembers reports an error wrapping ErrDuplicateMember if
// an object anywhere in data's first JSON value, at any depth, has two
// members whose names are the same once unescaped ("kid" and
// "\u006bid"), or the same under FoldKey ("kid" and "KID"). It also
// refuses a value that nests objects and arrays more than
// MaxNestingDepth deep, and reports malformed JSON as encoding/json
// does. Anything after the first value is left to the caller
// (CheckFieldCase refuses it).
//
// encoding/json keeps the last copy of a repeated member, or, when the
// member decodes into a struct or a map, merges the copies into one
// value. It also reads two names FoldKey maps together as one member.
// Another implementation may keep the first copy, or read the names as
// two members, so two readers could take different values from one
// signed or encrypted document. RFC 7515 §4, RFC 7516 §4 and RFC 7519
// §4 require a JOSE header's parameter names and a JWT's claim names to
// be unique, and let a recipient reject a repeat; RFC 7517 §4 does the
// same for a JWK's members. Any other object, such as a metadata
// document or one nested in a private member, is plain JSON, whose
// names RFC 8259 §4 says SHOULD be unique, noting that some recipients
// refuse a repeat.
//
// It reads data once, and holds the names of each object it is inside,
// so it takes time and memory linear in len(data).
func CheckDuplicateMembers(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber() // numbers are skipped, never converted, so none overflows
	err := checkValueMembers(dec, 0)
	if errors.Is(err, io.EOF) {
		return io.ErrUnexpectedEOF // a whole value never ends early
	}
	return err
}

// checkValueMembers checks the next value dec reads, which depth
// objects and arrays enclose.
func checkValueMembers(dec *json.Decoder, depth int) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	if depth >= MaxNestingDepth {
		return errNestedTooDeep
	}
	if delim == '{' {
		return checkObjectMembers(dec, depth)
	}
	for dec.More() {
		if err := checkValueMembers(dec, depth+1); err != nil {
			return err
		}
	}
	_, err = dec.Token() // "]"
	return err
}

// checkObjectMembers checks the members of the object whose "{" dec has
// just read, and their values, through its "}".
func checkObjectMembers(dec *json.Decoder, depth int) error {
	seen := make(map[string]string) // by FoldKey, the name as first spelled
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		name, _ := tok.(string) // a json.Decoder only reads a string here
		key := FoldKey(name)
		if first, repeated := seen[key]; repeated {
			return duplicateMemberError(first, name)
		}
		seen[key] = name
		if err := checkValueMembers(dec, depth+1); err != nil {
			return err
		}
	}
	_, err := dec.Token() // "}"
	return err
}

// duplicateMemberError is the error for name, which repeats first.
func duplicateMemberError(first, name string) error {
	if first == name {
		return fmt.Errorf("%w %q", ErrDuplicateMember, name)
	}
	return fmt.Errorf("%w: %q and %q differ only in case, which encoding/json reads as one member: JSON member names are case-sensitive",
		ErrDuplicateMember, first, name)
}
