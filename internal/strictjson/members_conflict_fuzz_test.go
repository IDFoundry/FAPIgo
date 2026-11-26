package strictjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
)

// FuzzCheckConflictingMembersOneReading: whatever CheckConflictingMembers
// accepts has one reading. A reader keeping the first copy of each
// repeated member and encoding/json, keeping the last, read its first
// value as the same tree, and no object in it holds two names FoldKey
// maps together. It accepts everything CheckDuplicateMembers accepts,
// and refuses everything CheckDuplicateMembers refuses for a reason
// other than a repeat.
func FuzzCheckConflictingMembersOneReading(f *testing.F) {
	for _, s := range []string{
		`{"iss":"a","code":"c","iss":"a"}`, `{"iss":"a","iss":"b"}`, `{"cnf":{"jkt":"a"},"cnf":{"jkt":"a"}}`,
		`{"cnf":{"jkt":"a"},"cnf":{}}`, `{"kid":"a","KID":"a"}`, `{"a":1,"a":1.0}`, "{\"a\":\"a\",\"a\":\"\\u0061\"}",
		`{"c":{"j":1,"j":2},"c":{"j":1,"j":2}}`, `[{"a":[1],"a":[1]}]`, `{"a":1,"a":1} {}`,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		dupErr, conflictErr := CheckDuplicateMembers(data), CheckConflictingMembers(data)
		if dupErr == nil && conflictErr != nil {
			t.Fatalf("%q: CheckDuplicateMembers accepts, CheckConflictingMembers = %v", data, conflictErr)
		}
		if dupErr != nil && !errors.Is(dupErr, ErrDuplicateMember) && conflictErr == nil {
			t.Fatalf("%q: CheckDuplicateMembers = %v, CheckConflictingMembers accepts", data, dupErr)
		}
		if conflictErr != nil {
			return
		}
		first, ok := readFirstWins(json.NewDecoder(bytes.NewReader(data)))
		if !ok {
			t.Fatalf("%q: accepted, but a first-wins reader finds a case variant or can't read it", data)
		}
		var last any
		dec := json.NewDecoder(bytes.NewReader(data))
		dec.UseNumber()
		if err := dec.Decode(&last); err != nil {
			t.Fatalf("%q: accepted, but encoding/json can't read it: %v", data, err)
		}
		if !reflect.DeepEqual(first, last) {
			t.Fatalf("%q: first-wins reading %#v, encoding/json's %#v", data, first, last)
		}
	})
}

// readFirstWins reads dec's next value as encoding/json would decode it
// into an any, with UseNumber, except that an object keeps the first
// copy of a repeated member. It reports false for an object holding two
// names FoldKey maps together but that differ, or for malformed JSON.
func readFirstWins(dec *json.Decoder) (any, bool) {
	dec.UseNumber()
	tok, err := dec.Token()
	if err != nil {
		return nil, false
	}
	switch tok {
	case json.Delim('{'):
		return readFirstWinsObject(dec)
	case json.Delim('['):
		out := []any{}
		for dec.More() {
			v, ok := readFirstWins(dec)
			if !ok {
				return nil, false
			}
			out = append(out, v)
		}
		_, err := dec.Token()
		return out, err == nil
	}
	return tok, true
}

func readFirstWinsObject(dec *json.Decoder) (any, bool) {
	out := map[string]any{}
	spelled := map[string]string{} // by FoldKey
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, false
		}
		name, _ := tok.(string)
		if s, ok := spelled[FoldKey(name)]; ok && s != name {
			return nil, false
		}
		spelled[FoldKey(name)] = name
		v, ok := readFirstWins(dec)
		if !ok {
			return nil, false
		}
		if _, repeated := out[name]; !repeated {
			out[name] = v
		}
	}
	_, err := dec.Token()
	return out, err == nil
}
