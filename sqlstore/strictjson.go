package sqlstore

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// checkStrictJSON reports an error for data, JSON text to be decoded
// into a value of v's type, that encoding/json would read other than as
// written:
//
//   - a member appearing twice in one object, of which encoding/json
//     keeps the last and silently drops the others;
//   - a member whose name matches one of a struct's json tags only
//     case-insensitively, which encoding/json reads as that member
//     although it isn't;
//   - invalid UTF-8, or a \u escape of an unpaired UTF-16 surrogate,
//     which encoding/json replaces with U+FFFD.
//
// Each lets a document a reviewer, or another JSON parser, reads one
// way configure something else. Data that isn't JSON at all is left for
// the decode that follows to refuse.
func checkStrictJSON(data []byte, v any) error {
	if !decodesLosslessly(data) {
		return errors.New("invalid UTF-8, or an escaped unpaired surrogate, which would decode as U+FFFD")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	w := jsonWalker{root: reflect.TypeOf(v)}
	for {
		tok, err := dec.Token()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return nil // not JSON: the decode refuses it
		}
		if err := w.token(tok); err != nil {
			return err
		}
	}
}

// jsonWalker follows a stream of json.Decoder tokens, knowing the Go
// type each value is decoded into.
type jsonWalker struct {
	root  reflect.Type
	stack []*jsonFrame
}

// jsonFrame is an object or array the walker is inside.
type jsonFrame struct {
	object  bool
	key     bool                    // an object's next token is a member name
	seen    map[string]bool         // an object's member names so far
	fields  map[string]reflect.Type // a struct's members by json tag; nil for any other type
	pending reflect.Type            // the type of the member value next, or an array's element type
}

func (w *jsonWalker) token(tok json.Token) error {
	if d, ok := tok.(json.Delim); ok && (d == '}' || d == ']') {
		w.stack = w.stack[:len(w.stack)-1]
		return nil
	}
	var top *jsonFrame
	if len(w.stack) > 0 {
		top = w.stack[len(w.stack)-1]
	}
	if top != nil && top.object && top.key {
		name, _ := tok.(string)
		return top.member(name)
	}
	t := w.root
	if top != nil {
		t = top.pending
		top.key = top.object
	}
	switch tok {
	case json.Delim('{'):
		w.stack = append(w.stack, &jsonFrame{object: true, key: true, seen: map[string]bool{}, fields: structFields(t)})
	case json.Delim('['):
		w.stack = append(w.stack, &jsonFrame{pending: elemType(t)})
	}
	return nil
}

// member checks name, the next member of the object f.
func (f *jsonFrame) member(name string) error {
	if f.seen[name] {
		return fmt.Errorf("member %q appears more than once", name)
	}
	f.seen[name] = true
	f.key = false
	if t, ok := f.fields[name]; ok || f.fields == nil {
		f.pending = t
		return nil
	}
	for exact := range f.fields {
		if strings.EqualFold(name, exact) {
			return fmt.Errorf("member %q is not %q: member names are case-sensitive", name, exact)
		}
	}
	f.pending = nil // unknown: the decode refuses it
	return nil
}

// structFields maps the json tag name of each tagged field of t, a
// struct or a pointer to one, to the field's type; nil for any other
// type.
func structFields(t reflect.Type) map[string]reflect.Type {
	for t != nil && t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t == nil || t.Kind() != reflect.Struct {
		return nil
	}
	out := map[string]reflect.Type{}
	for i := range t.NumField() {
		f := t.Field(i)
		if name, _, _ := strings.Cut(f.Tag.Get("json"), ","); name != "" && name != "-" && f.IsExported() {
			out[name] = f.Type
		}
	}
	return out
}

// elemType is the element type of t, a slice or array (or a pointer to
// one); nil for any other type.
func elemType(t reflect.Type) reflect.Type {
	for t != nil && t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t == nil || (t.Kind() != reflect.Slice && t.Kind() != reflect.Array) {
		return nil
	}
	return t.Elem()
}

// decodesLosslessly reports whether raw, JSON text, is valid UTF-8 with
// no \u escape of an unpaired UTF-16 surrogate: the strings encoding/json
// would otherwise alter, replacing each with U+FFFD (RFC 8259 §8.1,
// §8.2). A backslash only appears inside a JSON string, so raw is
// scanned for escapes without parsing it.
func decodesLosslessly(raw []byte) bool {
	if !utf8.Valid(raw) {
		return false
	}
	for i := 0; i < len(raw); i++ {
		if raw[i] != '\\' {
			continue
		}
		i++ // the escaped character
		if i >= len(raw) || raw[i] != 'u' {
			continue
		}
		n, ok := unicodeEscapeLength(raw, i-1)
		if !ok {
			return false
		}
		i += n - 2 // past the escape (or surrogate pair); the loop adds one
	}
	return true
}

// unicodeEscapeLength returns the length of the \u escape starting at
// raw[i] (its backslash), or of the surrogate pair it starts, and
// whether it decodes as written: a high surrogate must be followed
// directly by an escaped low one, and a low one can't stand alone.
func unicodeEscapeLength(raw []byte, i int) (int, bool) {
	r, ok := hexRune(raw, i+2)
	switch {
	case !ok:
		return 0, false
	case !utf16.IsSurrogate(r):
		return 6, true
	case r >= 0xdc00:
		return 0, false // a low surrogate on its own
	}
	low, ok := hexRune(raw, i+8)
	if !ok || raw[i+6] != '\\' || raw[i+7] != 'u' || low < 0xdc00 || low > 0xdfff {
		return 0, false
	}
	return 12, true
}

// hexRune reads the four hex digits of a \u escape starting at raw[i].
func hexRune(raw []byte, i int) (rune, bool) {
	if i < 0 || i+4 > len(raw) {
		return 0, false
	}
	n, err := strconv.ParseUint(string(raw[i:i+4]), 16, 16)
	if err != nil {
		return 0, false
	}
	return rune(n), true
}
