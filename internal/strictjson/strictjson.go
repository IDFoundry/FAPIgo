// Package strictjson closes the one way encoding/json decodes JOSE
// content differently from the specifications: it matches an object
// member to a struct field case-insensitively, so {"ALG": ...} fills a
// field tagged "alg", and when both "alg" and "ALG" appear the later one
// silently wins. JOSE and JWT member names are case-sensitive (RFC 7515
// §4, RFC 7519 §4), so a member that only case-folds to a field name is
// not that member — accepting it creates a parser differential with any
// strictly conforming implementation reading the same token.
//
// Unmarshal rejects such members, at every depth of the target type,
// before delegating to encoding/json. Exact names, and members matching
// no field at all, are left to encoding/json's own rules (and a
// Decoder's DisallowUnknownFields, where a caller uses one).
package strictjson

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"unicode"
)

// Unmarshal is json.Unmarshal, after CheckFieldCase.
func Unmarshal(data []byte, v any) error {
	if err := CheckFieldCase(data, v); err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

// CheckFieldCase reports an error if data contains, at any depth, an
// object member whose name matches a field of v's type (its json tag, or
// its Go name when untagged) only case-insensitively. It does not
// otherwise validate data; malformed JSON is left for the decode that
// follows to reject.
func CheckFieldCase(data []byte, v any) error {
	t := reflect.TypeOf(v)
	if t == nil {
		return nil
	}
	return check(data, t, false)
}

// CheckTaggedFieldCase is CheckFieldCase for fields with an explicit
// json tag only: a field without one has no spelling of its own on the
// wire, so encoding/json's case-insensitive match to its Go name is
// left alone. It is for types an application defines, which needn't tag
// every field.
func CheckTaggedFieldCase(data []byte, v any) error {
	t := reflect.TypeOf(v)
	if t == nil {
		return nil
	}
	return check(data, t, true)
}

// FoldKey maps name to one spelling shared by every name it equals under
// Unicode simple case folding (strings.EqualFold), as encoding/json
// compares member names: each rune becomes the least of its fold orbit,
// so "K", "k" and the Kelvin sign all map to "K", and "s" and "ſ" to
// "S".
func FoldKey(name string) string {
	var b strings.Builder
	for _, r := range name {
		least := r
		for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
			least = min(least, f)
		}
		b.WriteRune(least)
	}
	return b.String()
}

func check(raw []byte, t reflect.Type, taggedOnly bool) error {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	switch t.Kind() {
	case reflect.Struct:
		return checkStruct(raw, t, taggedOnly)
	case reflect.Slice, reflect.Array:
		if t.Elem().Kind() == reflect.Uint8 { // []byte decodes from a base64 string
			return nil
		}
		var elems []json.RawMessage
		if json.Unmarshal(raw, &elems) != nil {
			return nil
		}
		for _, e := range elems {
			if err := check(e, t.Elem(), taggedOnly); err != nil {
				return err
			}
		}
	case reflect.Map:
		var members map[string]json.RawMessage
		if json.Unmarshal(raw, &members) != nil {
			return nil
		}
		for _, m := range members {
			if err := check(m, t.Elem(), taggedOnly); err != nil {
				return err
			}
		}
	}
	return nil
}

func checkStruct(raw []byte, t reflect.Type, taggedOnly bool) error {
	if t == reflect.TypeOf(json.RawMessage{}) {
		return nil
	}
	if reflect.PointerTo(t).Implements(reflect.TypeOf((*json.Unmarshaler)(nil)).Elem()) {
		return nil // the type decodes itself
	}
	var members map[string]json.RawMessage
	if !bytes.HasPrefix(bytes.TrimSpace(raw), []byte("{")) || json.Unmarshal(raw, &members) != nil {
		return nil
	}
	fields := fieldTypes(t)
	byFold := make(map[string]string, len(fields))
	for name := range fields {
		byFold[FoldKey(name)] = name
	}
	for name, value := range members {
		if f, ok := fields[name]; ok {
			if err := check(value, f.typ, taggedOnly); err != nil {
				return err
			}
			continue
		}
		exact, ok := byFold[FoldKey(name)]
		if !ok {
			continue
		}
		if taggedOnly && !fields[exact].tagged {
			// encoding/json decodes it into the untagged field: check
			// what's inside.
			if err := check(value, fields[exact].typ, taggedOnly); err != nil {
				return err
			}
			continue
		}
		return fmt.Errorf("strictjson: member %q is not %q: JSON member names are case-sensitive", name, exact)
	}
	return nil
}

// field is a struct field as JSON sees it.
type field struct {
	typ    reflect.Type
	tagged bool // named by a json tag, not by its Go name
}

// fieldTypes maps each JSON member name t decodes (following
// encoding/json's naming, including promoted fields of embedded
// structs) to its field.
func fieldTypes(t reflect.Type) map[string]field {
	out := map[string]field{}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		tag := f.Tag.Get("json")
		if tag == "-" {
			continue
		}
		name, _, _ := strings.Cut(tag, ",")
		if embedded, ok := untaggedEmbeddedStruct(f, name); ok {
			addMissing(out, fieldTypes(embedded))
			continue
		}
		if !f.IsExported() {
			continue
		}
		tagged := name != ""
		if !tagged {
			name = f.Name
		}
		out[name] = field{typ: f.Type, tagged: tagged}
	}
	return out
}

// untaggedEmbeddedStruct returns the struct type f embeds, through any
// pointers, when f is an embedded field with no JSON name: encoding/json
// promotes such a struct's fields into the outer one.
func untaggedEmbeddedStruct(f reflect.StructField, name string) (reflect.Type, bool) {
	if !f.Anonymous || name != "" {
		return nil, false
	}
	ft := f.Type
	for ft.Kind() == reflect.Pointer {
		ft = ft.Elem()
	}
	return ft, ft.Kind() == reflect.Struct
}

// addMissing adds to out each of from's members out doesn't already have.
func addMissing(out, from map[string]field) {
	for k, v := range from {
		if _, exists := out[k]; !exists {
			out[k] = v
		}
	}
}
