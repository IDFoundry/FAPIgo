// Package depcheck holds the checks server.New, client.New and
// resource.NewVerifier apply alike to their Dependencies: that no
// interface-typed field holds a typed nil, and, under production
// assurance, that the Clock reads the system's time.
package depcheck

import (
	"reflect"
	"strings"
	"time"
	"unicode"
)

// TypedNil is a Dependencies field holding a non-nil interface value
// whose dynamic value is nil — a nil pointer, map, slice, func or
// channel — which a nil check (field == nil) doesn't catch, and which
// fails only once a method is called on it.
type TypedNil struct {
	// Name is the field's name in snake_case, or as overrides names
	// it.
	Name string

	// Type is the value's dynamic type: unqualified when it's declared
	// in the same package as deps' own type, as that package's own
	// error messages name its types, and package-qualified otherwise.
	Type string
}

// FindTypedNil returns the first interface-typed field of deps, a
// struct, holding a typed nil, in declaration order. overrides maps a
// field's Go name to the name to report in place of its snake_case.
func FindTypedNil(deps any, overrides map[string]string) (TypedNil, bool) {
	v := reflect.ValueOf(deps)
	t := v.Type()
	for i := range t.NumField() {
		field := t.Field(i)
		if field.Type.Kind() != reflect.Interface || !field.IsExported() {
			continue
		}
		value := v.Field(i)
		if value.IsNil() || !isNilValue(value.Elem()) {
			continue
		}
		name, ok := overrides[field.Name]
		if !ok {
			name = snakeCase(field.Name)
		}
		return TypedNil{Name: name, Type: typeName(value.Elem().Type(), t.PkgPath())}, true
	}
	return TypedNil{}, false
}

// isNilValue reports whether v is of a kind that can be nil, and is.
func isNilValue(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.Pointer, reflect.Map, reflect.Slice, reflect.Func, reflect.Chan, reflect.Interface:
		return v.IsNil()
	}
	return false
}

// typeName names t, unqualified when it's declared in local.
func typeName(t reflect.Type, local string) string {
	if t.Kind() == reflect.Pointer {
		return "*" + typeName(t.Elem(), local)
	}
	if t.Name() != "" && t.PkgPath() == local {
		return t.Name()
	}
	return t.String()
}

// snakeCase converts a Go identifier to snake_case, keeping an acronym
// together: ClientCertificateTrust is client_certificate_trust and
// HTTP is http. Callers pass an override for the few names that split
// badly (CIBARARPolicy, DPoPNonceCache).
func snakeCase(name string) string {
	runes := []rune(name)
	var b strings.Builder
	for i, r := range runes {
		if i > 0 && unicode.IsUpper(r) {
			prevLower := unicode.IsLower(runes[i-1])
			nextLower := i+1 < len(runes) && unicode.IsLower(runes[i+1])
			if prevLower || (unicode.IsUpper(runes[i-1]) && nextLower) {
				b.WriteByte('_')
			}
		}
		b.WriteRune(unicode.ToLower(r))
	}
	return b.String()
}

// ReadsSystemTime reports whether clock declares, through a
// ReadsSystemTime method returning true, that it reads the system's
// current time. server.ClockAssurance, client.ClockAssurance and
// resource.ClockAssurance are each that one method, so one clock type
// declaring it satisfies all three.
func ReadsSystemTime(clock any) bool {
	declared, ok := clock.(interface{ ReadsSystemTime() bool })
	return ok && declared.ReadsSystemTime()
}

// ClockOffset returns how far now, a Clock's reading, is from the
// system's time, as a non-negative duration.
func ClockOffset(now time.Time) time.Duration {
	offset := time.Since(now)
	if offset < 0 {
		return -offset
	}
	return offset
}
