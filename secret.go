package fapi

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"log/slog"
	"strings"
)

// ErrSecretSerialization is returned by Secret.MarshalText, so a Secret
// can never be silently serialized (into a log line, a JSON response, a
// debug dump) by generic tooling that doesn't know it's handling one.
var ErrSecretSerialization = errors.New("fapi: secret values cannot be marshaled")

// redactedSecret is what every rendering of a Secret prints in place of
// its value.
const redactedSecret = "[REDACTED]"

// Secret wraps a value — a token, code, or credential — that must never
// leak into a log line, error message or debug dump by accident. fmt
// prints [REDACTED] under every verb and flag (Format; %#v prints
// fapi.Secret([REDACTED])), log/slog logs [REDACTED] (LogValue), and
// String, GoString and MarshalText redact too; Reveal is the only way to
// get the raw value back out, so a caller has to opt in explicitly at
// the point it's actually needed (building a header, an HTTP body).
//
// The value never sits in a string field: a Secret holds a pointer to
// it. Where fmt calls no method of a value — %p, %w on a value that
// isn't an error, or a Secret (or a struct holding one) in an
// unexported field, which is also how log/slog's text handler prints a
// struct — it prints only that pointer's address, never the value.
//
// A Secret isn't comparable: ==, a map key, a switch on one or a
// comparable type argument doesn't compile, nor does == on a struct
// holding one, because comparing the pointers would silently stop
// matching equal values. Compare with Equal, which takes constant time,
// and test for the zero Secret with IsZero. Comparing Secrets through an
// interface (any(a) == any(b), a map[any] or sync.Map key) compiles and
// panics. reflect.DeepEqual compares Secrets by value, and go-cmp uses
// Equal.
//
// json.Marshal, xml.Marshal and gob fail on a Secret and on a struct
// holding one in an exported field (MarshalText). A method Secret gains
// later that a generic encoder calls, such as AppendText, must fail as
// MarshalText does.
type Secret struct {
	_ [0]func() // not comparable: compare with Equal
	v *string   // nil for the zero Secret, which NewSecret("") returns
}

// NewSecret wraps value as a Secret. NewSecret("") is the zero Secret.
func NewSecret(value string) Secret {
	if value == "" {
		return Secret{}
	}
	return Secret{v: &value}
}

// Reveal returns the wrapped value: "" for the zero Secret.
func (s Secret) Reveal() string {
	if s.v == nil {
		return ""
	}
	return *s.v
}

// IsZero reports whether s is the zero Secret, which NewSecret("")
// returns too.
func (s Secret) IsZero() bool {
	return s.v == nil
}

// Equal reports whether s and t wrap the same value, in time that
// depends only on the values' lengths. Two zero Secrets are equal.
func (s Secret) Equal(t Secret) bool {
	return subtle.ConstantTimeCompare([]byte(s.Reveal()), []byte(t.Reveal())) == 1
}

// String returns a fixed redacted placeholder, never the wrapped value.
func (s Secret) String() string {
	return redactedSecret
}

// GoString implements fmt.GoStringer so %#v also redacts.
func (s Secret) GoString() string {
	return "fapi.Secret([REDACTED])"
}

// Format implements fmt.Formatter, so no verb prints the wrapped value:
// v, s, q, x and X print [REDACTED] with the flags, width and precision
// given, exactly as they would print String's result; %#v prints
// GoString's; any other verb prints fmt's own wrong-verb shape,
// %!d(fapi.Secret=[REDACTED]).
func (s Secret) Format(f fmt.State, verb rune) {
	switch {
	case verb == 'v' && f.Flag('#'):
		_, _ = fmt.Fprintf(f, fmt.FormatString(f, 's'), s.GoString())
	case strings.ContainsRune("vsqxX", verb):
		_, _ = fmt.Fprintf(f, fmt.FormatString(f, verb), redactedSecret)
	default:
		_, _ = fmt.Fprintf(f, "%%!%c(fapi.Secret=%s)", verb, redactedSecret)
	}
}

// LogValue implements slog.LogValuer, so log/slog logs [REDACTED].
func (s Secret) LogValue() slog.Value {
	return slog.StringValue(redactedSecret)
}

// MarshalText always fails, so a Secret embedded in a struct can't be
// silently serialized by encoding/json or encoding/xml.
func (s Secret) MarshalText() ([]byte, error) {
	return nil, ErrSecretSerialization
}
