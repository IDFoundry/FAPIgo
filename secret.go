package fapi

import (
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"unique"
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
// The value never sits in a string field: a Secret holds the canonical
// handle unique.Make returns for it. Where fmt calls no method of a
// value — %p, %w on a value that isn't an error, or a Secret (or a
// struct holding one) in an unexported field, which is also how
// log/slog's text handler prints a struct — it prints only that
// handle's address, never the value. Two Secrets holding the same value
// share one handle, so ==, map keys and reflect.DeepEqual compare
// Secrets by value, and equal Secrets print the same address. A
// security decision that compares a secret compares its revealed value
// in constant time instead.
//
// The handles are shared process-wide, and NewSecret of a value some
// live Secret already holds takes a fraction of the time a new value
// does, so whoever can both choose a value NewSecret wraps and time it
// can learn whether the process holds that value. Wrap only values too
// long and random to guess, as this module's codes, tokens and handles
// are, never a short or predictable one, such as a one-time code, that
// someone could also submit.
//
// json.Marshal, xml.Marshal and gob fail on a Secret and on a struct
// holding one in an exported field (MarshalText). A reflecting tool
// that copies a struct's private fields, or go-cmp's AllowUnexported,
// can't rebuild the handle; compare Secrets with == or
// cmpopts.EquateComparable instead. A method Secret gains later that a
// generic encoder calls, such as AppendText, must fail as MarshalText
// does.
type Secret struct {
	h unique.Handle[string]
}

// NewSecret wraps value as a Secret. NewSecret("") is the zero Secret.
func NewSecret(value string) Secret {
	if value == "" {
		return Secret{}
	}
	return Secret{h: unique.Make(value)}
}

// Reveal returns the wrapped value: "" for the zero Secret.
func (s Secret) Reveal() string {
	if s.h == (unique.Handle[string]{}) {
		// The zero handle points nowhere: Value would dereference nil.
		return ""
	}
	return s.h.Value()
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
