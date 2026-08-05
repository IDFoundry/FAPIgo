package fapi

import "errors"

// ErrSecretSerialization is returned by Secret.MarshalText, so a Secret
// can never be silently serialized (into a log line, a JSON response, a
// debug dump) by generic tooling that doesn't know it's handling one.
var ErrSecretSerialization = errors.New("fapi: secret values cannot be marshaled")

// Secret wraps a value — a token, code, or credential — that must never
// leak into a log line, error message or debug dump by accident.
// String, GoString and MarshalText all redact; Reveal is the only way to
// get the raw value back out, so a caller has to opt in explicitly at
// the point it's actually needed (building a header, an HTTP body).
type Secret struct {
	value string
}

// NewSecret wraps value as a Secret.
func NewSecret(value string) Secret {
	return Secret{value: value}
}

// Reveal returns the wrapped value.
func (s Secret) Reveal() string {
	return s.value
}

// String returns a fixed redacted placeholder, never the wrapped value.
func (s Secret) String() string {
	return "[REDACTED]"
}

// GoString implements fmt.GoStringer so %#v also redacts.
func (s Secret) GoString() string {
	return "fapi.Secret([REDACTED])"
}

// MarshalText always fails, so a Secret embedded in a struct can't be
// silently serialized by encoding/json or encoding/xml.
func (s Secret) MarshalText() ([]byte, error) {
	return nil, ErrSecretSerialization
}
