package extension

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
)

// Definition captures the complete wire contract for one custom
// authorization parameter, defined exactly once and shared between
// client and server — see ARCHITECTURE.md design rules 10-11.
type Definition[T any] struct {
	// Name is the wire parameter name.
	Name string

	// Cardinality is whether the wire value is a single value or a JSON
	// array — checked against T's actual Go kind when the Definition is
	// registered (see Registered), so a mismatched declaration is caught
	// at startup rather than silently ignored.
	Cardinality Cardinality

	// AllowedSources is where this parameter may legitimately appear on
	// an authorization request. A value arriving anywhere else is
	// rejected with ErrSourceNotAllowed.
	AllowedSources Source

	// MaxBytes bounds the size of the parameter's encoded JSON value.
	// Required — there is no implicit default; zero rejects every value.
	MaxBytes int

	// Sensitive marks a value that must never be copied into a log line
	// or error message — a caller reading it back via Get is expected to
	// apply the same care it would to a fapi.Secret.
	Sensitive bool

	// ReturnInTokenClaims, if true, means a validated value should be
	// copied into the token claims an authorization server issues
	// (AccessTokenParams.Parameters / IDTokenParams.Parameters) — a
	// caller's decision, not something this package does on its own.
	ReturnInTokenClaims bool

	// Validate, if non-nil, applies extra semantic checks beyond T's JSON
	// shape (e.g. a string pattern, a numeric range, a business rule). A
	// Definition with no Validate accepts any value that unmarshals into
	// T without unknown fields.
	Validate func(T) error
}

// Registered is a type-erased handle to a Definition[T], for holding a
// heterogeneous collection of registered definitions in a Registry.
// Every concrete Definition[T] implements it; nothing else can, since
// its methods are unexported to this package — the same closed-set
// pattern used for every other sum type in this module.
type Registered interface {
	name() string
	cardinalityOK() bool
	returnInTokenClaims() bool
	validate(raw json.RawMessage, source Source, out *Values) error
}

func (d Definition[T]) name() string { return d.Name }

func (d Definition[T]) returnInTokenClaims() bool { return d.ReturnInTokenClaims }

func (d Definition[T]) cardinalityOK() bool {
	isSlice := reflect.TypeFor[T]().Kind() == reflect.Slice
	switch d.Cardinality {
	case Single:
		return !isSlice
	case Multiple:
		return isSlice
	default:
		return false
	}
}

func (d Definition[T]) validate(raw json.RawMessage, source Source, out *Values) error {
	if !d.AllowedSources.Allows(source) {
		return fmt.Errorf("%w: %q", ErrSourceNotAllowed, d.Name)
	}
	if d.MaxBytes <= 0 || len(raw) > d.MaxBytes {
		return fmt.Errorf("%w: %q", ErrValueTooLarge, d.Name)
	}

	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var v T
	if err := dec.Decode(&v); err != nil {
		return fmt.Errorf("extension: %q: malformed value: %w", d.Name, err)
	}
	if d.Validate != nil {
		if err := d.Validate(v); err != nil {
			return fmt.Errorf("extension: %q: %w", d.Name, err)
		}
	}

	if out.raw == nil {
		out.raw = make(map[string]json.RawMessage)
	}
	out.raw[d.Name] = raw
	return nil
}

// Values holds validated extension values, keyed internally by wire
// name. It has no public fields and no generic accessor of its own —
// Set and Get are the only way to write or read a value, and both take
// the same Definition a value was validated against, so a caller can
// never mismatch a stored value's type against its wire name the way a
// map[string]any would allow.
type Values struct {
	raw map[string]json.RawMessage
}

// Set encodes v under def's wire name into values. It fails if v does
// not satisfy def.Validate (when set), or if the encoded size exceeds
// def.MaxBytes.
func Set[T any](values *Values, def Definition[T], v T) error {
	if def.Validate != nil {
		if err := def.Validate(v); err != nil {
			return fmt.Errorf("extension: %q: %w", def.Name, err)
		}
	}
	encoded, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("extension: %q: marshal: %w", def.Name, err)
	}
	if def.MaxBytes <= 0 || len(encoded) > def.MaxBytes {
		return fmt.Errorf("%w: %q", ErrValueTooLarge, def.Name)
	}
	if values.raw == nil {
		values.raw = make(map[string]json.RawMessage)
	}
	values.raw[def.Name] = encoded
	return nil
}

// Get decodes the value stored under def's wire name, if any. It returns
// false if no value was set, and false (not an error) if the stored raw
// value cannot be decoded into T — that should not happen for a Values
// produced by this package's own Set or Registry.Parse, since both
// validate against T themselves before storing, but Get stays defensive
// rather than panicking on an externally-assembled Values.
func Get[T any](values Values, def Definition[T]) (T, bool) {
	var zero T
	raw, ok := values.raw[def.Name]
	if !ok {
		return zero, false
	}
	var v T
	if err := json.Unmarshal(raw, &v); err != nil {
		return zero, false
	}
	return v, true
}

// Snapshot returns a copy of every value in values, still raw JSON,
// keyed by wire name — for a caller (e.g. client, embedding an outgoing
// request object) that needs to enumerate an arbitrary, caller-populated
// Values without knowing each entry's Definition ahead of time. It is
// the one place this package hands back an untyped map, and only ever
// raw JSON bytes Set has already validated — never a live reference to
// Values' internal storage.
func Snapshot(values Values) map[string]json.RawMessage {
	out := make(map[string]json.RawMessage, len(values.raw))
	for k, v := range values.raw {
		out[k] = v
	}
	return out
}

// AsParameters returns values re-encoded as a map[string]json.RawMessage
// keyed by wire name — the shape AccessTokenParams.Parameters and
// IDTokenParams.Parameters (internal/token) expect — restricted to the
// given Definitions whose ReturnInTokenClaims is true. A caller passes
// the same Definitions it registered so this package never has to guess
// which values are claim-eligible from the raw map alone.
func AsParameters(values Values, defs ...Registered) map[string]json.RawMessage {
	out := make(map[string]json.RawMessage, len(defs))
	for _, d := range defs {
		if !d.returnInTokenClaims() {
			continue
		}
		if raw, ok := values.raw[d.name()]; ok {
			out[d.name()] = raw
		}
	}
	return out
}
