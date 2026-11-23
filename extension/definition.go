package extension

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"

	"github.com/idfoundry/fapigo/internal/strictjson"
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

	// Sensitivity is whether the value may be copied into a log line or
	// error message: Sensitive, for one a caller reading it back via Get
	// must treat as it would a fapi.Secret, or NotSensitive. Required —
	// NewRegistry refuses the zero value, so a secret parameter can't be
	// logged because its Definition forgot to say so. An error refusing
	// a Sensitive value names the parameter and T, and never quotes the
	// value (see Sensitive); Values prints no value of any sensitivity.
	Sensitivity Sensitivity

	// ReturnInTokenClaims, if true, means a validated value should be
	// copied into the token claims an authorization server issues
	// (AccessTokenParams.Parameters / IDTokenParams.Parameters) — a
	// caller's decision, not something this package does on its own.
	//
	// The value is the client's choice, so NewRegistry refuses
	// ReturnInTokenClaims under a name whose meaning a token's recipient
	// takes from the authorization server, the resource owner or the
	// token's own structure (ErrReservedTokenClaim): the claims an
	// authorization server sets itself (iss, sub, aud, exp, iat, nbf,
	// jti, client_id, scope, cnf, nonce, auth_time, acr, amr, azp and
	// the hashes); the RFC 9068 §2.2.3.1 authorization attributes roles,
	// groups and entitlements; the RFC 8693 delegation claims act and
	// may_act; authorization_details; the OIDC Core §5.1 standard
	// claims; _claim_names, _claim_sources, sub_jwk and events, which
	// change how a recipient processes a token; and code, state and
	// error, which would make an ID token look like a JARM response. An
	// authorization server that grants roles or delegation sets them
	// itself — server.GrantedAuthorization.IDTokenClaims for an ID
	// token, or its own server.AccessTokenIssuer for an access token —
	// never from a client's parameter.
	ReturnInTokenClaims bool

	// Validate, if non-nil, applies extra semantic checks beyond T's JSON
	// shape (e.g. a string pattern, a numeric range, a business rule). A
	// Definition with no Validate accepts any value that unmarshals into
	// T without unknown fields. Keep the value out of the error it
	// returns: a NotSensitive Definition's refusal carries that error's
	// text into server.Error's, which is meant for logs. A Sensitive
	// one's withholds it, and errors.Is still matches a sentinel it wraps.
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
	sensitivityOK() bool
	returnInTokenClaims() bool
	validate(raw json.RawMessage, source Source, out *Values) error
}

func (d Definition[T]) name() string { return d.Name }

func (d Definition[T]) returnInTokenClaims() bool { return d.ReturnInTokenClaims }

func (d Definition[T]) sensitivityOK() bool {
	return d.Sensitivity == NotSensitive || d.Sensitivity == Sensitive
}

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

	// encoding/json matches members to fields case-insensitively and
	// keeps the last of any repeat, while raw itself is what's stored and
	// may be copied into a token (ReturnInTokenClaims): of
	// {"amount":10,"AMOUNT":1000000} Validate would see 10 and a
	// case-sensitive reader of the token 1000000. Refuse both shapes, as
	// RARDefinition does.
	if err := checkDuplicateMembers(raw); err != nil {
		return d.refuse(valueMalformed, malformedStage, err)
	}
	var v T
	if err := strictjson.CheckTaggedFieldCase(raw, &v); err != nil {
		return d.refuse(valueMalformed, malformedStage, err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&v); err != nil {
		return d.refuse(valueMalformed, malformedStage, err)
	}
	if d.Validate != nil {
		if err := d.Validate(v); err != nil {
			return d.refuse(valueRejected, "", err)
		}
	}

	out.put(d.Name, raw)
	return nil
}

// refuse is the error validate and Set return when d refuses a value:
// kind is how, and stage the text a NotSensitive refusal carries before
// its cause, as it always has.
func (d Definition[T]) refuse(kind valueErrorKind, stage string, cause error) error {
	if d.Sensitivity == Sensitive {
		held := cause
		cause = &withheldCause{&held}
	}
	return &valueError{
		name: d.Name, kind: kind, stage: stage, typeName: reflect.TypeFor[T]().String(),
		cause: cause, sensitive: d.Sensitivity == Sensitive,
	}
}

// withheldCause holds a Sensitive Definition's refusal cause out of
// reach of fmt's reflection fallback (%#v, %w outside Errorf, a verb an
// error doesn't take), which prints a refusal's fields, and with them a
// cause held by value, such as netip's parse error, which quotes the
// value. Behind a pointer to an interface the cause prints as an
// address: fmt follows only a pointer to a struct, map, slice or array,
// and that only at the top. errors.Is still reaches the cause, through
// Unwrap.
type withheldCause struct{ err *error }

// Error withholds the cause's text, as the refusal's own does.
func (*withheldCause) Error() string { return withheldDetail }

// Unwrap returns the cause, for errors.Is through valueError.Is.
func (c *withheldCause) Unwrap() error { return *c.err }

// malformedStage is the text a NotSensitive refusal of a malformed value
// carries before its cause.
const malformedStage = "malformed value: "

// valueErrorKind is how a Definition refused a value.
type valueErrorKind uint8

const (
	// valueMalformed: the value isn't a valid T (its JSON, a member
	// repeated in it, or, at Set, T's own encoding).
	valueMalformed valueErrorKind = iota + 1

	// valueRejected: the Definition's Validate refused it.
	valueRejected
)

// valueError is a Definition's refusal of a value, from Registry.Parse
// or Set. Its text names the parameter. For a NotSensitive Definition it
// then carries its cause's text, and Unwrap the cause, exactly as
// before; for a Sensitive one it gives only how the value failed and
// T's name, and Unwrap returns nil, since the cause can quote the value:
// encoding/json's does for a number out of range or with a fraction, and
// time.Time, netip.Addr and big.Int quote what they couldn't parse, as
// the duplicate-member check names a map-typed value's members. errors.Is
// still finds a sentinel the cause wraps, through Is, without handing the
// cause out.
type valueError struct {
	name      string
	kind      valueErrorKind
	stage     string
	typeName  string
	cause     error
	sensitive bool
}

// withheldDetail ends a Sensitive Definition's refusal, in place of its
// cause.
const withheldDetail = "detail withheld: the definition is Sensitive"

func (e *valueError) Error() string {
	switch {
	case !e.sensitive:
		return fmt.Sprintf("extension: %q: %s%v", e.name, e.stage, e.cause)
	case e.kind == valueRejected:
		return fmt.Sprintf("extension: %q: value rejected by its Validate (%s)", e.name, withheldDetail)
	default:
		return fmt.Sprintf("extension: %q: malformed value: not a valid %s (%s)", e.name, e.typeName, withheldDetail)
	}
}

// Unwrap returns a NotSensitive Definition's cause, and nil for a
// Sensitive one's, so neither a printer that walks the chain nor
// errors.As can reach text quoting the value.
func (e *valueError) Unwrap() error {
	if e.sensitive {
		return nil
	}
	return e.cause
}

// Is reports whether a Sensitive Definition's cause matches target, so
// errors.Is finds ErrDuplicateMember, or a sentinel of Validate's own,
// as it does through a NotSensitive one's Unwrap.
func (e *valueError) Is(target error) bool {
	return e.sensitive && errors.Is(e.cause, target)
}

// Values holds validated extension values, keyed internally by wire
// name. It has no public fields and no generic accessor of its own —
// Set and Get are the only way to write or read a value, and both take
// the same Definition a value was validated against, so a caller can
// never mismatch a stored value's type against its wire name the way a
// map[string]any would allow.
//
// Values prints its parameter names and no value, whatever each one's
// Sensitivity (Format, String, GoString, LogValue): a Values restored by
// UnmarshalJSON knows no Definitions, so naming its parameters is all it
// can print without risking a Sensitive value. Log a NotSensitive value
// by reading it with Get. MarshalJSON, Snapshot and AsParameters carry
// every value, Sensitive ones included: they are for storing and issuing
// values, never for a log.
type Values struct {
	// The zero-size array of funcs keeps Values non-comparable, as the
	// map it holds made it.
	_ [0]func()

	// p points at a pointer to the values, so that fmt's reflection
	// fallback (a Values in an unexported field, or under %p, %w or a
	// verb fmt rejects) prints an address, never a value. One pointer
	// isn't enough: under a verb fmt rejects for a pointer it reaches by
	// reflection (s, q, f, t and most others), it prints that pointer
	// again as if it were the operand itself, showing what a pointer to
	// a struct or a map points to, but not what a pointer to a pointer
	// does.
	p **valuesData
}

// valuesData is what a non-zero Values holds. Copies of a Values share
// it, as they shared the map it holds.
type valuesData struct {
	raw map[string]json.RawMessage
}

// rawValues is values' map, nil for the zero Values.
func (values Values) rawValues() map[string]json.RawMessage {
	if values.p == nil {
		return nil
	}
	return (*values.p).raw
}

// put stores raw under name, giving a zero values storage of its own
// first.
func (values *Values) put(name string, raw json.RawMessage) {
	if values.p == nil {
		data := &valuesData{raw: make(map[string]json.RawMessage)}
		values.p = &data
	}
	(*values.p).raw[name] = raw
}

// Set encodes v under def's wire name into values. It fails if v does
// not satisfy def.Validate (when set), or if the encoded size exceeds
// def.MaxBytes.
func Set[T any](values *Values, def Definition[T], v T) error {
	if def.Validate != nil {
		if err := def.Validate(v); err != nil {
			return def.refuse(valueRejected, "", err)
		}
	}
	encoded, err := json.Marshal(v)
	if err != nil {
		return def.refuse(valueMalformed, "marshal: ", err)
	}
	if def.MaxBytes <= 0 || len(encoded) > def.MaxBytes {
		return fmt.Errorf("%w: %q", ErrValueTooLarge, def.Name)
	}
	// A T with its own MarshalJSON could still emit a repeated member.
	if err := checkDuplicateMembers(encoded); err != nil {
		return def.refuse(valueMalformed, "", err)
	}
	values.put(def.Name, encoded)
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
	raw, ok := values.rawValues()[def.Name]
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
// Values' internal storage. It carries every value, Sensitive ones
// included: never log it.
func Snapshot(values Values) map[string]json.RawMessage {
	raw := values.rawValues()
	out := make(map[string]json.RawMessage, len(raw))
	for k, v := range raw {
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
		if raw, ok := values.rawValues()[d.name()]; ok {
			out[d.name()] = raw
		}
	}
	return out
}

// MarshalJSON encodes values as a JSON object of their wire names — for
// storing, with the rest of an interaction, until the end user decides
// (see server.InteractionRequest.MarshalText). The encoding carries
// every value, Sensitive ones included: store it as you would a
// credential, and never log it.
func (values Values) MarshalJSON() ([]byte, error) {
	if values.p == nil {
		return []byte("{}"), nil
	}
	return json.Marshal((*values.p).raw)
}

// UnmarshalJSON restores values MarshalJSON encoded. It doesn't validate
// them against a Registry: restored values are for reading with Get, as
// values Registry.Parse returned are.
func (values *Values) UnmarshalJSON(data []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("extension: values: %w", err)
	}
	if len(raw) == 0 {
		*values = Values{} // the zero value, as Values{} encodes
		return nil
	}
	restored := &valuesData{raw: raw}
	values.p = &restored
	return nil
}

// checkDuplicateMembers reports whether raw, a JSON value of any kind,
// repeats a member name in any object at any depth, counting names that
// differ only in case as repeats (see checkMembers).
func checkDuplicateMembers(raw json.RawMessage) error {
	return checkValueMembers(json.NewDecoder(bytes.NewReader(raw)))
}
