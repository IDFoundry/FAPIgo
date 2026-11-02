// Package claimvalues applies the "value" and "values" members of an
// OpenID Connect "claims" request (OIDC Core §5.5.1) to the identity
// claims an ID token or a UserInfo response would release.
//
// §5.5.1: "An equality comparison is used to determine whether the
// requested Claim value matches. When the Claim value does not match the
// requested value, the Claim is not included in the response." "values"
// "is processed equivalently to a 'value' request, except that a choice
// of acceptable Claim values is provided."
package claimvalues

import (
	"bytes"
	"encoding/json"
	"io"
	"maps"
	"math/big"
	"slices"
	"strings"
)

// Acceptable is, for a claim requested with "value", "values" or both,
// the values it may be released with. A claim with no entry is
// unconstrained; one with an empty entry is never released (its values
// matched nothing, or "values" wasn't an array of them).
type Acceptable map[string][]json.RawMessage

// FromRequest returns the constraint request — one claim's entry in a
// "claims" location, null or an object — places on that claim, and
// whether it places one. Members are read by their exact names. With
// both "value" and "values", the claim must equal "value" and be among
// "values".
func FromRequest(request json.RawMessage) ([]json.RawMessage, bool) {
	var members map[string]json.RawMessage
	if trimmed := bytes.TrimSpace(request); len(trimmed) == 0 || trimmed[0] != '{' || json.Unmarshal(trimmed, &members) != nil {
		return nil, false
	}
	value, hasValue := members["value"]
	valuesRaw, hasValues := members["values"]
	switch {
	case !hasValue && !hasValues:
		return nil, false
	case !hasValues:
		return []json.RawMessage{value}, true
	}
	var values []json.RawMessage
	if json.Unmarshal(valuesRaw, &values) != nil {
		return []json.RawMessage{}, true
	}
	acceptable := make([]json.RawMessage, 0, len(values))
	for _, v := range values {
		if !hasValue || Equal(v, value) {
			acceptable = append(acceptable, v)
		}
	}
	return acceptable, true
}

// Equal reports whether a and b are the same JSON value: equal once
// decoded, so "1" equals "1.0" and member order doesn't matter. Numbers
// compare exactly, by the value their text denotes, not as float64,
// which would make integers above 2^53 that differ equal. Text that
// doesn't decode equals nothing.
func Equal(a, b json.RawMessage) bool {
	av, aok := decode(a)
	bv, bok := decode(b)
	return aok && bok && equalValues(av, bv)
}

// decode decodes raw as one JSON value, keeping numbers as their text.
func decode(raw json.RawMessage) (any, bool) {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var v any
	if d.Decode(&v) != nil {
		return nil, false
	}
	// Like json.Unmarshal, refuse anything after the value.
	if _, err := d.Token(); err != io.EOF {
		return nil, false
	}
	return v, true
}

// equalValues compares two values decode returned.
func equalValues(a, b any) bool {
	switch a := a.(type) {
	case json.Number:
		b, ok := b.(json.Number)
		return ok && equalNumbers(a, b)
	case []any:
		b, ok := b.([]any)
		return ok && slices.EqualFunc(a, b, equalValues)
	case map[string]any:
		b, ok := b.(map[string]any)
		return ok && maps.EqualFunc(a, b, equalValues)
	default:
		// string, bool or nil.
		return a == b
	}
}

// equalNumbers reports whether two JSON number texts denote the same
// value, exactly: each is reduced to a sign, its significant digits and
// a decimal exponent, so "100", "1e2" and "100.0" are equal. The
// exponent is a big.Int, so neither overflow nor a huge exponent's
// expansion (as big.Rat or big.Float would compute) is possible.
func equalNumbers(a, b json.Number) bool {
	an, aok := canonicalNumber(string(a))
	bn, bok := canonicalNumber(string(b))
	return aok && bok && an.negative == bn.negative && an.digits == bn.digits && an.exponent.Cmp(bn.exponent) == 0
}

// number is a JSON number as ±digits × 10^exponent, with digits
// free of leading and trailing zeros; zero has no digits, no sign and
// exponent 0.
type number struct {
	negative bool
	digits   string
	exponent *big.Int
}

// canonicalNumber reduces text, a JSON number (RFC 8259 §6) as
// encoding/json validated it, to a number.
func canonicalNumber(text string) (number, bool) {
	negative := strings.HasPrefix(text, "-")
	text = strings.TrimPrefix(text, "-")
	mantissa, exp, hasExp := strings.Cut(strings.ToLower(text), "e")
	exponent := new(big.Int)
	if hasExp {
		if _, ok := exponent.SetString(strings.TrimPrefix(exp, "+"), 10); !ok {
			return number{}, false
		}
	}
	integer, fraction, _ := strings.Cut(mantissa, ".")
	digits := integer + fraction
	exponent.Sub(exponent, big.NewInt(int64(len(fraction))))
	trimmed := strings.TrimRight(digits, "0")
	exponent.Add(exponent, big.NewInt(int64(len(digits)-len(trimmed))))
	digits = strings.TrimLeft(trimmed, "0")
	if digits == "" {
		return number{exponent: new(big.Int)}, true
	}
	return number{negative: negative, digits: digits, exponent: exponent}, true
}

// Allows reports whether name may be released with value under a.
func (a Acceptable) Allows(name string, value json.RawMessage) bool {
	acceptable, constrained := a[name]
	if !constrained {
		return true
	}
	for _, v := range acceptable {
		if Equal(v, value) {
			return true
		}
	}
	return false
}
