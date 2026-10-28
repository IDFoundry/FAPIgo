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
	"reflect"
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
// decoded, so "1" equals "1.0" and member order doesn't matter. Text
// that doesn't decode equals nothing.
func Equal(a, b json.RawMessage) bool {
	var av, bv any
	if json.Unmarshal(a, &av) != nil || json.Unmarshal(b, &bv) != nil {
		return false
	}
	return reflect.DeepEqual(av, bv)
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
