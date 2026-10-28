package federation

import (
	"encoding/json"
	"strings"
)

// spaceDelimitedParameters names the metadata parameters whose value is
// a string of space-separated values, which OpenID Federation 1.0
// §6.1.3.1.8 says "is to be regarded and processed as a string array by
// policy operators", the resulting parameter being "a space-separated
// string of individual scope values". scope (RFC 7591 §2) is the only
// one the spec names.
var spaceDelimitedParameters = map[string]bool{"scope": true}

// splitSpaceDelimitedOperators returns ops with each operand that holds
// a space-delimited parameter's value as a string turned into the
// string array §6.1.3.1.8 says operators work on: the value and default
// operands, and each one_of option. The array operands (add, subset_of,
// superset_of) already list individual values and are left alone. ops
// itself is not modified.
func splitSpaceDelimitedOperators(ops PolicyOperators) PolicyOperators {
	if len(ops) == 0 {
		return ops
	}
	out := make(PolicyOperators, len(ops))
	for name, operand := range ops {
		switch name {
		case opValue, opDefault:
			out[name] = splitSpaceDelimited(operand)
		case opOneOf:
			out[name] = splitOneOfOptions(operand)
		default:
			out[name] = operand
		}
	}
	return out
}

// splitOneOfOptions splits each string option of a one_of operand, so a
// value split by splitSpaceDelimited compares with it as arrays. An
// operand that isn't an array is returned unchanged, for
// validateOperandTypes to refuse.
func splitOneOfOptions(operand json.RawMessage) json.RawMessage {
	var options []json.RawMessage
	if json.Unmarshal(operand, &options) != nil {
		return operand
	}
	for i, option := range options {
		options[i] = splitSpaceDelimited(option)
	}
	encoded, err := json.Marshal(options)
	if err != nil {
		return operand
	}
	return encoded
}

// splitSpaceDelimited turns a JSON string into the JSON array of its
// space-separated values. Anything else (an array, null) is returned
// unchanged.
func splitSpaceDelimited(raw json.RawMessage) json.RawMessage {
	var v any
	if json.Unmarshal(raw, &v) != nil {
		return raw
	}
	s, ok := v.(string)
	if !ok {
		return raw
	}
	encoded, err := json.Marshal(strings.Fields(s))
	if err != nil {
		return raw
	}
	return encoded
}

// joinSpaceDelimited turns the string array a policy produced for a
// space-delimited parameter back into its space-separated string form.
// An array with a value that isn't a string, or that contains a space,
// can't be represented and is a policy error; a value that isn't an
// array is returned unchanged.
func joinSpaceDelimited(raw json.RawMessage) (json.RawMessage, error) {
	var values []json.RawMessage
	if json.Unmarshal(raw, &values) != nil {
		return raw, nil
	}
	parts := make([]string, 0, len(values))
	for _, v := range values {
		var s string
		if err := json.Unmarshal(v, &s); err != nil {
			return nil, policyError("space-delimited parameter values must be strings: %v", err)
		}
		if s == "" || strings.ContainsAny(s, " \t\n\r") {
			return nil, policyError("space-delimited parameter value %q is empty or contains whitespace", s)
		}
		parts = append(parts, s)
	}
	return json.Marshal(strings.Join(parts, " "))
}

// parameterOperators returns the operators to apply to, validate or
// merge for claim: ops itself, or ops with its operands split for a
// space-delimited parameter.
func parameterOperators(claim string, ops PolicyOperators) PolicyOperators {
	if spaceDelimitedParameters[claim] {
		return splitSpaceDelimitedOperators(ops)
	}
	return ops
}

// applyParameterPolicy applies ops to claim's current value. For a
// space-delimited parameter with a policy, the value is split into an
// array first and the result joined back afterwards (§6.1.3.1.8).
func applyParameterPolicy(claim string, ops PolicyOperators, crit critSet, value json.RawMessage, present bool) (json.RawMessage, bool, error) {
	if !spaceDelimitedParameters[claim] || len(ops) == 0 {
		return applyClaimPolicy(ops, crit, value, present)
	}
	if present {
		value = splitSpaceDelimited(value)
	}
	value, present, err := applyClaimPolicy(splitSpaceDelimitedOperators(ops), crit, value, present)
	if err != nil || !present {
		return value, present, err
	}
	value, err = joinSpaceDelimited(value)
	if err != nil {
		return nil, false, err
	}
	return value, true, nil
}
