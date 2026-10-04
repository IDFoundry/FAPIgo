package federation

import (
	"encoding/json"
	"fmt"
)

// Standard metadata policy operator names (OpenID Federation 1.0
// §6.1.3.1). Order matters: operatorApplicationOrder below is the
// "MUST declare in what order it is to be applied" sequence the spec
// fixes for these seven — value first, essential last.
const (
	opValue      = "value"
	opAdd        = "add"
	opDefault    = "default"
	opOneOf      = "one_of"
	opSubsetOf   = "subset_of"
	opSupersetOf = "superset_of"
	opEssential  = "essential"
)

// operatorApplicationOrder is OpenID Federation 1.0 §6.1.3.1's fixed
// application order for the standard operators. A non-standard
// operator (§6.1.3.2) is applied after value but before essential —
// this package does not otherwise act on one at all (see ApplyPolicy's
// own doc comment), so where exactly "after value, before essential"
// it would run never actually matters here.
var operatorApplicationOrder = []string{opValue, opAdd, opDefault, opOneOf, opSubsetOf, opSupersetOf, opEssential}

// ErrPolicyError wraps any failure produced while merging or applying a
// metadata policy — OpenID Federation 1.0 §6.1.4 calls this generically
// a "policy error" and requires the whole Trust Chain be considered
// invalid when one occurs; this package leaves that consequence to its
// caller and only reports the failure itself.
var ErrPolicyError = fmt.Errorf("federation: policy error")

// errEssentialNotBoolean is the error for an "essential" operator whose
// value isn't a boolean.
const errEssentialNotBoolean = "essential operator value must be a boolean: %v"

// policyError wraps a description into ErrPolicyError.
func policyError(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrPolicyError, fmt.Sprintf(format, args...))
}

// MergePolicy merges next into current (OpenID Federation 1.0
// §6.1.4.1's three-level merge — entity type, then metadata parameter,
// then operator), for a resolver walking a Trust Chain top-down (from
// the statement issued by the most superior entity to the one issued
// by the Trust Chain subject's immediate superior), and returns the
// combined policy. current may be nil (the first Subordinate Statement
// with a metadata_policy claim becomes the current policy outright, no
// merge needed) — callers walking a chain should pass nil for the
// first encountered policy and this function's own result onward from
// there.
//
// currentCrit/nextCrit are each statement's own metadata_policy_crit
// claim — see mergeOperators' own doc comment for how a non-standard
// operator's merge is decided.
func MergePolicy(current MetadataPolicy, currentCrit []string, next MetadataPolicy, nextCrit []string) (MetadataPolicy, error) {
	crit := newCritSet(currentCrit, nextCrit)
	if err := validatePolicy(next, crit); err != nil {
		return nil, err
	}
	if current == nil {
		return next, nil
	}
	if next == nil {
		return current, nil
	}

	merged := make(MetadataPolicy, len(current))
	for entityType, params := range current {
		merged[entityType] = cloneParamPolicies(params)
	}
	for entityType, nextParams := range next {
		currentParams, ok := merged[entityType]
		if !ok {
			merged[entityType] = cloneParamPolicies(nextParams)
			continue
		}
		for claim, nextOps := range nextParams {
			currentOps, ok := currentParams[claim]
			if !ok {
				currentParams[claim] = nextOps
				continue
			}
			mergedOps, err := mergeOperators(currentOps, nextOps, crit)
			if err != nil {
				return nil, fmt.Errorf("federation: metadata_policy: %s.%s: %w", entityType, claim, err)
			}
			currentParams[claim] = mergedOps
		}
	}
	return merged, nil
}

func cloneParamPolicies(params map[string]PolicyOperators) map[string]PolicyOperators {
	out := make(map[string]PolicyOperators, len(params))
	for claim, ops := range params {
		out[claim] = ops
	}
	return out
}

// mergeOperators merges next into current for one metadata parameter's
// operators, per each standard operator's own "Operator value merge"
// rule (OpenID Federation 1.0 §6.1.3.1.1-.7). A non-standard operator
// present in both current and next is merged only if its two values
// are structurally identical — this package cannot know a third-party
// operator's own merge semantics (§6.1.3.2 requires the operator
// itself to declare them), so identical values is the one merge every
// operator can safely support regardless; anything else is a policy
// error, matching crit's own "must be understood to be processed"
// requirement when the operator is listed as critical, and erring on
// the side of rejecting an ambiguous merge otherwise.
func mergeOperators(current, next PolicyOperators, crit critSet) (PolicyOperators, error) {
	// CodeQL (go/allocation-size-overflow) flags len(current)+len(next)
	// as a theoretical overflow in the make() size argument — the
	// capacity is only a hint, so drop the addition rather than carry
	// the finding, matching this repo's own established fix for the
	// identical pattern (server/token.go's withIdentityClaims,
	// cmd/conformance-as/resource.go's userinfoHandler).
	merged := make(PolicyOperators, len(current))
	for name, value := range current {
		merged[name] = value
	}
	for name, nextValue := range next {
		currentValue, ok := merged[name]
		if !ok {
			merged[name] = nextValue
			continue
		}
		mergedValue, err := mergeOperatorValue(name, currentValue, nextValue)
		if err != nil {
			return nil, err
		}
		merged[name] = mergedValue
	}
	if err := validateCombination(merged, crit); err != nil {
		return nil, err
	}
	return merged, nil
}

func mergeOperatorValue(name string, current, next json.RawMessage) (json.RawMessage, error) {
	switch name {
	case opValue, opDefault:
		// "The operator values MUST be equal. If the values are not
		// equal this MUST produce a policy error" (default,
		// §6.1.3.1.3); value's own rule (§6.1.3.1.1) is identical.
		equal, err := jsonEqual(current, next)
		if err != nil {
			return nil, err
		}
		if !equal {
			return nil, policyError("%q operator values differ across the trust chain and cannot be merged", name)
		}
		return current, nil
	case opAdd, opSupersetOf:
		// Union (§6.1.3.1.2, §6.1.3.1.6).
		return unionArrays(current, next)
	case opOneOf:
		// Intersection; empty intersection is a policy error
		// (§6.1.3.1.4).
		result, err := intersectArrays(current, next)
		if err != nil {
			return nil, err
		}
		var arr []json.RawMessage
		_ = json.Unmarshal(result, &arr)
		if len(arr) == 0 {
			return nil, policyError("one_of operator values have no common intersection across the trust chain")
		}
		return result, nil
	case opSubsetOf:
		// Intersection; an empty result is explicitly allowed
		// (§6.1.3.1.5).
		return intersectArrays(current, next)
	case opEssential:
		// Logical OR (§6.1.3.1.7).
		var a, b bool
		if err := json.Unmarshal(current, &a); err != nil {
			return nil, policyError(errEssentialNotBoolean, err)
		}
		if err := json.Unmarshal(next, &b); err != nil {
			return nil, policyError(errEssentialNotBoolean, err)
		}
		return json.Marshal(a || b)
	default:
		// Non-standard operator: see mergeOperators' own doc comment.
		equal, err := jsonEqual(current, next)
		if err != nil {
			return nil, err
		}
		if !equal {
			return nil, policyError("non-standard operator %q has differing values across the trust chain and this package does not know its merge rule", name)
		}
		return current, nil
	}
}

// validateCombination checks one metadata parameter's operators against
// OpenID Federation 1.0 §6.1.3.1: each standard operator's value has the
// right JSON type, only allowed operators appear together, and combined
// operators' values are consistent with each other. §6.1.4.1 requires a
// policy error otherwise — both for each statement's own policy and for
// the result of every merge, so that no statement lower in the chain can
// loosen what a superior's policy fixed (e.g. an intermediate's "add"
// extending a Trust Anchor's "value"). A non-standard operator listed in
// crit is a policy error too, since this package implements none.
//
// "The values of value" for a null value (which removes the parameter)
// are taken to be none, so a null value is compatible with an empty add,
// with subset_of, and with an empty superset_of, and with nothing else.
func validateCombination(ops PolicyOperators, crit critSet) error {
	if err := validateOperandTypes(ops); err != nil {
		return err
	}
	if _, ok := ops[opOneOf]; ok {
		for _, other := range []string{opAdd, opSubsetOf, opSupersetOf} {
			if _, ok := ops[other]; ok {
				return policyError("one_of cannot be combined with %s", other)
			}
		}
	}
	if valueRaw, ok := ops[opValue]; ok {
		if err := validateValueCombinations(valueRaw, ops); err != nil {
			return err
		}
	}
	if err := requireSubset(ops, opAdd, opSubsetOf, "add values must be a subset of subset_of"); err != nil {
		return err
	}
	if err := requireSubset(ops, opSupersetOf, opSubsetOf, "subset_of values must be a superset of superset_of"); err != nil {
		return err
	}
	for name := range ops {
		if isStandardOperator(name) {
			continue
		}
		if _, critical := crit[name]; critical {
			return policyError("metadata_policy_crit requires understanding non-standard operator %q, which this package does not implement", name)
		}
	}
	return nil
}

// validateOperandTypes checks each standard operator's value has the
// JSON type §6.1.3.1 gives it: arrays for add, one_of, subset_of and
// superset_of, a boolean for essential, and a non-null value for default.
func validateOperandTypes(ops PolicyOperators) error {
	for _, name := range []string{opAdd, opOneOf, opSubsetOf, opSupersetOf} {
		if raw, ok := ops[name]; ok {
			if _, err := decodeArray(raw); err != nil {
				return policyError("%s operator value must be an array: %v", name, err)
			}
		}
	}
	if raw, ok := ops[opEssential]; ok {
		var essential bool
		if err := json.Unmarshal(raw, &essential); err != nil {
			return policyError(errEssentialNotBoolean, err)
		}
	}
	if raw, ok := ops[opDefault]; ok && isJSONNull(raw) {
		return policyError("default operator value must not be null")
	}
	return nil
}

// validateValueCombinations checks value against every operator it is
// combined with (§6.1.3.1.1).
func validateValueCombinations(valueRaw json.RawMessage, ops PolicyOperators) error {
	if isJSONNull(valueRaw) {
		if _, ok := ops[opDefault]; ok {
			return policyError("value is null and cannot be combined with default")
		}
		if raw, ok := ops[opEssential]; ok {
			var essential bool
			_ = json.Unmarshal(raw, &essential) // type already checked
			if essential {
				return policyError("value operator is null and essential operator is true")
			}
		}
	}
	if raw, ok := ops[opOneOf]; ok {
		options, _ := decodeArray(raw) // type already checked
		found, err := contains(options, valueRaw)
		if err != nil {
			return policyError("one_of: %v", err)
		}
		if !found { // a null value is among no one_of values
			return policyError("value must be among the one_of values")
		}
	}
	for _, check := range []struct {
		op, subsetOf, msg string
	}{
		{opAdd, opValue, "add values must be a subset of value"},
		{opValue, opSubsetOf, "value must be a subset of subset_of"},
		{opSupersetOf, opValue, "value must be a superset of superset_of"},
	} {
		if err := requireSubset(ops, check.op, check.subsetOf, check.msg); err != nil {
			return err
		}
	}
	return nil
}

// requireSubset reports a policy error unless the values of operator sub
// are all among the values of operator super, when both are present. A
// null value (from the value operator) has no values; any other non-array
// value can't be compared as a set and is a policy error.
func requireSubset(ops PolicyOperators, sub, super, msg string) error {
	subRaw, ok := ops[sub]
	if !ok {
		return nil
	}
	superRaw, ok := ops[super]
	if !ok {
		return nil
	}
	subValues, err := policyValues(sub, subRaw)
	if err != nil {
		return err
	}
	superValues, err := policyValues(super, superRaw)
	if err != nil {
		return err
	}
	superSet, err := newValueSet(superValues)
	if err != nil {
		return policyError("%s: %v", msg, err)
	}
	for _, v := range subValues {
		found, err := superSet.contains(v)
		if err != nil {
			return policyError("%s: %v", msg, err)
		}
		if !found {
			return policyError("%s", msg)
		}
	}
	return nil
}

// policyValues is an operator's value as a set of values: its elements
// for an array, none for null.
func policyValues(op string, raw json.RawMessage) ([]json.RawMessage, error) {
	if isJSONNull(raw) {
		return nil, nil
	}
	values, err := decodeArray(raw)
	if err != nil {
		return nil, policyError("%s must be an array to be combined as a set of values: %v", op, err)
	}
	return values, nil
}

// isJSONNull reports whether raw is the JSON literal null.
func isJSONNull(raw json.RawMessage) bool {
	var v any
	return json.Unmarshal(raw, &v) == nil && v == nil
}

// ValidatePolicy checks every metadata parameter policy in policy with
// validateCombination.
func ValidatePolicy(policy MetadataPolicy, crit []string) error {
	return validatePolicy(policy, newCritSet(crit))
}

func validatePolicy(policy MetadataPolicy, crit critSet) error {
	for entityType, params := range policy {
		for claim, ops := range params {
			if err := validateCombination(ops, crit); err != nil {
				return fmt.Errorf("federation: metadata_policy: %s.%s: %w", entityType, claim, err)
			}
		}
	}
	return nil
}

func isStandardOperator(name string) bool {
	switch name {
	case opValue, opAdd, opDefault, opOneOf, opSubsetOf, opSupersetOf, opEssential:
		return true
	default:
		return false
	}
}

// ApplyPolicy applies policy — a Trust Chain's already-resolved
// metadata policy, e.g. MergePolicy's own result — to metadata (both
// keyed by Entity Type identifier, e.g. "openid_relying_party"),
// returning the Resolved Metadata (OpenID Federation 1.0 §6.1.4.2).
// The policy applies to the Entity Types metadata has, and only those:
// §6.1.4.2 applies operators "for every Entity Type metadata ... for
// which a corresponding metadata parameter policy is present", and
// §6.1.2 scopes a policy to "Subordinate Entities of that type". A
// policy for an Entity Type metadata lacks creates nothing and checks
// nothing — not even "essential" — so it can't give an entity metadata
// it never declared, including a type allowed_entity_types removed
// (§6.2.3). metadata may be nil; the result is then empty.
//
// Only the seven standard operators (§6.1.3.1) are understood and
// acted on; a non-standard operator (§6.1.3.2) is ignored during
// application (per the spec's own "implementations MUST ignore
// additional operators that are not understood" default) unless it
// appears in crit, in which case ApplyPolicy fails outright — this
// package has no extension point for a caller to supply its own
// operator implementations yet, so "ignore" and "fail if critical" are
// the only two options available, matching the spec's own fallback
// behavior for an implementation with no support for a given
// non-standard operator at all.
func ApplyPolicy(policy MetadataPolicy, critNames []string, metadata map[string]json.RawMessage) (map[string]json.RawMessage, error) {
	crit := newCritSet(critNames)
	if err := validatePolicy(policy, crit); err != nil {
		return nil, err
	}
	resolved := make(map[string]json.RawMessage, len(metadata))
	for entityType, raw := range metadata {
		var current map[string]json.RawMessage
		if err := json.Unmarshal(raw, &current); err != nil {
			return nil, policyError("metadata.%s is not a JSON object: %v", entityType, err)
		}
		result, err := applyEntityTypePolicy(policy[entityType], crit, current)
		if err != nil {
			return nil, fmt.Errorf("federation: metadata.%s: %w", entityType, err)
		}
		encoded, err := json.Marshal(result)
		if err != nil {
			return nil, policyError("marshal resolved metadata.%s: %v", entityType, err)
		}
		resolved[entityType] = encoded
	}
	return resolved, nil
}

func applyEntityTypePolicy(params map[string]PolicyOperators, crit critSet, current map[string]json.RawMessage) (map[string]json.RawMessage, error) {
	claims := make(map[string]bool, len(params))
	for claim := range params {
		claims[claim] = true
	}
	for claim := range current {
		claims[claim] = true
	}

	resolved := make(map[string]json.RawMessage, len(claims))
	for claim := range claims {
		value, present := current[claim]
		value, present, err := applyClaimPolicy(params[claim], crit, value, present)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", claim, err)
		}
		if present {
			resolved[claim] = value
		}
	}
	return resolved, nil
}

// applyClaimPolicy applies ops to one metadata parameter's current
// value, in the fixed order operatorApplicationOrder declares.
func applyClaimPolicy(ops PolicyOperators, crit critSet, value json.RawMessage, present bool) (json.RawMessage, bool, error) {
	for _, op := range operatorApplicationOrder {
		raw, ok := ops[op]
		if !ok {
			continue
		}
		var err error
		value, present, err = applyOperator(op, raw, value, present)
		if err != nil {
			return nil, false, err
		}
	}
	for name := range ops {
		if isStandardOperator(name) {
			continue
		}
		if _, critical := crit[name]; critical {
			return nil, false, policyError("metadata_policy_crit requires understanding non-standard operator %q, which this package does not implement", name)
		}
		// Not critical: ignored, per ApplyPolicy's own doc comment.
	}
	return value, present, nil
}

// applyOperator applies op to value/present per §6.1.3.1.1's operator
// table. Each operator's own logic is split into its own function
// purely to keep this dispatcher's cognitive complexity manageable.
func applyOperator(op string, operand json.RawMessage, value json.RawMessage, present bool) (json.RawMessage, bool, error) {
	switch op {
	case opValue:
		return applyValueOperator(operand)
	case opAdd:
		return applyAddOperator(operand, value)
	case opDefault:
		return applyDefaultOperator(operand, value, present)
	case opOneOf:
		return applyOneOfOperator(operand, value, present)
	case opSubsetOf:
		return applySubsetOfOperator(operand, value, present)
	case opSupersetOf:
		return applySupersetOfOperator(operand, value, present)
	case opEssential:
		return applyEssentialOperator(operand, value, present)
	default:
		return value, present, nil
	}
}

func applyValueOperator(operand json.RawMessage) (json.RawMessage, bool, error) {
	var v any
	if err := json.Unmarshal(operand, &v); err != nil {
		return nil, false, policyError("value: %v", err)
	}
	if v == nil {
		return nil, false, nil
	}
	return operand, true, nil
}

func applyAddOperator(operand, value json.RawMessage) (json.RawMessage, bool, error) {
	merged, err := unionArrays(value, operand)
	if err != nil {
		return nil, false, fmt.Errorf("add: %w", err)
	}
	return merged, true, nil
}

func applyDefaultOperator(operand, value json.RawMessage, present bool) (json.RawMessage, bool, error) {
	if present {
		return value, present, nil
	}
	return operand, true, nil
}

func applyOneOfOperator(operand, value json.RawMessage, present bool) (json.RawMessage, bool, error) {
	if !present {
		return value, present, nil
	}
	var options []json.RawMessage
	if err := json.Unmarshal(operand, &options); err != nil {
		return nil, false, policyError("one_of: %v", err)
	}
	ok, err := contains(options, value)
	if err != nil {
		return nil, false, fmt.Errorf("one_of: %w", err)
	}
	if !ok {
		return nil, false, policyError("value is not one of the allowed values")
	}
	return value, present, nil
}

func applySubsetOfOperator(operand, value json.RawMessage, present bool) (json.RawMessage, bool, error) {
	if !present {
		return value, present, nil
	}
	result, err := intersectArrays(value, operand)
	if err != nil {
		return nil, false, fmt.Errorf("subset_of: %w", err)
	}
	return result, true, nil
}

func applySupersetOfOperator(operand, value json.RawMessage, present bool) (json.RawMessage, bool, error) {
	if !present {
		return value, present, nil
	}
	var required []json.RawMessage
	if err := json.Unmarshal(operand, &required); err != nil {
		return nil, false, policyError("superset_of: %v", err)
	}
	var have []json.RawMessage
	if err := json.Unmarshal(value, &have); err != nil {
		return nil, false, policyError("superset_of: metadata parameter is not an array: %v", err)
	}
	haveSet, err := newValueSet(have)
	if err != nil {
		return nil, false, fmt.Errorf("superset_of: %w", err)
	}
	for _, want := range required {
		ok, err := haveSet.contains(want)
		if err != nil {
			return nil, false, fmt.Errorf("superset_of: %w", err)
		}
		if !ok {
			return nil, false, policyError("value does not contain all required superset_of values")
		}
	}
	return value, present, nil
}

func applyEssentialOperator(operand, value json.RawMessage, present bool) (json.RawMessage, bool, error) {
	var essential bool
	if err := json.Unmarshal(operand, &essential); err != nil {
		return nil, false, policyError("essential: %v", err)
	}
	if essential && !present {
		return nil, false, policyError("essential metadata parameter is absent after applying policy")
	}
	return value, present, nil
}

// unionArrays returns the set union of a and b — both JSON arrays,
// deduplicated by structural equality (§6.1.3.1.2's "values already
// present ... MUST NOT be added another time"). a may be an absent
// (nil, zero-length) parameter, in which case the result is simply b's
// own values (§6.1.3.1.2's "if the metadata parameter is absent, it
// MUST be initialized with the value of this operator").
func unionArrays(a, b json.RawMessage) (json.RawMessage, error) {
	aArr, err := decodeArray(a)
	if err != nil {
		return nil, err
	}
	bArr, err := decodeArray(b)
	if err != nil {
		return nil, err
	}
	seen, err := newValueSet(aArr)
	if err != nil {
		return nil, err
	}
	out := append([]json.RawMessage{}, aArr...)
	for _, v := range bArr {
		added, err := seen.add(v)
		if err != nil {
			return nil, err
		}
		if added {
			out = append(out, v)
		}
	}
	return json.Marshal(out)
}

// intersectArrays returns the set intersection of a and b.
func intersectArrays(a, b json.RawMessage) (json.RawMessage, error) {
	aArr, err := decodeArray(a)
	if err != nil {
		return nil, err
	}
	bArr, err := decodeArray(b)
	if err != nil {
		return nil, err
	}
	bSet, err := newValueSet(bArr)
	if err != nil {
		return nil, err
	}
	out := []json.RawMessage{}
	for _, v := range aArr {
		ok, err := bSet.contains(v)
		if err != nil {
			return nil, err
		}
		if ok {
			out = append(out, v)
		}
	}
	return json.Marshal(out)
}

func decodeArray(raw json.RawMessage) ([]json.RawMessage, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var arr []json.RawMessage
	if err := json.Unmarshal(raw, &arr); err != nil {
		return nil, policyError("expected a JSON array: %v", err)
	}
	return arr, nil
}

// contains reports whether target is among arr's values, compared as
// jsonEqual does.
func contains(arr []json.RawMessage, target json.RawMessage) (bool, error) {
	set, err := newValueSet(arr)
	if err != nil {
		return false, err
	}
	return set.contains(target)
}

// jsonEqual reports whether a and b decode to structurally equal JSON
// values — used everywhere this package needs to compare a metadata
// parameter or operator value, since neither is a fixed Go type. Two
// numbers that differ only in JSON representation (1 vs 1.0) compare
// equal, matching ordinary JSON value equality; object member order
// never matters, since both sides are decoded before comparing.
func jsonEqual(a, b json.RawMessage) (bool, error) {
	ak, err := canonicalJSON(a)
	if err != nil {
		return false, err
	}
	bk, err := canonicalJSON(b)
	if err != nil {
		return false, err
	}
	return ak == bk, nil
}

// canonicalJSON re-encodes raw so that two structurally equal JSON
// values (see jsonEqual) always encode identically: decoding normalizes
// numbers to float64, and encoding sorts object members. Negative zero
// is the one decoded value encoding differently from a value it equals,
// so it is normalized to zero.
func canonicalJSON(raw json.RawMessage) (string, error) {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return "", policyError("%v", err)
	}
	encoded, err := json.Marshal(normalizeZero(v))
	if err != nil {
		return "", policyError("%v", err)
	}
	return string(encoded), nil
}

func normalizeZero(v any) any {
	switch t := v.(type) {
	case float64:
		if t == 0 {
			return float64(0)
		}
	case []any:
		for i, e := range t {
			t[i] = normalizeZero(e)
		}
	case map[string]any:
		for k, e := range t {
			t[k] = normalizeZero(e)
		}
	}
	return v
}

// valueSet is a set of JSON values keyed by canonicalJSON, so that set
// operations over a policy's arrays take time linear in their sizes.
// Policies come from any superior in a Trust Chain, and chains are
// resolved before a client authenticates, so comparing every pair of
// values would let a large array cost quadratic time.
type valueSet map[string]struct{}

func newValueSet(values []json.RawMessage) (valueSet, error) {
	set := make(valueSet, len(values))
	for _, v := range values {
		if _, err := set.add(v); err != nil {
			return nil, err
		}
	}
	return set, nil
}

// add adds v, reporting whether it was not already present.
func (s valueSet) add(v json.RawMessage) (bool, error) {
	key, err := canonicalJSON(v)
	if err != nil {
		return false, err
	}
	if _, ok := s[key]; ok {
		return false, nil
	}
	s[key] = struct{}{}
	return true, nil
}

func (s valueSet) contains(v json.RawMessage) (bool, error) {
	key, err := canonicalJSON(v)
	if err != nil {
		return false, err
	}
	_, ok := s[key]
	return ok, nil
}

// critSet is a union of metadata_policy_crit claims, as a set.
type critSet map[string]struct{}

func newCritSet(lists ...[]string) critSet {
	set := critSet{}
	for _, list := range lists {
		for _, name := range list {
			set[name] = struct{}{}
		}
	}
	return set
}
