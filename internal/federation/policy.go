package federation

import (
	"encoding/json"
	"fmt"
	"reflect"
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
	if current == nil {
		return next, nil
	}
	if next == nil {
		return current, nil
	}
	crit := unionStrings(currentCrit, nextCrit)

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
func mergeOperators(current, next PolicyOperators, crit []string) (PolicyOperators, error) {
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
			return nil, policyError("essential operator value must be a boolean: %v", err)
		}
		if err := json.Unmarshal(next, &b); err != nil {
			return nil, policyError("essential operator value must be a boolean: %v", err)
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

// validateCombination rejects the specific operator combinations
// OpenID Federation 1.0 §6.1.3.1 explicitly disallows. This is not a
// complete combination linter for every MAY-combine rule the standard
// operators declare (e.g. "add MUST be a subset of value") — those
// constrain what a well-formed policy author writes, not what this
// package must reject to compute a correct Resolved Metadata, and
// enforcing all of them is deferred until something in this codebase
// actually needs that completeness. The one combination this function
// does enforce — value: null with essential: true — is checked because
// ApplyPolicy's own value/essential ordering would otherwise silently
// produce a confusing result (a required parameter deleted by the
// same policy that requires it) rather than the policy error the spec
// calls for.
func validateCombination(ops PolicyOperators, crit []string) error {
	valueRaw, hasValue := ops[opValue]
	essentialRaw, hasEssential := ops[opEssential]
	if hasValue && hasEssential {
		var essential bool
		if err := json.Unmarshal(essentialRaw, &essential); err == nil && essential {
			var v any
			if json.Unmarshal(valueRaw, &v) == nil && v == nil {
				return policyError("value operator is null and essential operator is true")
			}
		}
	}
	for name := range ops {
		if isStandardOperator(name) {
			continue
		}
		// A non-standard operator this package doesn't otherwise act
		// on (see ApplyPolicy) is fine to carry through unless the
		// statement itself demanded it be understood.
		if containsString(crit, name) {
			return policyError("metadata_policy_crit requires understanding non-standard operator %q, which this package does not implement", name)
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
// metadata may be nil (an Entity Configuration that declared no
// metadata at all still receives whatever default/add/value operators
// supply).
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
func ApplyPolicy(policy MetadataPolicy, crit []string, metadata map[string]json.RawMessage) (map[string]json.RawMessage, error) {
	// Capacity is only a hint; see mergeOperators' own doc comment on
	// why this drops the addition rather than sum the two lengths.
	entityTypes := make(map[string]bool, len(policy))
	for entityType := range policy {
		entityTypes[entityType] = true
	}
	for entityType := range metadata {
		entityTypes[entityType] = true
	}

	resolved := make(map[string]json.RawMessage, len(entityTypes))
	for entityType := range entityTypes {
		var current map[string]json.RawMessage
		if raw, ok := metadata[entityType]; ok {
			if err := json.Unmarshal(raw, &current); err != nil {
				return nil, policyError("metadata.%s is not a JSON object: %v", entityType, err)
			}
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

func applyEntityTypePolicy(params map[string]PolicyOperators, crit []string, current map[string]json.RawMessage) (map[string]json.RawMessage, error) {
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
func applyClaimPolicy(ops PolicyOperators, crit []string, value json.RawMessage, present bool) (json.RawMessage, bool, error) {
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
		if containsString(crit, name) {
			return nil, false, policyError("metadata_policy_crit requires understanding non-standard operator %q, which this package does not implement", name)
		}
		// Not critical: ignored, per ApplyPolicy's own doc comment.
	}
	return value, present, nil
}

func applyOperator(op string, operand json.RawMessage, value json.RawMessage, present bool) (json.RawMessage, bool, error) {
	switch op {
	case opValue:
		var v any
		if err := json.Unmarshal(operand, &v); err != nil {
			return nil, false, policyError("value: %v", err)
		}
		if v == nil {
			return nil, false, nil
		}
		return operand, true, nil
	case opAdd:
		merged, err := unionArrays(value, operand)
		if err != nil {
			return nil, false, fmt.Errorf("add: %w", err)
		}
		return merged, true, nil
	case opDefault:
		if present {
			return value, present, nil
		}
		return operand, true, nil
	case opOneOf:
		if !present {
			return value, present, nil
		}
		var options []json.RawMessage
		if err := json.Unmarshal(operand, &options); err != nil {
			return nil, false, policyError("one_of: %v", err)
		}
		ok, err := containsRaw(options, value)
		if err != nil {
			return nil, false, fmt.Errorf("one_of: %w", err)
		}
		if !ok {
			return nil, false, policyError("value is not one of the allowed values")
		}
		return value, present, nil
	case opSubsetOf:
		if !present {
			return value, present, nil
		}
		result, err := intersectArrays(value, operand)
		if err != nil {
			return nil, false, fmt.Errorf("subset_of: %w", err)
		}
		return result, true, nil
	case opSupersetOf:
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
		for _, want := range required {
			ok, err := containsRaw(have, want)
			if err != nil {
				return nil, false, fmt.Errorf("superset_of: %w", err)
			}
			if !ok {
				return nil, false, policyError("value does not contain all required superset_of values")
			}
		}
		return value, present, nil
	case opEssential:
		var essential bool
		if err := json.Unmarshal(operand, &essential); err != nil {
			return nil, false, policyError("essential: %v", err)
		}
		if essential && !present {
			return nil, false, policyError("essential metadata parameter is absent after applying policy")
		}
		return value, present, nil
	default:
		return value, present, nil
	}
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
	out := append([]json.RawMessage{}, aArr...)
	for _, v := range bArr {
		ok, err := containsRaw(out, v)
		if err != nil {
			return nil, err
		}
		if !ok {
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
	out := []json.RawMessage{}
	for _, v := range aArr {
		ok, err := containsRaw(bArr, v)
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

func containsRaw(arr []json.RawMessage, target json.RawMessage) (bool, error) {
	for _, v := range arr {
		equal, err := jsonEqual(v, target)
		if err != nil {
			return false, err
		}
		if equal {
			return true, nil
		}
	}
	return false, nil
}

// jsonEqual reports whether a and b decode to structurally equal JSON
// values — used everywhere this package needs to compare a metadata
// parameter or operator value, since neither is a fixed Go type. Two
// numbers that differ only in JSON representation (1 vs 1.0) compare
// equal, matching ordinary JSON value equality; object member order
// never matters, since both sides are decoded before comparing.
func jsonEqual(a, b json.RawMessage) (bool, error) {
	var av, bv any
	if err := json.Unmarshal(a, &av); err != nil {
		return false, policyError("%v", err)
	}
	if err := json.Unmarshal(b, &bv); err != nil {
		return false, policyError("%v", err)
	}
	return reflect.DeepEqual(av, bv), nil
}

func unionStrings(a, b []string) []string {
	if len(a) == 0 {
		return b
	}
	if len(b) == 0 {
		return a
	}
	out := append([]string{}, a...)
	for _, s := range b {
		if !containsString(out, s) {
			out = append(out, s)
		}
	}
	return out
}

func containsString(arr []string, target string) bool {
	for _, s := range arr {
		if s == target {
			return true
		}
	}
	return false
}
