package federation

import (
	"encoding/json"
	"testing"
)

// TestApplyPolicyMetadataPolicyExample reproduces OpenID Federation
// 1.0 §6.1.5's own non-normative worked example verbatim (Figures
// 10-14: a Trust Anchor's RP metadata policy, an Intermediate's own
// policy + metadata values for its subordinates, merged via
// MergePolicy, then applied via ApplyPolicy to a leaf RP's Entity
// Configuration metadata) and checks the result matches the spec's own
// Figure 14 output exactly — the strongest validation available for
// this package short of a live conformance run.
func TestApplyPolicyMetadataPolicyExample(t *testing.T) {
	trustAnchorPolicy := mustPolicy(t, `{
		"openid_relying_party": {
			"grant_types": {
				"default": ["authorization_code"],
				"subset_of": ["authorization_code", "refresh_token"],
				"superset_of": ["authorization_code"]
			},
			"token_endpoint_auth_method": {
				"one_of": ["private_key_jwt", "self_signed_tls_client_auth"],
				"essential": true
			},
			"token_endpoint_auth_signing_alg": {
				"one_of": ["PS256", "ES256"]
			},
			"subject_type": {
				"value": "pairwise"
			},
			"contacts": {
				"add": ["helpdesk@federation.example.org"]
			}
		}
	}`)

	intermediatePolicy := mustPolicy(t, `{
		"openid_relying_party": {
			"grant_types": {
				"subset_of": ["authorization_code"]
			},
			"token_endpoint_auth_method": {
				"one_of": ["self_signed_tls_client_auth"]
			},
			"contacts": {
				"add": ["helpdesk@org.example.org"]
			}
		}
	}`)
	intermediateMetadata := map[string]json.RawMessage{
		"openid_relying_party": json.RawMessage(`{
			"sector_identifier_uri": "https://org.example.org/sector-ids.json",
			"policy_uri": "https://org.example.org/policy.html"
		}`),
	}

	// Walking top-down: the statement from the most superior entity
	// (the Trust Anchor) becomes "current" first, then the
	// Intermediate's own policy is merged into it.
	merged, err := MergePolicy(trustAnchorPolicy, nil, intermediatePolicy, nil)
	if err != nil {
		t.Fatalf("MergePolicy: %v", err)
	}

	wantMerged := mustPolicy(t, `{
		"openid_relying_party": {
			"grant_types": {
				"default": ["authorization_code"],
				"superset_of": ["authorization_code"],
				"subset_of": ["authorization_code"]
			},
			"token_endpoint_auth_method": {
				"one_of": ["self_signed_tls_client_auth"],
				"essential": true
			},
			"token_endpoint_auth_signing_alg": {
				"one_of": ["PS256", "ES256"]
			},
			"subject_type": {
				"value": "pairwise"
			},
			"contacts": {
				"add": ["helpdesk@federation.example.org", "helpdesk@org.example.org"]
			}
		}
	}`)
	assertPolicyEqual(t, merged, wantMerged)

	// The Intermediate's own metadata values for its subordinates are
	// applied to the leaf's Entity Configuration metadata first
	// (§6.1.4.2's own "if the Subordinate Statement ... contains a
	// metadata Claim, this MUST first be applied" step) — simulated
	// here as the caller pre-merging plain metadata values before
	// calling ApplyPolicy, exactly as a resolver would after walking
	// the chain and encountering the Intermediate's own Subordinate
	// Statement about the leaf.
	leafMetadata := map[string]json.RawMessage{
		"openid_relying_party": json.RawMessage(`{
			"redirect_uris": ["https://rp.example.org/callback"],
			"response_types": ["code"],
			"token_endpoint_auth_method": "self_signed_tls_client_auth",
			"contacts": ["rp_admins@rp.example.org"]
		}`),
	}
	combinedMetadata := mergeMetadataValues(t, leafMetadata, intermediateMetadata)

	resolved, err := ApplyPolicy(merged, nil, combinedMetadata)
	if err != nil {
		t.Fatalf("ApplyPolicy: %v", err)
	}

	wantResolved := map[string]json.RawMessage{
		"openid_relying_party": json.RawMessage(`{
			"redirect_uris": ["https://rp.example.org/callback"],
			"grant_types": ["authorization_code"],
			"response_types": ["code"],
			"token_endpoint_auth_method": "self_signed_tls_client_auth",
			"subject_type": "pairwise",
			"sector_identifier_uri": "https://org.example.org/sector-ids.json",
			"policy_uri": "https://org.example.org/policy.html",
			"contacts": ["rp_admins@rp.example.org", "helpdesk@federation.example.org", "helpdesk@org.example.org"]
		}`),
	}
	assertMetadataEqual(t, resolved, wantResolved)
}

// TestApplyPolicyEssentialSubsetOfTable reproduces OpenID Federation
// 1.0 §6.1.3.1.8's Table 1 verbatim: every combination of essential
// and subset_of the spec itself lists, with the input metadata
// parameter value it names, checked against the exact output (or
// error) the table states.
func TestApplyPolicyEssentialSubsetOfTable(t *testing.T) {
	subsetOf := `["a","b","c"]`
	cases := []struct {
		name      string
		essential bool
		input     string // "" means the parameter is absent
		wantJSON  string // "" means the parameter must be absent from the result
		wantErr   bool
	}{
		{name: "essential true, overlapping input", essential: true, input: `["a","e"]`, wantJSON: `["a"]`},
		{name: "essential false, overlapping input", essential: false, input: `["a","e"]`, wantJSON: `["a"]`},
		{name: "essential true, disjoint input", essential: true, input: `["d","e"]`, wantJSON: `[]`},
		{name: "essential false, disjoint input", essential: false, input: `["d","e"]`, wantJSON: `[]`},
		{name: "essential true, no parameter", essential: true, input: "", wantErr: true},
		{name: "essential false, no parameter", essential: false, input: "", wantJSON: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ops := PolicyOperators{
				opEssential: json.RawMessage(boolJSON(tc.essential)),
				opSubsetOf:  json.RawMessage(subsetOf),
			}
			var value json.RawMessage
			present := tc.input != ""
			if present {
				value = json.RawMessage(tc.input)
			}
			result, resultPresent, err := applyClaimPolicy(ops, nil, value, present)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("applyClaimPolicy() = nil error, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("applyClaimPolicy: %v", err)
			}
			if tc.wantJSON == "" {
				if resultPresent {
					t.Fatalf("result present = true, want absent")
				}
				return
			}
			if !resultPresent {
				t.Fatalf("result present = false, want present")
			}
			eq, err := jsonEqual(result, json.RawMessage(tc.wantJSON))
			if err != nil {
				t.Fatalf("jsonEqual: %v", err)
			}
			if !eq {
				t.Fatalf("result = %s, want %s", result, tc.wantJSON)
			}
		})
	}
}

// TestMergeOperatorValuePerOperator exercises each standard operator's
// own "Operator value merge" rule (OpenID Federation 1.0 §6.1.3.1.1-.7)
// directly, beyond what TestApplyPolicyMetadataPolicyExample's single
// worked example already covers (add and essential merges, and every
// operator's own rejection case).
func TestMergeOperatorValuePerOperator(t *testing.T) {
	cases := []struct {
		name        string
		op          string
		current     string
		next        string
		want        string // "" means an error is expected
		wantErrLike string
	}{
		{name: "value: equal merges", op: opValue, current: `"pairwise"`, next: `"pairwise"`, want: `"pairwise"`},
		{name: "value: unequal errors", op: opValue, current: `"pairwise"`, next: `"public"`, wantErrLike: "differ"},
		{name: "default: equal merges", op: opDefault, current: `["a"]`, next: `["a"]`, want: `["a"]`},
		{name: "default: unequal errors", op: opDefault, current: `["a"]`, next: `["b"]`, wantErrLike: "differ"},
		{name: "add: union, deduplicated", op: opAdd, current: `["a","b"]`, next: `["b","c"]`, want: `["a","b","c"]`},
		{name: "superset_of: union", op: opSupersetOf, current: `["a"]`, next: `["b"]`, want: `["a","b"]`},
		{name: "subset_of: intersection", op: opSubsetOf, current: `["a","b"]`, next: `["b","c"]`, want: `["b"]`},
		{name: "subset_of: empty intersection is allowed", op: opSubsetOf, current: `["a"]`, next: `["b"]`, want: `[]`},
		{name: "one_of: intersection", op: opOneOf, current: `["a","b"]`, next: `["b","c"]`, want: `["b"]`},
		{name: "one_of: empty intersection errors", op: opOneOf, current: `["a"]`, next: `["b"]`, wantErrLike: "intersection"},
		{name: "essential: OR true/false", op: opEssential, current: `true`, next: `false`, want: `true`},
		{name: "essential: OR false/false", op: opEssential, current: `false`, next: `false`, want: `false`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := mergeOperatorValue(tc.op, json.RawMessage(tc.current), json.RawMessage(tc.next))
			if tc.wantErrLike != "" {
				if err == nil {
					t.Fatalf("mergeOperatorValue() = nil error, want error containing %q", tc.wantErrLike)
				}
				return
			}
			if err != nil {
				t.Fatalf("mergeOperatorValue: %v", err)
			}
			eq, err := jsonEqual(got, json.RawMessage(tc.want))
			if err != nil {
				t.Fatalf("jsonEqual: %v", err)
			}
			if !eq {
				t.Fatalf("mergeOperatorValue() = %s, want %s", got, tc.want)
			}
		})
	}
}

// TestMetadataPolicyCriticalOperator confirms a non-standard operator
// is ignored during application unless metadata_policy_crit demands it
// be understood, in which case both ApplyPolicy and MergePolicy must
// fail — OpenID Federation 1.0 §3.1.3/§6.1.4.1's own "MUST produce a
// policy error" requirement.
func TestMetadataPolicyCriticalOperator(t *testing.T) {
	policy := MetadataPolicy{
		"openid_relying_party": {
			"custom_claim": PolicyOperators{"x-custom-op": json.RawMessage(`"whatever"`)},
		},
	}
	metadata := map[string]json.RawMessage{
		"openid_relying_party": json.RawMessage(`{"custom_claim":"declared-value"}`),
	}

	t.Run("ignored when not critical", func(t *testing.T) {
		resolved, err := ApplyPolicy(policy, nil, metadata)
		if err != nil {
			t.Fatalf("ApplyPolicy: %v", err)
		}
		var rp map[string]json.RawMessage
		if err := json.Unmarshal(resolved["openid_relying_party"], &rp); err != nil {
			t.Fatalf("unmarshal resolved: %v", err)
		}
		eq, err := jsonEqual(rp["custom_claim"], json.RawMessage(`"declared-value"`))
		if err != nil || !eq {
			t.Fatalf("custom_claim = %s, want unchanged by the ignored operator", rp["custom_claim"])
		}
	})

	t.Run("fails when listed as critical", func(t *testing.T) {
		if _, err := ApplyPolicy(policy, []string{"x-custom-op"}, metadata); err == nil {
			t.Fatalf("ApplyPolicy(critical unknown operator) = nil error, want error")
		}
	})

	t.Run("MergePolicy fails when listed as critical on either side", func(t *testing.T) {
		other := MetadataPolicy{
			"openid_relying_party": {
				"custom_claim": PolicyOperators{"x-custom-op": json.RawMessage(`"different"`)},
			},
		}
		if _, err := MergePolicy(policy, []string{"x-custom-op"}, other, nil); err == nil {
			t.Fatalf("MergePolicy(critical unknown operator) = nil error, want error")
		}
	})
}

// TestMergePolicyEntityTypeAndParameterUnion confirms MergePolicy's
// top two merge levels (entity type, then metadata parameter) copy
// through anything the other side didn't already have, rather than
// only ever merging same-named operators — TestApplyPolicyMetadataPolicyExample's
// worked example never exercises a policy naming an entity type or
// parameter the other side omits entirely.
func TestMergePolicyEntityTypeAndParameterUnion(t *testing.T) {
	current := MetadataPolicy{
		"openid_relying_party": {
			"subject_type": PolicyOperators{opValue: json.RawMessage(`"pairwise"`)},
		},
	}
	next := MetadataPolicy{
		"openid_relying_party": {
			"grant_types": PolicyOperators{opDefault: json.RawMessage(`["authorization_code"]`)},
		},
		"openid_provider": {
			"request_parameter_supported": PolicyOperators{opValue: json.RawMessage(`true`)},
		},
	}

	merged, err := MergePolicy(current, nil, next, nil)
	if err != nil {
		t.Fatalf("MergePolicy: %v", err)
	}
	if _, ok := merged["openid_provider"]; !ok {
		t.Fatalf("merged policy missing entity type only next declared: %v", merged)
	}
	rp := merged["openid_relying_party"]
	if _, ok := rp["subject_type"]; !ok {
		t.Fatalf("merged policy lost parameter only current declared: %v", rp)
	}
	if _, ok := rp["grant_types"]; !ok {
		t.Fatalf("merged policy missing parameter only next declared: %v", rp)
	}
}

func boolJSON(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func mustPolicy(t *testing.T, raw string) MetadataPolicy {
	t.Helper()
	var p MetadataPolicy
	if err := json.Unmarshal([]byte(raw), &p); err != nil {
		t.Fatalf("unmarshal policy: %v", err)
	}
	return p
}

// mergeMetadataValues applies overlay's own claims on top of base for
// each entity type — a plain object-merge (overlay wins on collision),
// standing in for the Intermediate Entity's own metadata claim being
// applied to its subordinate's before that subordinate's Resolved
// Metadata is computed (§6.1.4.2's own first step, ahead of policy
// application), which this package doesn't itself perform since it
// belongs to chain-walking (see policy.go's own doc comments).
func mergeMetadataValues(t *testing.T, base, overlay map[string]json.RawMessage) map[string]json.RawMessage {
	t.Helper()
	out := make(map[string]json.RawMessage, len(base))
	for entityType, raw := range base {
		var claims map[string]json.RawMessage
		if err := json.Unmarshal(raw, &claims); err != nil {
			t.Fatalf("unmarshal base metadata: %v", err)
		}
		if overlayRaw, ok := overlay[entityType]; ok {
			var overlayClaims map[string]json.RawMessage
			if err := json.Unmarshal(overlayRaw, &overlayClaims); err != nil {
				t.Fatalf("unmarshal overlay metadata: %v", err)
			}
			for k, v := range overlayClaims {
				claims[k] = v
			}
		}
		encoded, err := json.Marshal(claims)
		if err != nil {
			t.Fatalf("marshal merged metadata: %v", err)
		}
		out[entityType] = encoded
	}
	return out
}

func assertPolicyEqual(t *testing.T, got, want MetadataPolicy) {
	t.Helper()
	gotJSON, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal got: %v", err)
	}
	wantJSON, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("marshal want: %v", err)
	}
	eq, err := jsonEqual(gotJSON, wantJSON)
	if err != nil {
		t.Fatalf("jsonEqual: %v", err)
	}
	if !eq {
		t.Fatalf("policy mismatch:\ngot:  %s\nwant: %s", gotJSON, wantJSON)
	}
}

func assertMetadataEqual(t *testing.T, got, want map[string]json.RawMessage) {
	t.Helper()
	for entityType, wantRaw := range want {
		gotRaw, ok := got[entityType]
		if !ok {
			t.Fatalf("resolved metadata missing entity type %q", entityType)
		}
		eq, err := jsonEqual(gotRaw, wantRaw)
		if err != nil {
			t.Fatalf("jsonEqual: %v", err)
		}
		if !eq {
			t.Fatalf("entity type %q mismatch:\ngot:  %s\nwant: %s", entityType, gotRaw, wantRaw)
		}
	}
	for entityType := range got {
		if _, ok := want[entityType]; !ok {
			t.Fatalf("resolved metadata has unexpected entity type %q: %s", entityType, got[entityType])
		}
	}
}
