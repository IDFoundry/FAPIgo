package federation

import (
	"encoding/json"
	"fmt"
	"slices"
)

// federationEntityType is the federation_entity Entity Type Identifier
// (OpenID Federation 1.0 §5.1.1).
const federationEntityType = "federation_entity"

// openIDProviderEntityType is the openid_provider Entity Type
// Identifier (OpenID Federation 1.0 §5.1.3).
const openIDProviderEntityType = "openid_provider"

// validateStatementContent refuses content the spec forbids an Entity
// Statement to carry that Parse doesn't itself refuse, because a
// consumer can still act on it: an invalid metadata_policy (§6.1.2,
// §6.1.3, which a resolver refuses once it applies the policy),
// federation_entity in allowed_entity_types (§6.2.3), a Trust Mark
// whose own trust_mark_type differs from the type it is listed under
// (§3.1.2), and openid_provider metadata whose issuer isn't the Entity
// Identifier (§5.1.3).
func validateStatementContent(p CreateParams) error {
	if err := ValidatePolicy(p.MetadataPolicy, p.MetadataPolicyCritical); err != nil {
		return err
	}
	if p.Constraints != nil && slices.Contains(p.Constraints.AllowedEntityTypes, federationEntityType) {
		return fmt.Errorf("federation: constraints: allowed_entity_types must not list %s, which is always allowed (OpenID Federation 1.0 §6.2.3)", federationEntityType)
	}
	for i, tm := range p.TrustMarks {
		mark, err := ParseTrustMark(tm.TrustMark)
		if err != nil {
			return fmt.Errorf("federation: trust_marks[%d]: %w", i, err)
		}
		if mark.ClaimedTrustMarkType() != tm.TrustMarkType {
			return fmt.Errorf("federation: trust_marks[%d]: listed as %q but the Trust Mark's own trust_mark_type is %q (OpenID Federation 1.0 §3.1.2)", i, tm.TrustMarkType, mark.ClaimedTrustMarkType())
		}
	}
	if p.Issuer == p.Subject {
		return checkOpenIDProviderIssuer(p.Metadata, p.Issuer)
	}
	return nil
}

// checkOpenIDProviderIssuer refuses openid_provider metadata whose
// issuer is present and isn't entityID: §5.1.3 "The issuer parameter
// value in the openid_provider metadata MUST match the Federation
// Entity Identifier".
func checkOpenIDProviderIssuer(metadata map[string]json.RawMessage, entityID string) error {
	raw, ok := metadata[openIDProviderEntityType]
	if !ok {
		return nil
	}
	var op struct {
		Issuer *string `json:"issuer"`
	}
	if err := json.Unmarshal(raw, &op); err != nil {
		return fmt.Errorf("federation: metadata.%s: %w", openIDProviderEntityType, err)
	}
	if op.Issuer != nil && *op.Issuer != entityID {
		return fmt.Errorf("federation: metadata.%s.issuer %q is not the Entity Identifier %q (OpenID Federation 1.0 §5.1.3)", openIDProviderEntityType, *op.Issuer, entityID)
	}
	return nil
}

// checkRoundTrip refuses claims Parse would refuse, so this package
// never signs a statement it, or another conformant implementation,
// rejects: an empty authority_hints or metadata_policy_crit, metadata
// that isn't an object of objects or uses null, a non-https
// source_endpoint, a negative max_path_length, and so on.
func checkRoundTrip(claims map[string]any) error {
	payload, err := json.Marshal(claims)
	if err != nil {
		return fmt.Errorf("federation: marshal claims: %w", err)
	}
	if _, err := parseClaims(payload); err != nil {
		return fmt.Errorf("federation: the statement would not parse: %w", err)
	}
	return nil
}
