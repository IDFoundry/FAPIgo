package federation

import (
	"encoding/json"
	"fmt"
	"net/url"
	"slices"
	"strings"

	intfed "github.com/idfoundry/fapigo/internal/federation"
)

// subordinateConstraint is one Subordinate Statement's own
// "constraints" claim (OpenID Federation 1.0 §6.2), collected bottom-up
// as Resolve walks upward. appliesTo is a snapshot — taken at the
// moment the constraint is read — of every entity ID already known to
// be Subordinate to whichever entity set it (everyone from the Trust
// Chain subject up to, but not including, that entity itself): a
// constraint only ever governs entities already below its issuer in
// the chain, never ones discovered later above it, so a later entity's
// own constraint must not retroactively apply to entities recorded
// under an earlier, unrelated snapshot.
type subordinateConstraint struct {
	constraints intfed.Constraints
	appliesTo   []string
}

// checkNamingConstraints validates every collected naming_constraints
// constraint (OpenID Federation 1.0 §6.2.2) against the entity IDs it
// governs. Each constraint is independently applied (per §6.2's own
// "the constraints Claim in each Subordinate Statement MUST be
// independently applied, if present. If any of the constraints checks
// fails, the Trust Chain MUST be considered invalid").
func checkNamingConstraints(constraints []subordinateConstraint) error {
	for _, sc := range constraints {
		if sc.constraints.NamingConstraints == nil {
			continue
		}
		for _, entityID := range sc.appliesTo {
			if err := checkNamingConstraint(*sc.constraints.NamingConstraints, entityID); err != nil {
				return err
			}
		}
	}
	return nil
}

// checkNamingConstraint validates entityID's host against nc, per
// OpenID Federation 1.0 §6.2.2: "Any name matching a restriction in the
// excluded list is invalid, regardless of the information appearing in
// the permitted list" — checked first, unconditionally — and otherwise,
// when a permitted list is present at all, entityID's host must match
// at least one of its entries.
func checkNamingConstraint(nc intfed.NamingConstraints, entityID string) error {
	host, err := entityIDHost(entityID)
	if err != nil {
		return err
	}
	for _, excluded := range nc.Excluded {
		if domainNameConstraintMatches(excluded, host) {
			return fmt.Errorf("federation: entity %q is excluded by naming_constraints (%q)", entityID, excluded)
		}
	}
	if len(nc.Permitted) == 0 {
		return nil
	}
	for _, permitted := range nc.Permitted {
		if domainNameConstraintMatches(permitted, host) {
			return nil
		}
	}
	return fmt.Errorf("federation: entity %q is not within any permitted naming_constraints namespace", entityID)
}

// entityIDHost extracts entityID's own host — every entity ID reaching
// this check has already passed ValidEntityID (an https URL with a
// host) by virtue of having been successfully fetched, so the only
// realistic failure here would indicate an internal inconsistency, not
// attacker-controlled input.
func entityIDHost(entityID string) (string, error) {
	u, err := url.Parse(entityID)
	if err != nil {
		return "", fmt.Errorf("federation: invalid entity identifier %q: %w", entityID, err)
	}
	return u.Hostname(), nil
}

// domainNameConstraintMatches reports whether host satisfies constraint,
// per the RFC 5280 §4.2.1.10 domain-name-constraint syntax OpenID
// Federation 1.0 §6.2.2 itself specifies: a constraint beginning with
// "." is a subtree match — satisfied by any host with one or more
// additional labels before that suffix, but NOT by the bare domain
// itself (".example.com" matches "host.example.com", not
// "example.com") — and a constraint not beginning with "." specifies an
// exact host. Matched case-insensitively, per normal domain-name
// comparison.
func domainNameConstraintMatches(constraint, host string) bool {
	if strings.HasPrefix(constraint, ".") {
		return len(host) > len(constraint) && strings.EqualFold(host[len(host)-len(constraint):], constraint)
	}
	return strings.EqualFold(constraint, host)
}

// filterAllowedEntityTypes applies every collected allowed_entity_types
// constraint (OpenID Federation 1.0 §6.2.3) to metadata (the Trust
// Chain subject's own declared metadata, before any metadata_policy is
// applied — §6.2.3's own "This MUST be done before applying Metadata
// Policies"), returning a filtered copy. Each constraint is
// independently applied like checkNamingConstraints — a metadata Entity
// Type survives only if every constraint that declares an
// allowed_entity_types list includes it; federation_entity is always
// kept, since §6.2.3 requires it "MUST NOT be included in the
// constraint" and is "always allowed" regardless.
func filterAllowedEntityTypes(constraints []subordinateConstraint, metadata map[string]json.RawMessage) map[string]json.RawMessage {
	var allowedSets [][]string
	for _, sc := range constraints {
		if sc.constraints.AllowedEntityTypes != nil {
			allowedSets = append(allowedSets, sc.constraints.AllowedEntityTypes)
		}
	}
	if len(allowedSets) == 0 {
		return metadata
	}
	filtered := make(map[string]json.RawMessage, len(metadata))
	for entityType, v := range metadata {
		if entityType == federationEntityType {
			filtered[entityType] = v
			continue
		}
		allowed := true
		for _, set := range allowedSets {
			if !slices.Contains(set, entityType) {
				allowed = false
				break
			}
		}
		if allowed {
			filtered[entityType] = v
		}
	}
	return filtered
}
