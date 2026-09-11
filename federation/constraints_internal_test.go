package federation

import (
	"encoding/json"
	"testing"

	intfed "github.com/idfoundry/fapigo/internal/federation"
)

func TestDomainNameConstraintMatchesExactHost(t *testing.T) {
	if !domainNameConstraintMatches("host.example.com", "host.example.com") {
		t.Errorf("exact match = false, want true")
	}
	if domainNameConstraintMatches("host.example.com", "other.example.com") {
		t.Errorf("mismatched host = true, want false")
	}
}

func TestDomainNameConstraintMatchesIsCaseInsensitive(t *testing.T) {
	if !domainNameConstraintMatches("Host.Example.COM", "host.example.com") {
		t.Errorf("case-insensitive exact match = false, want true")
	}
}

func TestDomainNameConstraintMatchesSubtree(t *testing.T) {
	if !domainNameConstraintMatches(".example.com", "host.example.com") {
		t.Errorf(".example.com should match host.example.com")
	}
	if !domainNameConstraintMatches(".example.com", "my.host.example.com") {
		t.Errorf(".example.com should match my.host.example.com (multiple labels)")
	}
	// RFC 5280 §4.2.1.10: a dot-prefixed constraint is NOT satisfied by
	// the bare domain itself.
	if domainNameConstraintMatches(".example.com", "example.com") {
		t.Errorf(".example.com should NOT match the bare domain example.com")
	}
	if domainNameConstraintMatches(".example.com", "notexample.com") {
		t.Errorf(".example.com should not match a host that merely ends with the same characters")
	}
}

func TestEntityIDHostRejectsUnparseableEntityID(t *testing.T) {
	if _, err := entityIDHost("http://[::1"); err == nil {
		t.Fatalf("entityIDHost(unparseable) = nil error, want error")
	}
}

func TestCheckNamingConstraintPropagatesUnparseableEntityID(t *testing.T) {
	nc := intfed.NamingConstraints{Excluded: []string{"example.com"}}
	if err := checkNamingConstraint(nc, "http://[::1"); err == nil {
		t.Fatalf("checkNamingConstraint(unparseable entity ID) = nil error, want error")
	}
}

func TestCheckNamingConstraintExcludedRejects(t *testing.T) {
	nc := intfed.NamingConstraints{Excluded: []string{".excluded.example.com"}}
	if err := checkNamingConstraint(nc, "https://rp.excluded.example.com"); err == nil {
		t.Fatalf("checkNamingConstraint(excluded) = nil error, want error")
	}
}

func TestCheckNamingConstraintPermittedRequiresMatch(t *testing.T) {
	nc := intfed.NamingConstraints{Permitted: []string{".permitted.example.com"}}
	if err := checkNamingConstraint(nc, "https://rp.other.example.com"); err == nil {
		t.Fatalf("checkNamingConstraint(not in permitted namespace) = nil error, want error")
	}
	if err := checkNamingConstraint(nc, "https://rp.permitted.example.com"); err != nil {
		t.Fatalf("checkNamingConstraint(in permitted namespace): %v, want nil error", err)
	}
}

func TestCheckNamingConstraintNoPermittedAllowsAnything(t *testing.T) {
	nc := intfed.NamingConstraints{}
	if err := checkNamingConstraint(nc, "https://rp.anything.example.org"); err != nil {
		t.Fatalf("checkNamingConstraint(empty constraint): %v, want nil error", err)
	}
}

func TestCheckNamingConstraintsExcludedOverridesPermitted(t *testing.T) {
	nc := intfed.NamingConstraints{
		Permitted: []string{".example.com"},
		Excluded:  []string{"east.example.com"},
	}
	if err := checkNamingConstraint(nc, "https://east.example.com"); err == nil {
		t.Fatalf("checkNamingConstraint(excluded within permitted namespace) = nil error, want error")
	}
	if err := checkNamingConstraint(nc, "https://west.example.com"); err != nil {
		t.Fatalf("checkNamingConstraint(permitted, not excluded): %v, want nil error", err)
	}
}

func TestCheckNamingConstraintsAppliesToEveryEntryInAppliesTo(t *testing.T) {
	constraints := []subordinateConstraint{
		{
			constraints: intfed.Constraints{NamingConstraints: &intfed.NamingConstraints{Excluded: []string{"bad.example.com"}}},
			appliesTo:   []string{"https://good.example.com", "https://bad.example.com"},
		},
	}
	if err := checkNamingConstraints(constraints); err == nil {
		t.Fatalf("checkNamingConstraints(one excluded entry among appliesTo) = nil error, want error")
	}
}

func TestFilterAllowedEntityTypesNoConstraintsReturnsUnchanged(t *testing.T) {
	metadata := map[string]json.RawMessage{"openid_relying_party": json.RawMessage(`{}`)}
	got := filterAllowedEntityTypes(nil, metadata)
	if len(got) != 1 {
		t.Fatalf("filterAllowedEntityTypes(no constraints) = %v, want unchanged", got)
	}
}

func TestFilterAllowedEntityTypesIntersectsMultipleConstraints(t *testing.T) {
	metadata := map[string]json.RawMessage{
		"openid_relying_party": json.RawMessage(`{}`),
		"openid_provider":      json.RawMessage(`{}`),
	}
	constraints := []subordinateConstraint{
		{constraints: intfed.Constraints{AllowedEntityTypes: []string{"openid_relying_party", "openid_provider"}}},
		{constraints: intfed.Constraints{AllowedEntityTypes: []string{"openid_relying_party"}}},
	}
	got := filterAllowedEntityTypes(constraints, metadata)
	if _, ok := got["openid_relying_party"]; !ok {
		t.Errorf("openid_relying_party missing, want it allowed by both constraints")
	}
	if _, ok := got["openid_provider"]; ok {
		t.Errorf("openid_provider present, want it removed (not allowed by the second constraint)")
	}
}

func TestFilterAllowedEntityTypesAlwaysKeepsFederationEntity(t *testing.T) {
	metadata := map[string]json.RawMessage{
		"openid_relying_party": json.RawMessage(`{}`),
		"federation_entity":    json.RawMessage(`{}`),
	}
	constraints := []subordinateConstraint{
		{constraints: intfed.Constraints{AllowedEntityTypes: []string{}}},
	}
	got := filterAllowedEntityTypes(constraints, metadata)
	if _, ok := got["federation_entity"]; !ok {
		t.Errorf("federation_entity missing, want it always kept")
	}
	if _, ok := got["openid_relying_party"]; ok {
		t.Errorf("openid_relying_party present, want it removed (empty allowed_entity_types allows only federation_entity)")
	}
}
