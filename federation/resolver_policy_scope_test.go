package federation_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/fapigo/federation"
	intfed "github.com/idfoundry/fapigo/internal/federation"
)

// rpPolicyCreatingClient is a metadata policy that, if it were applied to
// an entity with no openid_relying_party metadata, would build a complete
// relying party registration out of nothing.
func rpPolicyCreatingClient(t *testing.T) intfed.MetadataPolicy {
	t.Helper()
	var p intfed.MetadataPolicy
	raw := `{"openid_relying_party":{
		"redirect_uris":{"value":["https://attacker.example/cb"]},
		"token_endpoint_auth_method":{"value":"private_key_jwt"},
		"response_types":{"value":["code"]}}}`
	if err := json.Unmarshal([]byte(raw), &p); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestPolicyDoesNotRecreateAFilteredEntityType covers OpenID Federation 1.0
// §6.2.3 against §6.1.4.2: allowed_entity_types removes an Entity Type
// from the subject's metadata, and a metadata policy for that type must
// not build it again, or a constrained superior could turn a leaf it
// vouches for into a relying party and get it registered.
func TestPolicyDoesNotRecreateAFilteredEntityType(t *testing.T) {
	f := setupConstrainedFederationWith(t, constrainedFederationParams{
		constraints: &intfed.Constraints{AllowedEntityTypes: []string{"openid_provider"}},
		policy:      rpPolicyCreatingClient(t),
		leMetadata: map[string]json.RawMessage{
			"openid_provider":      json.RawMessage(`{"issuer":"https://op.example"}`),
			"openid_relying_party": json.RawMessage(`{"redirect_uris":["https://le.example/cb"]}`),
		},
	})
	resolved, err := f.newResolver(t).Resolve(context.Background(), f.leID)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if rp, ok := resolved.Metadata["openid_relying_party"]; ok {
		t.Fatalf("Resolved Metadata has openid_relying_party %s, which allowed_entity_types removed", rp)
	}
	if _, ok := resolved.Metadata["openid_provider"]; !ok {
		t.Error("Resolved Metadata lost the allowed openid_provider type")
	}
}

// TestPolicyForAnAbsentEntityTypeIsIgnored covers an entity that never
// declared the type a policy is about: nothing is created, and an
// "essential" operator for that type doesn't make the entity's own
// resolution fail.
func TestPolicyForAnAbsentEntityTypeIsIgnored(t *testing.T) {
	policy := rpPolicyCreatingClient(t)
	policy["openid_relying_party"]["contacts"] = intfed.PolicyOperators{"essential": json.RawMessage(`true`)}
	f := setupConstrainedFederationWith(t, constrainedFederationParams{
		policy:     policy,
		leMetadata: map[string]json.RawMessage{"openid_provider": json.RawMessage(`{"issuer":"https://op.example"}`)},
	})
	resolved, err := f.newResolver(t).Resolve(context.Background(), f.leID)
	if err != nil {
		t.Fatalf("Resolve of an OP under an essential RP policy: %v", err)
	}
	if _, ok := resolved.Metadata["openid_relying_party"]; ok {
		t.Error("a policy created openid_relying_party metadata for an entity that never declared it")
	}
}

// TestChainExpiresWithItsSubordinateStatement covers §10.4: the Trust
// Chain expires at the earliest exp of all its statements, so a superior
// that issues short-lived statements about an entity stops vouching for
// it when one lapses.
func TestChainExpiresWithItsSubordinateStatement(t *testing.T) {
	f := setupConstrainedFederationWith(t, constrainedFederationParams{aboutLELifetime: 2 * time.Minute})
	resolved, err := f.newResolver(t).Resolve(context.Background(), f.leID)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if limit := f.now.Add(2 * time.Minute); resolved.ExpiresAt.After(limit) {
		t.Errorf("ExpiresAt = %v, want no later than the Subordinate Statement's exp %v", resolved.ExpiresAt, limit)
	}
}

// TestChainExpiresWithAnIntermediateSubordinateStatement is
// TestChainExpiresWithItsSubordinateStatement for a statement in the
// middle of a longer chain (leaf > i1 > i2 > ta), where i1's statement
// about the leaf is short-lived.
func TestChainExpiresWithAnIntermediateSubordinateStatement(t *testing.T) {
	g := newFederationGraph(t, "leaf", "i1", "i2", "ta")
	g.lifetimes = map[string]time.Duration{"i1>leaf": 2 * time.Minute}
	g.link(map[string][]string{"leaf": {"i1"}, "i1": {"i2"}, "i2": {"ta"}})
	resolved, err := g.resolver(5, 5, "ta").Resolve(context.Background(), g.entities["leaf"].id)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if limit := g.now.Add(2 * time.Minute); resolved.ExpiresAt.After(limit) {
		t.Errorf("ExpiresAt = %v, want no later than i1's statement's exp %v", resolved.ExpiresAt, limit)
	}
}

// TestEntityIDWithTrailingDotRefused covers a host ending in ".": the same
// host to DNS and TLS, but a different string, which would otherwise slip
// past an "excluded" naming constraint written for the usual form.
func TestEntityIDWithTrailingDotRefused(t *testing.T) {
	for _, id := range []string{"https://le.example.", "https://le.example.:8443/x"} {
		if err := federation.ValidEntityID(id); err == nil || !strings.Contains(err.Error(), "dot") {
			t.Errorf("ValidEntityID(%q) = %v, want refused for its trailing dot", id, err)
		}
	}
	if err := federation.ValidEntityID("https://le.example/path."); err != nil {
		t.Errorf("ValidEntityID with a dot ending the path: %v, want accepted", err)
	}

	f := setupConstrainedFederation(t, &intfed.Constraints{
		NamingConstraints: &intfed.NamingConstraints{Excluded: []string{loopbackHost}},
	}, nil)
	dotted := strings.Replace(f.leID, loopbackHost, loopbackHost+".", 1)
	if _, err := f.newResolver(t).Resolve(context.Background(), dotted); err == nil {
		t.Fatalf("Resolve(%q) = nil error, want the trailing-dot host refused", dotted)
	}
}
