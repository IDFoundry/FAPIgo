package federation_test

import (
	"encoding/json"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/federation"
	intfed "github.com/idfoundry/fapigo/internal/federation"
)

func newTestSelfIssuer(t *testing.T, authorityHints []string) (*federation.SelfIssuer, json.RawMessage) {
	t.Helper()
	key := generateKey(t)
	jwks := jwksFor(t, "k", key)
	issuer, err := federation.NewSelfIssuer(federation.SelfIssueConfig{
		EntityID: "https://le.example.org", AuthorityHints: authorityHints, Lifetime: time.Hour,
	}, federation.SelfIssueDependencies{Signer: key, Algorithm: fapi.ES256, KeyID: "k", JWKS: jwks, Clock: fixedClock{now: time.Now()}})
	if err != nil {
		t.Fatalf("NewSelfIssuer: %v", err)
	}
	return issuer, jwks
}

func newTestSubordinateIssuer(t *testing.T) (*federation.SubordinateIssuer, json.RawMessage) {
	t.Helper()
	key := generateKey(t)
	issuer, err := federation.NewSubordinateIssuer(federation.SubordinateIssueConfig{EntityID: "https://ta.example.org", Lifetime: time.Hour},
		federation.SubordinateIssueDependencies{Signer: key, Algorithm: fapi.ES256, KeyID: "k", Clock: fixedClock{now: time.Now()}})
	if err != nil {
		t.Fatalf("NewSubordinateIssuer: %v", err)
	}
	return issuer, jwksFor(t, "le", generateKey(t))
}

// requireParsesAndValidates checks token is accepted by the library's
// own Parse and its metadata_policy by ValidatePolicy, as a resolver
// would require.
func requireParsesAndValidates(t *testing.T, token string) {
	t.Helper()
	st, err := intfed.Parse(token)
	if err != nil {
		t.Fatalf("intfed.Parse: %v", err)
	}
	policy, crit := st.ClaimedMetadataPolicy()
	if err := intfed.ValidatePolicy(policy, crit); err != nil {
		t.Fatalf("ValidatePolicy: %v", err)
	}
}

// TestStatementBuildersRoundTripThroughParse: every statement a
// SelfIssuer or SubordinateIssuer signs with a full set of claims is one
// the library's own Parse and ValidatePolicy accept.
func TestStatementBuildersRoundTripThroughParse(t *testing.T) {
	self, _ := newTestSelfIssuer(t, []string{"https://ta.example.org"})
	ec, err := self.EntityConfiguration(map[string]json.RawMessage{
		"federation_entity": json.RawMessage(`{"organization_name":"Example"}`),
		"openid_provider":   json.RawMessage(`{"issuer":"https://le.example.org"}`),
	})
	if err != nil {
		t.Fatalf("EntityConfiguration: %v", err)
	}
	requireParsesAndValidates(t, ec)

	sub, jwks := newTestSubordinateIssuer(t)
	st, err := sub.SubordinateStatement(federation.SubordinateStatementParams{
		Subject: "https://le.example.org", JWKS: jwks,
		Metadata:       map[string]json.RawMessage{"openid_relying_party": json.RawMessage(`{"contacts":["ops@example.org"]}`)},
		MetadataPolicy: federation.MetadataPolicy{"openid_relying_party": {"scope": {"subset_of": json.RawMessage(`["openid","email"]`)}}},
		Constraints: &federation.Constraints{
			MaxPathLength: 0, HasMaxPathLength: true, AllowedEntityTypes: []string{"openid_relying_party"},
			NamingConstraints: &federation.NamingConstraints{Permitted: []string{".example.org"}},
		},
		SourceEndpoint: "https://ta.example.org/fetch",
	})
	if err != nil {
		t.Fatalf("SubordinateStatement: %v", err)
	}
	requireParsesAndValidates(t, st)
}

// TestSelfIssuerRefusesNonConformantClaims covers the Entity
// Configuration claims OpenID Federation 1.0 forbids an issuer to
// publish.
func TestSelfIssuerRefusesNonConformantClaims(t *testing.T) {
	for name, tc := range map[string]struct {
		authorityHints []string
		metadata       map[string]json.RawMessage
		trustMarks     []federation.RawTrustMark
	}{
		"§3.1.2 empty authority_hints":       {authorityHints: []string{}},
		"§5.1.3 openid_provider issuer":      {metadata: map[string]json.RawMessage{"openid_provider": json.RawMessage(`{"issuer":"https://someone-else.example.org"}`)}},
		"§5 null Entity Type metadata":       {metadata: map[string]json.RawMessage{"openid_relying_party": json.RawMessage(`null`)}},
		"§5 null metadata parameter":         {metadata: map[string]json.RawMessage{"openid_relying_party": json.RawMessage(`{"client_name":null}`)}},
		"§3.1.2 trust mark that isn't a JWT": {trustMarks: []federation.RawTrustMark{{TrustMarkType: "https://tm.example.org/a", TrustMark: "not-a-jwt"}}},
		"§3.1.2 trust mark of another type":  {trustMarks: []federation.RawTrustMark{{TrustMarkType: "https://tm.example.org/a", TrustMark: testTrustMarkOfType(t, "https://tm.example.org/b")}}},
	} {
		t.Run(name, func(t *testing.T) {
			self, _ := newTestSelfIssuer(t, tc.authorityHints)
			if token, err := self.EntityConfiguration(tc.metadata, tc.trustMarks...); err == nil {
				t.Fatalf("EntityConfiguration = %s, want it refused", token)
			}
		})
	}
}

// TestSubordinateIssuerRefusesNonConformantClaims covers the
// Subordinate Statement claims OpenID Federation 1.0 forbids an issuer
// to publish, including a max_path_length the library's own Parse
// refuses.
func TestSubordinateIssuerRefusesNonConformantClaims(t *testing.T) {
	for name, p := range map[string]federation.SubordinateStatementParams{
		"§3.1.3 empty metadata_policy_crit": {MetadataPolicyCritical: []string{}},
		"§6.1.3.1.4 one_of with subset_of":  {MetadataPolicy: federation.MetadataPolicy{"openid_relying_party": {"grant_types": {"one_of": json.RawMessage(`["a"]`), "subset_of": json.RawMessage(`["a"]`)}}}},
		"§6.2.1 negative max_path_length":   {Constraints: &federation.Constraints{MaxPathLength: -1, HasMaxPathLength: true}},
		"§6.2.3 federation_entity allowed":  {Constraints: &federation.Constraints{AllowedEntityTypes: []string{"federation_entity"}}},
		"§3.2 source_endpoint not a URL":    {SourceEndpoint: "not a url"},
		"§5 null metadata":                  {Metadata: map[string]json.RawMessage{"openid_relying_party": json.RawMessage(`null`)}},
	} {
		t.Run(name, func(t *testing.T) {
			sub, jwks := newTestSubordinateIssuer(t)
			p.Subject, p.JWKS = "https://le.example.org", jwks
			if token, err := sub.SubordinateStatement(p); err == nil {
				t.Fatalf("SubordinateStatement = %s, want it refused", token)
			}
		})
	}
}

func testTrustMarkOfType(t *testing.T, trustMarkType string) string {
	t.Helper()
	mark, err := intfed.CreateTrustMark(intfed.CreateTrustMarkParams{
		Signer: generateKey(t), Algorithm: fapi.ES256, KeyID: "tmi",
		Issuer: "https://tmi.example.org", Subject: "https://le.example.org",
		TrustMarkType: trustMarkType, Now: time.Now(),
	})
	if err != nil {
		t.Fatalf("CreateTrustMark: %v", err)
	}
	return mark
}
