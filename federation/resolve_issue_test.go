package federation_test

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/federation"
	intfed "github.com/idfoundry/fapigo/internal/federation"
)

func validResolveIssueConfig() federation.ResolveIssueConfig {
	return federation.ResolveIssueConfig{EntityID: "https://resolver.example.org"}
}

func validResolveIssueDependencies(t *testing.T) federation.ResolveIssueDependencies {
	t.Helper()
	return federation.ResolveIssueDependencies{
		Signer: generateKey(t), Algorithm: fapi.ES256, KeyID: "resolver-key", Clock: federation.SystemClock{},
	}
}

func TestNewResolveIssuerRejectsInvalidConfig(t *testing.T) {
	cases := map[string]func(*federation.ResolveIssueConfig, *federation.ResolveIssueDependencies){
		"no entity id": func(c *federation.ResolveIssueConfig, d *federation.ResolveIssueDependencies) { c.EntityID = "" },
		"non-https entity": func(c *federation.ResolveIssueConfig, d *federation.ResolveIssueDependencies) {
			c.EntityID = "http://x.example.org"
		},
		"no signer": func(c *federation.ResolveIssueConfig, d *federation.ResolveIssueDependencies) { d.Signer = nil },
		"no key id": func(c *federation.ResolveIssueConfig, d *federation.ResolveIssueDependencies) { d.KeyID = "" },
		"no clock":  func(c *federation.ResolveIssueConfig, d *federation.ResolveIssueDependencies) { d.Clock = nil },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := validResolveIssueConfig()
			deps := validResolveIssueDependencies(t)
			mutate(&cfg, &deps)
			if _, err := federation.NewResolveIssuer(cfg, deps); err == nil {
				t.Fatalf("NewResolveIssuer(%s) = nil error, want error", name)
			}
		})
	}
}

// resolveThreeLevelLeaf resolves f.leID via a real *federation.Resolver
// against the shared three-level fixture, returning the result — the
// same ResolvedEntity.Tokens correctness TestResolveTokensMatchesTrustChain
// already verifies independently, reused here as ResolveIssuer.Response's
// own real input rather than a hand-built stand-in.
func resolveThreeLevelLeaf(t *testing.T, f *threeLevelFederation) federation.ResolvedEntity {
	t.Helper()
	r := f.newResolver(t)
	resolved, err := r.Resolve(context.Background(), f.leID)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	return resolved
}

func TestResolveIssuerResponse(t *testing.T) {
	f := setupThreeLevelFederation(t)
	resolved := resolveThreeLevelLeaf(t, f)

	key := generateKey(t)
	issuer, err := federation.NewResolveIssuer(federation.ResolveIssueConfig{EntityID: "https://resolver.example.org"},
		federation.ResolveIssueDependencies{
			Signer: key, Algorithm: fapi.ES256, KeyID: "resolver-key",
			Clock: fixedClock{now: f.now.Add(time.Minute)},
		})
	if err != nil {
		t.Fatalf("NewResolveIssuer: %v", err)
	}

	token, err := issuer.Response(resolved, []string{f.taID, "https://some-other-anchor.example.org"}, nil, nil)
	if err != nil {
		t.Fatalf("Response: %v", err)
	}

	resp, err := intfed.ParseResolveResponse(token)
	if err != nil {
		t.Fatalf("ParseResolveResponse: %v", err)
	}
	if resp.ClaimedIssuer() != "https://resolver.example.org" {
		t.Errorf("ClaimedIssuer() = %q", resp.ClaimedIssuer())
	}
	claims, err := resp.Verify(&key.PublicKey, intfed.ResolveResponseVerifyPolicy{
		ExpectedIssuer: "https://resolver.example.org", ExpectedSubject: f.leID,
		Algorithm: fapi.ES256, Now: f.now.Add(time.Minute),
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if claims.Subject != f.leID {
		t.Errorf("Subject = %q, want %q", claims.Subject, f.leID)
	}
	if len(claims.TrustChain) != len(resolved.Tokens) {
		t.Fatalf("TrustChain = %v, want %v", claims.TrustChain, resolved.Tokens)
	}
	for i, tok := range resolved.Tokens {
		if claims.TrustChain[i] != tok {
			t.Errorf("TrustChain[%d] = %q, want %q", i, claims.TrustChain[i], tok)
		}
	}
	if _, ok := claims.Metadata["openid_relying_party"]; !ok {
		t.Errorf("Metadata missing openid_relying_party: %v", claims.Metadata)
	}
}

// TestResolveIssuerResponseFiltersEntityTypes uses a hand-built
// ResolvedEntity (not a real Resolve, whose own three-level fixture
// only ever resolves a single Entity Type on the leaf, openid_relying_party
// — insufficient to actually exercise narrowing) with two Entity Types,
// confirming entityTypes keeps only the requested one.
func TestResolveIssuerResponseFiltersEntityTypes(t *testing.T) {
	resolved := federation.ResolvedEntity{
		EntityID: "https://op.example.org", TrustAnchor: "https://ta.example.org",
		Metadata: map[string]json.RawMessage{
			"openid_provider":   json.RawMessage(`{"issuer":"https://op.example.org"}`),
			"federation_entity": json.RawMessage(`{"organization_name":"Example Org"}`),
		},
		ExpiresAt: time.Now().Add(time.Hour),
		Tokens:    []string{"placeholder-chain-entry"},
	}

	key := generateKey(t)
	issuer, err := federation.NewResolveIssuer(federation.ResolveIssueConfig{EntityID: "https://resolver.example.org"},
		federation.ResolveIssueDependencies{Signer: key, Algorithm: fapi.ES256, KeyID: "resolver-key", Clock: federation.SystemClock{}})
	if err != nil {
		t.Fatalf("NewResolveIssuer: %v", err)
	}

	token, err := issuer.Response(resolved, []string{"https://ta.example.org"}, []string{"federation_entity"}, nil)
	if err != nil {
		t.Fatalf("Response: %v", err)
	}
	resp, err := intfed.ParseResolveResponse(token)
	if err != nil {
		t.Fatalf("ParseResolveResponse: %v", err)
	}
	claims, err := resp.Verify(&key.PublicKey, intfed.ResolveResponseVerifyPolicy{
		ExpectedIssuer: "https://resolver.example.org", ExpectedSubject: "https://op.example.org",
		Algorithm: fapi.ES256, Now: time.Now(),
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if _, ok := claims.Metadata["openid_provider"]; ok {
		t.Errorf("Metadata still contains openid_provider after filtering to federation_entity: %v", claims.Metadata)
	}
	if _, ok := claims.Metadata["federation_entity"]; !ok {
		t.Errorf("Metadata missing federation_entity: %v", claims.Metadata)
	}
}

// TestResolveIssuerResponseIncludesVerifiedTrustMark reuses
// trustMarkFederation (TA doubling as Trust Mark Issuer, LE declaring
// one Trust Mark about itself) to confirm Response's own trustMarks
// parameter reaches the signed response's "trust_marks" claim intact.
func TestResolveIssuerResponseIncludesVerifiedTrustMark(t *testing.T) {
	f := setupTrustMarkFederation(t, nil, nil)
	r := f.newResolver(t)

	resolved, err := r.Resolve(context.Background(), f.leID)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(resolved.TrustMarks) != 1 {
		t.Fatalf("TrustMarks = %v, want 1 entry", resolved.TrustMarks)
	}
	claims, err := r.VerifyTrustMark(context.Background(), f.leID, resolved.TrustMarks[0])
	if err != nil {
		t.Fatalf("VerifyTrustMark: %v", err)
	}

	key := generateKey(t)
	issuer, err := federation.NewResolveIssuer(federation.ResolveIssueConfig{EntityID: "https://resolver.example.org"},
		federation.ResolveIssueDependencies{Signer: key, Algorithm: fapi.ES256, KeyID: "resolver-key", Clock: fixedClock{now: f.now}})
	if err != nil {
		t.Fatalf("NewResolveIssuer: %v", err)
	}

	// trustMarkFederation's LE Entity Configuration declares no
	// openid_relying_party (or any) metadata of its own — it's a trust
	// marks fixture, not a metadata one — but CreateResolveResponse
	// requires a non-empty "metadata" claim; inject a minimal
	// placeholder, incidental to what this test actually exercises.
	resolved.Metadata = map[string]json.RawMessage{"openid_relying_party": json.RawMessage(`{}`)}

	trustMarks := []federation.VerifiedTrustMark{{RawTrustMark: resolved.TrustMarks[0], ExpiresAt: claims.ExpiresAt}}
	token, err := issuer.Response(resolved, []string{f.taID}, nil, trustMarks)
	if err != nil {
		t.Fatalf("Response: %v", err)
	}

	resp, err := intfed.ParseResolveResponse(token)
	if err != nil {
		t.Fatalf("ParseResolveResponse: %v", err)
	}
	respClaims, err := resp.Verify(&key.PublicKey, intfed.ResolveResponseVerifyPolicy{
		ExpectedIssuer: "https://resolver.example.org", ExpectedSubject: f.leID,
		Algorithm: fapi.ES256, Now: f.now,
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if len(respClaims.TrustMarks) != 1 {
		t.Fatalf("TrustMarks = %v, want 1 entry", respClaims.TrustMarks)
	}
	if respClaims.TrustMarks[0].TrustMarkType != testTrustMarkType {
		t.Errorf("TrustMarks[0].TrustMarkType = %q, want %q", respClaims.TrustMarks[0].TrustMarkType, testTrustMarkType)
	}
	if respClaims.TrustMarks[0].TrustMark != resolved.TrustMarks[0].TrustMark {
		t.Errorf("TrustMarks[0].TrustMark = %q, want the original trust mark JWT", respClaims.TrustMarks[0].TrustMark)
	}
}

// TestResolveIssuerResponseCapsExpiryToTrustMark confirms a trust
// mark's own earlier ExpiresAt lowers the response's "exp" below what
// resolved.ExpiresAt alone would give (§8.3.2's own "MUST be the
// minimum of the exp value of the Trust Chain... as well as any Trust
// Mark included in the response").
func TestResolveIssuerResponseCapsExpiryToTrustMark(t *testing.T) {
	f := setupThreeLevelFederation(t)
	resolved := resolveThreeLevelLeaf(t, f)

	key := generateKey(t)
	issuer, err := federation.NewResolveIssuer(federation.ResolveIssueConfig{EntityID: "https://resolver.example.org"},
		federation.ResolveIssueDependencies{Signer: key, Algorithm: fapi.ES256, KeyID: "resolver-key", Clock: fixedClock{now: f.now}})
	if err != nil {
		t.Fatalf("NewResolveIssuer: %v", err)
	}

	// resolved.ExpiresAt is f.now+1h (every fixture statement has a
	// 1-hour lifetime); this trust mark's own exp is earlier still.
	earlyExpiry := f.now.Add(time.Minute)
	trustMarks := []federation.VerifiedTrustMark{{
		RawTrustMark: intfed.RawTrustMark{TrustMarkType: testTrustMarkType, TrustMark: "placeholder"},
		ExpiresAt:    earlyExpiry,
	}}
	token, err := issuer.Response(resolved, []string{f.taID}, nil, trustMarks)
	if err != nil {
		t.Fatalf("Response: %v", err)
	}
	resp, err := intfed.ParseResolveResponse(token)
	if err != nil {
		t.Fatalf("ParseResolveResponse: %v", err)
	}
	claims, err := resp.Verify(&key.PublicKey, intfed.ResolveResponseVerifyPolicy{
		ExpectedIssuer: "https://resolver.example.org", ExpectedSubject: f.leID,
		Algorithm: fapi.ES256, Now: f.now,
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	// The response's own "exp" is JSON-encoded as a whole-second Unix
	// timestamp (§8.3.2's "iat"/"exp" shape), so compare at that same
	// precision rather than requiring an exact time.Time match.
	if claims.ExpiresAt.Unix() != earlyExpiry.Unix() {
		t.Errorf("ExpiresAt = %v, want %v (the trust mark's own earlier expiry)", claims.ExpiresAt, earlyExpiry)
	}
}

func TestResolveIssuerResponseRejectsWrongTrustAnchor(t *testing.T) {
	f := setupThreeLevelFederation(t)
	resolved := resolveThreeLevelLeaf(t, f)

	issuer, err := federation.NewResolveIssuer(validResolveIssueConfig(), federation.ResolveIssueDependencies{
		Signer: generateKey(t), Algorithm: fapi.ES256, KeyID: "resolver-key",
		Clock: fixedClock{now: f.now.Add(time.Minute)},
	})
	if err != nil {
		t.Fatalf("NewResolveIssuer: %v", err)
	}
	if _, err := issuer.Response(resolved, []string{"https://not-the-actual-anchor.example.org"}, nil, nil); err == nil {
		t.Fatalf("Response(wrong trust anchor) = nil error, want error")
	}
}

func TestResolveIssuerResponseRejectsExpiredChain(t *testing.T) {
	f := setupThreeLevelFederation(t)
	resolved := resolveThreeLevelLeaf(t, f)

	issuer, err := federation.NewResolveIssuer(validResolveIssueConfig(), federation.ResolveIssueDependencies{
		Signer: generateKey(t), Algorithm: fapi.ES256, KeyID: "resolver-key",
		// Every statement in the fixture was issued at f.now with a
		// 1-hour lifetime; answering 2 hours later means resolved's own
		// ExpiresAt has already passed.
		Clock: fixedClock{now: f.now.Add(2 * time.Hour)},
	})
	if err != nil {
		t.Fatalf("NewResolveIssuer: %v", err)
	}
	if _, err := issuer.Response(resolved, []string{f.taID}, nil, nil); err == nil {
		t.Fatalf("Response(expired chain) = nil error, want error")
	}
}

func TestResolveIssuerResponseRejectsNoTokens(t *testing.T) {
	issuer, err := federation.NewResolveIssuer(validResolveIssueConfig(), validResolveIssueDependencies(t))
	if err != nil {
		t.Fatalf("NewResolveIssuer: %v", err)
	}
	resolved := federation.ResolvedEntity{
		EntityID: "https://op.example.org", TrustAnchor: "https://ta.example.org",
		Metadata:  map[string]json.RawMessage{"openid_provider": json.RawMessage(`{}`)},
		ExpiresAt: time.Now().Add(time.Hour),
	}
	if _, err := issuer.Response(resolved, []string{"https://ta.example.org"}, nil, nil); err == nil {
		t.Fatalf("Response(no tokens) = nil error, want error")
	}
}

func TestResolveRequestFromHTTP(t *testing.T) {
	r := httptest.NewRequest("GET", "https://resolver.example.org/resolve?sub=https%3A%2F%2Fop.example.org&trust_anchor=https%3A%2F%2Fta1.example.org&trust_anchor=https%3A%2F%2Fta2.example.org&entity_type=openid_provider", nil)
	subject, trustAnchors, entityTypes, err := federation.ResolveRequestFromHTTP(r)
	if err != nil {
		t.Fatalf("ResolveRequestFromHTTP: %v", err)
	}
	if subject != "https://op.example.org" {
		t.Errorf("subject = %q", subject)
	}
	if len(trustAnchors) != 2 || trustAnchors[0] != "https://ta1.example.org" || trustAnchors[1] != "https://ta2.example.org" {
		t.Errorf("trustAnchors = %v, want both repeated values preserved", trustAnchors)
	}
	if len(entityTypes) != 1 || entityTypes[0] != "openid_provider" {
		t.Errorf("entityTypes = %v", entityTypes)
	}
}

func TestResolveRequestFromHTTPRequiresFields(t *testing.T) {
	cases := map[string]string{
		"no sub":          "https://resolver.example.org/resolve?trust_anchor=https%3A%2F%2Fta.example.org",
		"invalid sub":     "https://resolver.example.org/resolve?sub=not-a-url&trust_anchor=https%3A%2F%2Fta.example.org",
		"no trust anchor": "https://resolver.example.org/resolve?sub=https%3A%2F%2Fop.example.org",
	}
	for name, target := range cases {
		t.Run(name, func(t *testing.T) {
			r := httptest.NewRequest("GET", target, nil)
			if _, _, _, err := federation.ResolveRequestFromHTTP(r); err == nil {
				t.Fatalf("ResolveRequestFromHTTP(%s) = nil error, want error", name)
			}
		})
	}
}
