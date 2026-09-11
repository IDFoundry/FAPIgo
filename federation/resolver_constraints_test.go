package federation_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/fapihttp"
	"github.com/idfoundry/fapigo/federation"
	intfed "github.com/idfoundry/fapigo/internal/federation"
)

// loopbackHost is every entity's own host in this file's fixture:
// httptest.NewTLSServer always binds to 127.0.0.1, so naming_constraints
// tests below match against that fixed value exactly (an exact,
// non-dot-prefixed constraint) rather than a dot-prefixed subtree — a
// loopback address has no subdomains to test that shape against; the
// subtree-matching logic itself is covered by the internal
// domainNameConstraintMatches unit tests instead.
const loopbackHost = "127.0.0.1"

// constrainedFederation is a minimal two-level federation (TA -> LE)
// purpose-built for naming_constraints/allowed_entity_types tests: TA's
// own Subordinate Statement about LE carries constraints, set by the
// caller. Two levels is enough to exercise Resolve's constraint
// enforcement directly, without threeLevelFederation's extra
// Intermediate hop and metadata_policy machinery, which these tests
// don't need.
type constrainedFederation struct {
	taID, leID string
	taJWKS     json.RawMessage
	fetcher    *fapihttp.Client
	now        time.Time
}

// setupConstrainedFederation builds the fixture, embedding constraints
// (nil means TA's statement about LE carries no "constraints" claim at
// all) in TA's own Subordinate Statement about LE. leMetadata, if
// non-nil, overrides LE's own declared metadata (default: a minimal
// openid_relying_party object) — used by the allowed_entity_types tests
// to give LE more than one metadata Entity Type to filter between.
func setupConstrainedFederation(t *testing.T, constraints *intfed.Constraints, leMetadata map[string]json.RawMessage) *constrainedFederation {
	t.Helper()
	now := time.Now()

	taKey, leKey := generateKey(t), generateKey(t)
	taJWKS, leJWKS := jwksFor(t, "ta", taKey), jwksFor(t, "le", leKey)

	taMux := http.NewServeMux()
	taServer := httptest.NewTLSServer(taMux)
	t.Cleanup(taServer.Close)
	leMux := http.NewServeMux()
	leServer := httptest.NewTLSServer(leMux)
	t.Cleanup(leServer.Close)

	taID, leID := taServer.URL, leServer.URL

	sign := func(p intfed.CreateParams) string {
		t.Helper()
		token, err := intfed.Create(p)
		if err != nil {
			t.Fatalf("intfed.Create: %v", err)
		}
		return token
	}

	taConfig := sign(intfed.CreateParams{
		Signer: taKey, Algorithm: fapi.ES256, KeyID: "ta",
		Issuer: taID, Subject: taID, Now: now, Lifetime: time.Hour, JWKS: taJWKS,
		Metadata: federationEntityMetadata(t, taID+"/fetch"),
	})
	taAboutLE := sign(intfed.CreateParams{
		Signer: taKey, Algorithm: fapi.ES256, KeyID: "ta",
		Issuer: taID, Subject: leID, Now: now, Lifetime: time.Hour, JWKS: leJWKS,
		Constraints: constraints,
	})
	if leMetadata == nil {
		leMetadata = map[string]json.RawMessage{
			"openid_relying_party": json.RawMessage(`{"redirect_uris":["` + leID + `/cb"],"response_types":["code"]}`),
		}
	}
	leConfig := sign(intfed.CreateParams{
		Signer: leKey, Algorithm: fapi.ES256, KeyID: "le",
		Issuer: leID, Subject: leID, Now: now, Lifetime: time.Hour, JWKS: leJWKS,
		AuthorityHints: []string{taID},
		Metadata:       leMetadata,
	})

	taMux.HandleFunc("/.well-known/openid-federation", serveStatement(taConfig))
	taMux.HandleFunc("/fetch", serveFetch(map[string]string{leID: taAboutLE}))
	leMux.HandleFunc("/.well-known/openid-federation", serveStatement(leConfig))

	pool := x509.NewCertPool()
	pool.AddCert(taServer.Certificate())
	pool.AddCert(leServer.Certificate())
	httpClient := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}
	fetcher, err := fapihttp.New(httpClient, fapihttp.Config{
		MaxResponseBytes: 1 << 16, RequestTimeout: 5 * time.Second, MaxRedirects: 1,
		AllowLoopbackHTTP: true,
	})
	if err != nil {
		t.Fatalf("fapihttp.New: %v", err)
	}

	return &constrainedFederation{taID: taID, leID: leID, taJWKS: taJWKS, fetcher: fetcher, now: now}
}

func (f *constrainedFederation) newResolver(t *testing.T) *federation.Resolver {
	t.Helper()
	r, err := federation.NewResolver(federation.Config{
		TrustAnchors: []federation.TrustAnchor{{EntityID: f.taID, JWKS: f.taJWKS}},
		Limits: federation.Limits{
			MaxPathLength: 5, MaxStatementLifetime: 2 * time.Hour, MaxClockSkew: 5 * time.Second,
		},
	}, federation.Dependencies{HTTP: f.fetcher, Clock: fixedClock{now: f.now}})
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	return r
}

func TestResolveEnforcesNamingConstraintsExcluded(t *testing.T) {
	f := setupConstrainedFederation(t, &intfed.Constraints{
		NamingConstraints: &intfed.NamingConstraints{Excluded: []string{loopbackHost}},
	}, nil)
	r := f.newResolver(t)
	if _, err := r.Resolve(context.Background(), f.leID); err == nil {
		t.Fatalf("Resolve(excluded host) = nil error, want error")
	}
}

func TestResolveEnforcesNamingConstraintsPermittedMismatch(t *testing.T) {
	f := setupConstrainedFederation(t, &intfed.Constraints{
		NamingConstraints: &intfed.NamingConstraints{Permitted: []string{"not-this-host.example.org"}},
	}, nil)
	r := f.newResolver(t)
	if _, err := r.Resolve(context.Background(), f.leID); err == nil {
		t.Fatalf("Resolve(permitted mismatch) = nil error, want error")
	}
}

func TestResolveAcceptsNamingConstraintsPermittedMatch(t *testing.T) {
	f := setupConstrainedFederation(t, &intfed.Constraints{
		NamingConstraints: &intfed.NamingConstraints{Permitted: []string{loopbackHost}},
	}, nil)
	r := f.newResolver(t)
	if _, err := r.Resolve(context.Background(), f.leID); err != nil {
		t.Fatalf("Resolve(permitted match): %v, want nil error", err)
	}
}

// Excluded always wins, regardless of what the permitted list says —
// OpenID Federation 1.0 §6.2.2: "Any name matching a restriction in the
// excluded list is invalid, regardless of the information appearing in
// the permitted list."
func TestResolveNamingConstraintsExcludedOverridesPermitted(t *testing.T) {
	f := setupConstrainedFederation(t, &intfed.Constraints{
		NamingConstraints: &intfed.NamingConstraints{
			Permitted: []string{loopbackHost},
			Excluded:  []string{loopbackHost},
		},
	}, nil)
	r := f.newResolver(t)
	if _, err := r.Resolve(context.Background(), f.leID); err == nil {
		t.Fatalf("Resolve(excluded overrides permitted) = nil error, want error")
	}
}

func TestResolveAcceptsNoNamingConstraints(t *testing.T) {
	f := setupConstrainedFederation(t, nil, nil)
	r := f.newResolver(t)
	if _, err := r.Resolve(context.Background(), f.leID); err != nil {
		t.Fatalf("Resolve(no constraints): %v, want nil error", err)
	}
}

func TestResolveFiltersDisallowedEntityTypes(t *testing.T) {
	leMetadata := map[string]json.RawMessage{
		"openid_relying_party": json.RawMessage(`{"redirect_uris":["https://rp.example/cb"],"response_types":["code"]}`),
		"openid_provider":      json.RawMessage(`{"issuer":"https://op.example"}`),
	}
	f := setupConstrainedFederation(t, &intfed.Constraints{AllowedEntityTypes: []string{"openid_relying_party"}}, leMetadata)
	r := f.newResolver(t)
	result, err := r.Resolve(context.Background(), f.leID)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if _, ok := result.Metadata["openid_relying_party"]; !ok {
		t.Errorf("Metadata missing openid_relying_party, want it to survive (in allowed_entity_types)")
	}
	if _, ok := result.Metadata["openid_provider"]; ok {
		t.Errorf("Metadata contains openid_provider, want it filtered out (not in allowed_entity_types)")
	}
}

func TestResolveKeepsFederationEntityMetadataDespiteAllowedEntityTypes(t *testing.T) {
	leMetadata := map[string]json.RawMessage{
		"openid_relying_party": json.RawMessage(`{"redirect_uris":["https://rp.example/cb"],"response_types":["code"]}`),
		"federation_entity":    json.RawMessage(`{"organization_name":"Example RP"}`),
	}
	f := setupConstrainedFederation(t, &intfed.Constraints{AllowedEntityTypes: []string{"openid_relying_party"}}, leMetadata)
	r := f.newResolver(t)
	result, err := r.Resolve(context.Background(), f.leID)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if _, ok := result.Metadata["federation_entity"]; !ok {
		t.Errorf("Metadata missing federation_entity, want it always kept regardless of allowed_entity_types")
	}
}

func TestResolveAllowsAnyEntityTypeWithoutAllowedEntityTypesConstraint(t *testing.T) {
	leMetadata := map[string]json.RawMessage{
		"openid_relying_party": json.RawMessage(`{"redirect_uris":["https://rp.example/cb"],"response_types":["code"]}`),
		"openid_provider":      json.RawMessage(`{"issuer":"https://op.example"}`),
	}
	f := setupConstrainedFederation(t, nil, leMetadata)
	r := f.newResolver(t)
	result, err := r.Resolve(context.Background(), f.leID)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if _, ok := result.Metadata["openid_provider"]; !ok {
		t.Errorf("Metadata missing openid_provider, want it kept (no allowed_entity_types constraint)")
	}
}

// setupThreeLevelConstrainedFederation mirrors setupConstrainedFederation,
// but with an Intermediate (I1) between TA and LE, and intermediateConstraints
// embedded in I1's own Subordinate Statement about LE — exercising
// Resolve's constraint collection in the "superior is an Intermediate,
// not yet a Trust Anchor" branch (intfed.Statement.ClaimedConstraints,
// an unverified read deferred until the whole chain is proven valid),
// which setupConstrainedFederation's own two-level TA -> LE topology
// never reaches (there, the constraint always comes from the
// TrustAnchor-terminal branch's already-verified aboveClaims instead).
func setupThreeLevelConstrainedFederation(t *testing.T, taConstraints, intermediateConstraints *intfed.Constraints) *constrainedFederation {
	t.Helper()
	now := time.Now()

	taKey, i1Key, leKey := generateKey(t), generateKey(t), generateKey(t)
	taJWKS, i1JWKS, leJWKS := jwksFor(t, "ta", taKey), jwksFor(t, "i1", i1Key), jwksFor(t, "le", leKey)

	taMux := http.NewServeMux()
	taServer := httptest.NewTLSServer(taMux)
	t.Cleanup(taServer.Close)
	i1Mux := http.NewServeMux()
	i1Server := httptest.NewTLSServer(i1Mux)
	t.Cleanup(i1Server.Close)
	leMux := http.NewServeMux()
	leServer := httptest.NewTLSServer(leMux)
	t.Cleanup(leServer.Close)

	taID, i1ID, leID := taServer.URL, i1Server.URL, leServer.URL

	sign := func(p intfed.CreateParams) string {
		t.Helper()
		token, err := intfed.Create(p)
		if err != nil {
			t.Fatalf("intfed.Create: %v", err)
		}
		return token
	}

	taConfig := sign(intfed.CreateParams{
		Signer: taKey, Algorithm: fapi.ES256, KeyID: "ta",
		Issuer: taID, Subject: taID, Now: now, Lifetime: time.Hour, JWKS: taJWKS,
		Metadata: federationEntityMetadata(t, taID+"/fetch"),
	})
	taAboutI1 := sign(intfed.CreateParams{
		Signer: taKey, Algorithm: fapi.ES256, KeyID: "ta",
		Issuer: taID, Subject: i1ID, Now: now, Lifetime: time.Hour, JWKS: i1JWKS,
		Constraints: taConstraints,
	})
	i1Config := sign(intfed.CreateParams{
		Signer: i1Key, Algorithm: fapi.ES256, KeyID: "i1",
		Issuer: i1ID, Subject: i1ID, Now: now, Lifetime: time.Hour, JWKS: i1JWKS,
		AuthorityHints: []string{taID},
		Metadata:       federationEntityMetadata(t, i1ID+"/fetch"),
	})
	i1AboutLE := sign(intfed.CreateParams{
		Signer: i1Key, Algorithm: fapi.ES256, KeyID: "i1",
		Issuer: i1ID, Subject: leID, Now: now, Lifetime: time.Hour, JWKS: leJWKS,
		Constraints: intermediateConstraints,
	})
	leConfig := sign(intfed.CreateParams{
		Signer: leKey, Algorithm: fapi.ES256, KeyID: "le",
		Issuer: leID, Subject: leID, Now: now, Lifetime: time.Hour, JWKS: leJWKS,
		AuthorityHints: []string{i1ID},
		Metadata: map[string]json.RawMessage{
			"openid_relying_party": json.RawMessage(`{"redirect_uris":["` + leID + `/cb"],"response_types":["code"]}`),
		},
	})

	taMux.HandleFunc("/.well-known/openid-federation", serveStatement(taConfig))
	taMux.HandleFunc("/fetch", serveFetch(map[string]string{i1ID: taAboutI1}))
	i1Mux.HandleFunc("/.well-known/openid-federation", serveStatement(i1Config))
	i1Mux.HandleFunc("/fetch", serveFetch(map[string]string{leID: i1AboutLE}))
	leMux.HandleFunc("/.well-known/openid-federation", serveStatement(leConfig))

	pool := x509.NewCertPool()
	pool.AddCert(taServer.Certificate())
	pool.AddCert(i1Server.Certificate())
	pool.AddCert(leServer.Certificate())
	httpClient := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}
	fetcher, err := fapihttp.New(httpClient, fapihttp.Config{
		MaxResponseBytes: 1 << 16, RequestTimeout: 5 * time.Second, MaxRedirects: 1,
		AllowLoopbackHTTP: true,
	})
	if err != nil {
		t.Fatalf("fapihttp.New: %v", err)
	}

	return &constrainedFederation{taID: taID, leID: leID, taJWKS: taJWKS, fetcher: fetcher, now: now}
}

func TestResolveEnforcesIntermediateNamingConstraints(t *testing.T) {
	f := setupThreeLevelConstrainedFederation(t, nil, &intfed.Constraints{
		NamingConstraints: &intfed.NamingConstraints{Excluded: []string{loopbackHost}},
	})
	r := f.newResolver(t)
	if _, err := r.Resolve(context.Background(), f.leID); err == nil {
		t.Fatalf("Resolve(intermediate's naming_constraints excludes LE) = nil error, want error")
	}
}

func TestResolveAcceptsIntermediateWithNoConstraints(t *testing.T) {
	f := setupThreeLevelConstrainedFederation(t, nil, nil)
	r := f.newResolver(t)
	if _, err := r.Resolve(context.Background(), f.leID); err != nil {
		t.Fatalf("Resolve(intermediate sets no constraints): %v, want nil error", err)
	}
}

// TestResolveEnforcesMaxPathLengthConstraint proves Resolve wires
// checkMaxPathLengthConstraints into the real chain walk: TA's own
// max_path_length=0 forbids any Intermediate between TA and LE, but
// this fixture's chain (TA -> I1 -> LE) has exactly one (I1).
func TestResolveEnforcesMaxPathLengthConstraint(t *testing.T) {
	f := setupThreeLevelConstrainedFederation(t, &intfed.Constraints{MaxPathLength: 0, HasMaxPathLength: true}, nil)
	r := f.newResolver(t)
	if _, err := r.Resolve(context.Background(), f.leID); err == nil {
		t.Fatalf("Resolve(TA max_path_length=0, 1 actual intermediate) = nil error, want error")
	}
}

func TestResolveAcceptsSatisfiedMaxPathLengthConstraint(t *testing.T) {
	f := setupThreeLevelConstrainedFederation(t, &intfed.Constraints{MaxPathLength: 1, HasMaxPathLength: true}, nil)
	r := f.newResolver(t)
	if _, err := r.Resolve(context.Background(), f.leID); err != nil {
		t.Fatalf("Resolve(TA max_path_length=1, 1 actual intermediate): %v, want nil error", err)
	}
}
