package federation_test

// This file deliberately doesn't import internal/federation: it builds
// and resolves a federation through the federation package's own names
// only, the way code outside this module has to.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/federation"
)

func TestPublicTypesBuildAndResolvePolicy(t *testing.T) {
	now := time.Now()
	taKey, leKey := generateKey(t), generateKey(t)
	taJWKS, leJWKS := jwksFor(t, "ta", taKey), jwksFor(t, "le", leKey)

	taMux, leMux := http.NewServeMux(), http.NewServeMux()
	taServer, leServer := httptest.NewTLSServer(taMux), httptest.NewTLSServer(leMux)
	t.Cleanup(taServer.Close)
	t.Cleanup(leServer.Close)
	taID, leID := taServer.URL, leServer.URL

	taSelf, err := federation.NewSelfIssuer(federation.SelfIssueConfig{EntityID: taID, Lifetime: time.Hour},
		federation.SelfIssueDependencies{Signer: taKey, Algorithm: fapi.ES256, KeyID: "ta", JWKS: taJWKS, Clock: fixedClock{now: now}})
	if err != nil {
		t.Fatalf("NewSelfIssuer(ta): %v", err)
	}
	taConfig, err := taSelf.EntityConfiguration(federationEntityMetadata(t, taID+"/fetch"))
	if err != nil {
		t.Fatalf("EntityConfiguration(ta): %v", err)
	}
	subordinates, err := federation.NewSubordinateIssuer(federation.SubordinateIssueConfig{EntityID: taID, Lifetime: time.Hour},
		federation.SubordinateIssueDependencies{Signer: taKey, Algorithm: fapi.ES256, KeyID: "ta", Clock: fixedClock{now: now}})
	if err != nil {
		t.Fatalf("NewSubordinateIssuer: %v", err)
	}
	aboutLE, err := subordinates.SubordinateStatement(federation.SubordinateStatementParams{
		Subject: leID, JWKS: leJWKS, SourceEndpoint: taID + "/fetch",
		MetadataPolicy: federation.MetadataPolicy{
			"openid_relying_party": {"grant_types": federation.PolicyOperators{
				"subset_of": json.RawMessage(`["authorization_code"]`),
			}},
		},
		Constraints: &federation.Constraints{
			NamingConstraints: &federation.NamingConstraints{Permitted: []string{"127.0.0.1"}},
		},
	})
	if err != nil {
		t.Fatalf("SubordinateStatement: %v", err)
	}

	leSelf, err := federation.NewSelfIssuer(federation.SelfIssueConfig{EntityID: leID, AuthorityHints: []string{taID}, Lifetime: time.Hour},
		federation.SelfIssueDependencies{Signer: leKey, Algorithm: fapi.ES256, KeyID: "le", JWKS: leJWKS, Clock: fixedClock{now: now}})
	if err != nil {
		t.Fatalf("NewSelfIssuer(le): %v", err)
	}
	leConfig, err := leSelf.EntityConfiguration(map[string]json.RawMessage{
		"openid_relying_party": json.RawMessage(`{"grant_types":["authorization_code","client_credentials"]}`),
	})
	if err != nil {
		t.Fatalf("EntityConfiguration(le): %v", err)
	}

	taMux.HandleFunc("/.well-known/openid-federation", serveStatement(taConfig))
	taMux.HandleFunc("/fetch", serveFetch(map[string]string{leID: aboutLE}))
	leMux.HandleFunc("/.well-known/openid-federation", serveStatement(leConfig))

	r, err := federation.NewResolver(federation.Config{
		TrustAnchors: []federation.TrustAnchor{{EntityID: taID, JWKS: taJWKS}},
		Limits:       federation.Limits{MaxPathLength: 5, MaxAuthorityHints: 5, MaxStatementLifetime: 2 * time.Hour, MaxClockSkew: 5 * time.Second},
	}, federation.Dependencies{HTTP: fetcherFor(t, taServer, leServer), Clock: fixedClock{now: now}})
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	resolved, err := r.Resolve(context.Background(), leID)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	var rp struct {
		GrantTypes []string `json:"grant_types"`
	}
	if err := json.Unmarshal(resolved.Metadata["openid_relying_party"], &rp); err != nil {
		t.Fatalf("unmarshal resolved metadata: %v", err)
	}
	if len(rp.GrantTypes) != 1 || rp.GrantTypes[0] != "authorization_code" {
		t.Fatalf("resolved grant_types = %v, want the policy's subset [authorization_code]", rp.GrantTypes)
	}
}

func TestPublicTrustMarkStatusConstants(t *testing.T) {
	i, err := federation.NewTrustMarkIssuer(federation.TrustMarkIssueConfig{EntityID: "https://issuer.example.org"},
		federation.TrustMarkIssueDependencies{Signer: generateKey(t), Algorithm: fapi.ES256, KeyID: "k", Clock: fixedClock{now: time.Now()}})
	if err != nil {
		t.Fatalf("NewTrustMarkIssuer: %v", err)
	}
	for _, status := range []federation.TrustMarkStatus{
		federation.TrustMarkStatusActive, federation.TrustMarkStatusExpired,
		federation.TrustMarkStatusRevoked, federation.TrustMarkStatusInvalid,
	} {
		if _, err := i.StatusResponse(federation.StatusResponseParams{TrustMark: "a.b.c", Status: status}); err != nil {
			t.Errorf("StatusResponse(%s): %v", status, err)
		}
	}
}

// TestEntityConfigurationPublishesVerifiableTrustMark issues a Trust Mark
// with TrustMarkIssuer, publishes it in the subject's Entity
// Configuration via SelfIssuer, and verifies it after resolution — the
// whole Trust Mark lifecycle through public API only.
func TestEntityConfigurationPublishesVerifiableTrustMark(t *testing.T) {
	const markType = "https://federation.example.org/marks/loa-high"
	now := time.Now()
	taKey, leKey := generateKey(t), generateKey(t)
	taJWKS, leJWKS := jwksFor(t, "ta", taKey), jwksFor(t, "le", leKey)
	taMux, leMux := http.NewServeMux(), http.NewServeMux()
	taServer, leServer := httptest.NewTLSServer(taMux), httptest.NewTLSServer(leMux)
	t.Cleanup(taServer.Close)
	t.Cleanup(leServer.Close)
	taID, leID := taServer.URL, leServer.URL
	clock := fixedClock{now: now}

	taSelf, err := federation.NewSelfIssuer(federation.SelfIssueConfig{
		EntityID: taID, Lifetime: time.Hour, TrustMarkIssuers: map[string][]string{markType: {taID}},
	}, federation.SelfIssueDependencies{Signer: taKey, Algorithm: fapi.ES256, KeyID: "ta", JWKS: taJWKS, Clock: clock})
	if err != nil {
		t.Fatalf("NewSelfIssuer(ta): %v", err)
	}
	taConfig, err := taSelf.EntityConfiguration(federationEntityMetadata(t, taID+"/fetch"))
	if err != nil {
		t.Fatalf("EntityConfiguration(ta): %v", err)
	}
	subordinates, err := federation.NewSubordinateIssuer(federation.SubordinateIssueConfig{EntityID: taID, Lifetime: time.Hour},
		federation.SubordinateIssueDependencies{Signer: taKey, Algorithm: fapi.ES256, KeyID: "ta", Clock: clock})
	if err != nil {
		t.Fatalf("NewSubordinateIssuer: %v", err)
	}
	aboutLE, err := subordinates.SubordinateStatement(federation.SubordinateStatementParams{Subject: leID, JWKS: leJWKS, SourceEndpoint: taID + "/fetch"})
	if err != nil {
		t.Fatalf("SubordinateStatement: %v", err)
	}
	marks, err := federation.NewTrustMarkIssuer(federation.TrustMarkIssueConfig{EntityID: taID},
		federation.TrustMarkIssueDependencies{Signer: taKey, Algorithm: fapi.ES256, KeyID: "ta", Clock: clock})
	if err != nil {
		t.Fatalf("NewTrustMarkIssuer: %v", err)
	}
	markJWT, err := marks.TrustMark(federation.TrustMarkParams{Subject: leID, TrustMarkType: markType, Lifetime: time.Hour})
	if err != nil {
		t.Fatalf("TrustMark: %v", err)
	}

	leSelf, err := federation.NewSelfIssuer(federation.SelfIssueConfig{EntityID: leID, AuthorityHints: []string{taID}, Lifetime: time.Hour},
		federation.SelfIssueDependencies{Signer: leKey, Algorithm: fapi.ES256, KeyID: "le", JWKS: leJWKS, Clock: clock})
	if err != nil {
		t.Fatalf("NewSelfIssuer(le): %v", err)
	}
	leConfig, err := leSelf.EntityConfiguration(map[string]json.RawMessage{
		"openid_relying_party": json.RawMessage(`{}`),
	}, federation.RawTrustMark{TrustMarkType: markType, TrustMark: markJWT})
	if err != nil {
		t.Fatalf("EntityConfiguration(le): %v", err)
	}

	taMux.HandleFunc("/.well-known/openid-federation", serveStatement(taConfig))
	taMux.HandleFunc("/fetch", serveFetch(map[string]string{leID: aboutLE}))
	leMux.HandleFunc("/.well-known/openid-federation", serveStatement(leConfig))

	r, err := federation.NewResolver(federation.Config{
		TrustAnchors: []federation.TrustAnchor{{EntityID: taID, JWKS: taJWKS}},
		Limits:       federation.Limits{MaxPathLength: 5, MaxAuthorityHints: 5, MaxStatementLifetime: 2 * time.Hour, MaxClockSkew: 5 * time.Second},
	}, federation.Dependencies{HTTP: fetcherFor(t, taServer, leServer), Clock: clock})
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	resolved, err := r.Resolve(context.Background(), leID)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(resolved.TrustMarks) != 1 {
		t.Fatalf("TrustMarks = %v, want the published mark", resolved.TrustMarks)
	}
	claims, err := r.VerifyTrustMark(context.Background(), leID, resolved.TrustMarks[0], federation.RequireFederationAccreditation)
	if err != nil {
		t.Fatalf("VerifyTrustMark: %v", err)
	}
	if claims.Issuer != taID || claims.TrustMarkType != markType {
		t.Fatalf("claims = %+v", claims)
	}
}
