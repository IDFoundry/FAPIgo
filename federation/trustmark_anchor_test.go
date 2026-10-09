package federation_test

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/federation"
	intfed "github.com/idfoundry/fapigo/internal/federation"
)

// twoFederations is two Trust Anchors, X and Y, configured on one
// Resolver, a Trust Mark Issuer I, and a subject S that is a member of
// Y only and declares a Trust Mark I issued about it.
type twoFederations struct {
	xID, yID, iID, sID string
	resolver           *federation.Resolver
}

// setupTwoFederations builds the fixture. issuerHints are I's authority
// hints by name ("x", "y"); xAccredits and yAccredits are the issuers
// (by name, "i") each Trust Anchor's "trust_mark_issuers" lists for the
// test Trust Mark type. An empty list means anyone may issue it
// (OpenID Federation 1.0 §3.1.2), so a federation accrediting no one
// else lists only itself.
func setupTwoFederations(t *testing.T, issuerHints, xAccredits, yAccredits []string) *twoFederations {
	t.Helper()
	now := time.Now()
	type entity struct {
		key    *ecdsa.PrivateKey
		jwks   json.RawMessage
		mux    *http.ServeMux
		server *httptest.Server
		id     string
	}
	ents := map[string]*entity{}
	for _, name := range []string{"x", "y", "i", "s"} {
		e := &entity{key: generateKey(t), mux: http.NewServeMux()}
		e.jwks = jwksFor(t, name, e.key)
		e.server = httptest.NewTLSServer(e.mux)
		t.Cleanup(e.server.Close)
		e.id = e.server.URL
		ents[name] = e
	}
	ids := func(names []string) []string {
		out := []string{}
		for _, n := range names {
			out = append(out, ents[n].id)
		}
		return out
	}
	sign := func(p intfed.CreateParams) string {
		t.Helper()
		token, err := intfed.Create(p)
		if err != nil {
			t.Fatalf("intfed.Create: %v", err)
		}
		return token
	}
	subordinate := func(sup, sub string) string {
		return sign(intfed.CreateParams{
			Signer: ents[sup].key, Algorithm: fapi.ES256, KeyID: sup,
			Issuer: ents[sup].id, Subject: ents[sub].id, Now: now, Lifetime: time.Hour, JWKS: ents[sub].jwks,
		})
	}

	// The Trust Anchors, each listing its own accredited issuers and
	// serving Subordinate Statements for whoever names it.
	fetchBy := map[string]map[string]string{"x": {}, "y": {}}
	for _, sup := range issuerHints {
		fetchBy[sup][ents["i"].id] = subordinate(sup, "i")
	}
	fetchBy["y"][ents["s"].id] = subordinate("y", "s")
	for name, accredits := range map[string][]string{"x": xAccredits, "y": yAccredits} {
		e := ents[name]
		e.mux.HandleFunc("/.well-known/openid-federation", serveStatement(sign(intfed.CreateParams{
			Signer: e.key, Algorithm: fapi.ES256, KeyID: name,
			Issuer: e.id, Subject: e.id, Now: now, Lifetime: time.Hour, JWKS: e.jwks,
			Metadata:         federationEntityMetadata(t, e.id+"/fetch"),
			TrustMarkIssuers: map[string][]string{testTrustMarkType: ids(accredits)},
		})))
		e.mux.HandleFunc("/fetch", serveFetch(fetchBy[name]))
	}

	// The issuer, a member of whichever federations issuerHints names.
	i := ents["i"]
	i.mux.HandleFunc("/.well-known/openid-federation", serveStatement(sign(intfed.CreateParams{
		Signer: i.key, Algorithm: fapi.ES256, KeyID: "i",
		Issuer: i.id, Subject: i.id, Now: now, Lifetime: time.Hour, JWKS: i.jwks,
		AuthorityHints: ids(issuerHints),
	})))

	// The subject, a member of Y only, with a Trust Mark from I.
	s := ents["s"]
	mark := signTrustMark(t, i.key, "i", map[string]any{
		"iss": i.id, "sub": s.id, "trust_mark_type": testTrustMarkType,
		"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
	})
	s.mux.HandleFunc("/.well-known/openid-federation", serveStatement(sign(intfed.CreateParams{
		Signer: s.key, Algorithm: fapi.ES256, KeyID: "s",
		Issuer: s.id, Subject: s.id, Now: now, Lifetime: time.Hour, JWKS: s.jwks,
		AuthorityHints: []string{ents["y"].id},
		TrustMarks:     []intfed.RawTrustMark{{TrustMarkType: testTrustMarkType, TrustMark: mark}},
	})))

	resolver, err := federation.NewResolver(federation.Config{
		TrustAnchors: []federation.TrustAnchor{
			{EntityID: ents["x"].id, JWKS: ents["x"].jwks},
			{EntityID: ents["y"].id, JWKS: ents["y"].jwks},
		},
		Limits: federation.Limits{MaxPathLength: 3, MaxAuthorityHints: 3, MaxStatementLifetime: 2 * time.Hour, MaxClockSkew: 5 * time.Second},
	}, federation.Dependencies{
		HTTP:  fetcherFor(t, ents["x"].server, ents["y"].server, ents["i"].server, ents["s"].server),
		Clock: fixedClock{now: now},
	})
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	return &twoFederations{xID: ents["x"].id, yID: ents["y"].id, iID: i.id, sID: s.id, resolver: resolver}
}

// TestVerifyTrustMarkAccreditationComesFromTheSubjectsTrustAnchor: a
// Trust Mark's accreditation is the federation the subject belongs to.
// An issuer accredited only by another Trust Anchor configured on the
// same Resolver doesn't pass RequireFederationAccreditation for the
// subject, whether or not the issuer is also a member of the subject's
// federation.
func TestVerifyTrustMarkAccreditationComesFromTheSubjectsTrustAnchor(t *testing.T) {
	for _, tc := range []struct {
		name                   string
		issuerHints            []string
		xAccredits, yAccredits []string
		wantErr                string
	}{
		{"issuer only in the other federation", []string{"x"}, []string{"i"}, []string{"y"}, "trust mark issuer"},
		{"issuer in both, accredited only by the other", []string{"x", "y"}, []string{"i"}, []string{"y"}, "does not accredit"},
		{"issuer in both, accredited by the subject's", []string{"x", "y"}, nil, []string{"i"}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := setupTwoFederations(t, tc.issuerHints, tc.xAccredits, tc.yAccredits)
			subject, err := f.resolver.Resolve(context.Background(), f.sID)
			if err != nil {
				t.Fatalf("Resolve(subject): %v", err)
			}
			if subject.TrustAnchor != f.yID {
				t.Fatalf("subject resolved through %q, want Y %q", subject.TrustAnchor, f.yID)
			}
			claims, err := f.resolver.VerifyTrustMark(context.Background(), subject, subject.TrustMarks[0], federation.RequireFederationAccreditation)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("VerifyTrustMark: %v, want accepted", err)
				}
				if claims.Issuer != f.iID {
					t.Fatalf("Issuer = %q, want %q", claims.Issuer, f.iID)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("VerifyTrustMark = %v, want an error containing %q", err, tc.wantErr)
			}
		})
	}
}

// TestVerifyTrustMarkRefusesAnUnconfiguredTrustAnchor: the subject must
// have been resolved by this Resolver, through one of its Trust Anchors.
func TestVerifyTrustMarkRefusesAnUnconfiguredTrustAnchor(t *testing.T) {
	f := setupTwoFederations(t, []string{"y"}, nil, []string{"i"})
	subject, err := f.resolver.Resolve(context.Background(), f.sID)
	if err != nil {
		t.Fatalf("Resolve(subject): %v", err)
	}
	subject.TrustAnchor = "https://elsewhere.example"
	if _, err := f.resolver.VerifyTrustMark(context.Background(), subject, subject.TrustMarks[0], federation.RequireFederationAccreditation); err == nil || !strings.Contains(err.Error(), "not one of this resolver's trust anchors") {
		t.Fatalf("VerifyTrustMark(unconfigured trust anchor) = %v, want refused", err)
	}
}
