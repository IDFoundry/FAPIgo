package federation_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/fapihttp"
	"github.com/idfoundry/fapigo/federation"
	intfed "github.com/idfoundry/fapigo/internal/federation"
)

// accreditationFederation is a TA -> LE federation whose TA publishes
// trustMarkIssuers, and whose LE declares three Trust Marks of
// testTrustMarkType: one issued by the TA, one LE issued about itself,
// and one the TA issued without a kid header.
type accreditationFederation struct {
	resolver                       *federation.Resolver
	leID, taID                     string
	byTA, selfIssued, withoutKeyID intfed.RawTrustMark
}

// subject resolves the federation's leaf, the subject of its Trust Marks.
func (f accreditationFederation) subject(t *testing.T) federation.ResolvedEntity {
	t.Helper()
	resolved, err := f.resolver.Resolve(context.Background(), f.leID)
	if err != nil {
		t.Fatalf("Resolve(subject): %v", err)
	}
	return resolved
}

func setupAccreditationFederation(t *testing.T, trustMarkIssuers func(taID, leID string) map[string][]string) accreditationFederation {
	t.Helper()
	now := time.Now()
	taKey, leKey := generateKey(t), generateKey(t)
	taJWKS, leJWKS := jwksFor(t, "ta", taKey), jwksFor(t, "le", leKey)

	taMux, leMux := http.NewServeMux(), http.NewServeMux()
	taServer, leServer := httptest.NewTLSServer(taMux), httptest.NewTLSServer(leMux)
	t.Cleanup(taServer.Close)
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
	markClaims := func(iss string) map[string]any {
		return map[string]any{"iss": iss, "sub": leID, "trust_mark_type": testTrustMarkType, "iat": now.Unix(), "exp": now.Add(time.Hour).Unix()}
	}
	f := accreditationFederation{leID: leID, taID: taID}
	f.byTA = intfed.RawTrustMark{TrustMarkType: testTrustMarkType, TrustMark: signTrustMark(t, taKey, "ta", markClaims(taID))}
	f.selfIssued = intfed.RawTrustMark{TrustMarkType: testTrustMarkType, TrustMark: signTrustMark(t, leKey, "le", markClaims(leID))}
	f.withoutKeyID = intfed.RawTrustMark{TrustMarkType: testTrustMarkType, TrustMark: signTrustMark(t, taKey, "", markClaims(taID))}

	taMux.HandleFunc("/.well-known/openid-federation", serveStatement(sign(intfed.CreateParams{
		Signer: taKey, Algorithm: fapi.ES256, KeyID: "ta",
		Issuer: taID, Subject: taID, Now: now, Lifetime: time.Hour, JWKS: taJWKS,
		Metadata:         federationEntityMetadata(t, taID+"/fetch"),
		TrustMarkIssuers: trustMarkIssuers(taID, leID),
	})))
	taMux.HandleFunc("/fetch", serveFetch(map[string]string{leID: sign(intfed.CreateParams{
		Signer: taKey, Algorithm: fapi.ES256, KeyID: "ta",
		Issuer: taID, Subject: leID, Now: now, Lifetime: time.Hour, JWKS: leJWKS,
	})}))
	leMux.HandleFunc("/.well-known/openid-federation", serveStatement(sign(intfed.CreateParams{
		Signer: leKey, Algorithm: fapi.ES256, KeyID: "le",
		Issuer: leID, Subject: leID, Now: now, Lifetime: time.Hour, JWKS: leJWKS,
		AuthorityHints: []string{taID},
		TrustMarks:     []intfed.RawTrustMark{f.byTA, f.selfIssued, f.withoutKeyID},
	})))

	pool := x509.NewCertPool()
	pool.AddCert(taServer.Certificate())
	pool.AddCert(leServer.Certificate())
	fetcher, err := fapihttp.New(&http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}, fapihttp.Config{
		MaxResponseBytes: 1 << 16, RequestTimeout: 5 * time.Second, MaxRedirects: 1, AllowLoopbackHTTP: true,
	})
	if err != nil {
		t.Fatalf("fapihttp.New: %v", err)
	}
	f.resolver, err = federation.NewResolver(federation.Config{
		TrustAnchors: []federation.TrustAnchor{{EntityID: taID, JWKS: taJWKS}},
		Limits:       federation.Limits{MaxPathLength: 5, MaxAuthorityHints: 5, MaxStatementLifetime: 2 * time.Hour, MaxClockSkew: 5 * time.Second},
	}, federation.Dependencies{HTTP: fetcher, Clock: fixedClock{now: now}})
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	return f
}

// TestVerifyTrustMarkAccreditation checks that a federation member —
// here the very entity the mark is about — can't have a self-issued
// Trust Mark accepted under RequireFederationAccreditation unless the
// Trust Anchor accredits it for that type, while the TA-accredited
// issuer's mark is accepted; and that AcceptAnyFederationIssuer keeps
// the unaccredited behaviour available as an explicit choice.
func TestVerifyTrustMarkAccreditation(t *testing.T) {
	ctx := context.Background()
	onlyTA := setupAccreditationFederation(t, func(taID, _ string) map[string][]string {
		return map[string][]string{testTrustMarkType: {taID}}
	})

	if _, err := onlyTA.resolver.VerifyTrustMark(ctx, onlyTA.subject(t), onlyTA.byTA, federation.RequireFederationAccreditation); err != nil {
		t.Fatalf("VerifyTrustMark(accredited issuer): %v", err)
	}
	if _, err := onlyTA.resolver.VerifyTrustMark(ctx, onlyTA.subject(t), onlyTA.selfIssued, federation.RequireFederationAccreditation); err == nil || !strings.Contains(err.Error(), "does not accredit") {
		t.Fatalf("VerifyTrustMark(self-issued, require) = %v, want an accreditation error", err)
	}
	claims, err := onlyTA.resolver.VerifyTrustMark(ctx, onlyTA.subject(t), onlyTA.selfIssued, federation.AcceptAnyFederationIssuer)
	if err != nil || claims.Issuer != onlyTA.leID {
		t.Fatalf("VerifyTrustMark(self-issued, accept any) = %+v, %v; want accepted with the entity itself as issuer", claims, err)
	}

	anyone := setupAccreditationFederation(t, func(string, string) map[string][]string {
		return map[string][]string{testTrustMarkType: {}}
	})
	if _, err := anyone.resolver.VerifyTrustMark(ctx, anyone.subject(t), anyone.selfIssued, federation.RequireFederationAccreditation); err != nil {
		t.Fatalf("VerifyTrustMark(self-issued, type open to anyone): %v", err)
	}

	unlisted := setupAccreditationFederation(t, func(string, string) map[string][]string { return nil })
	if _, err := unlisted.resolver.VerifyTrustMark(ctx, unlisted.subject(t), unlisted.byTA, federation.RequireFederationAccreditation); err == nil || !strings.Contains(err.Error(), "not in trust anchor") {
		t.Fatalf("VerifyTrustMark(type not listed) = %v, want an accreditation error", err)
	}

	if _, err := onlyTA.resolver.VerifyTrustMark(ctx, onlyTA.subject(t), onlyTA.byTA, federation.TrustMarkAccreditation(0)); err == nil {
		t.Fatal("VerifyTrustMark(zero accreditation) = nil error, want the explicit choice required")
	}
}

// TestVerifyTrustMarkRequiresKeyID checks OpenID Federation 1.0 §7's
// requirement that a Trust Mark carry its signing key's kid.
func TestVerifyTrustMarkRequiresKeyID(t *testing.T) {
	f := setupAccreditationFederation(t, func(taID, _ string) map[string][]string {
		return map[string][]string{testTrustMarkType: {taID}}
	})
	_, err := f.resolver.VerifyTrustMark(context.Background(), f.subject(t), f.withoutKeyID, federation.AcceptAnyFederationIssuer)
	if err == nil || !strings.Contains(err.Error(), "no kid") {
		t.Fatalf("VerifyTrustMark(no kid) = %v, want a kid error", err)
	}
}

// TestResolvedEntityExposesTrustMarkIssuers checks that a Trust Anchor's
// trust_mark_issuers reaches ResolvedEntity.
func TestResolvedEntityExposesTrustMarkIssuers(t *testing.T) {
	f := setupAccreditationFederation(t, func(taID, _ string) map[string][]string {
		return map[string][]string{testTrustMarkType: {taID}}
	})
	ta, err := f.resolver.Resolve(context.Background(), f.taID)
	if err != nil {
		t.Fatalf("Resolve(trust anchor): %v", err)
	}
	if got := ta.TrustMarkIssuers[testTrustMarkType]; len(got) != 1 || got[0] != f.taID {
		t.Fatalf("TrustMarkIssuers[%q] = %v, want [%s]", testTrustMarkType, got, f.taID)
	}
}
