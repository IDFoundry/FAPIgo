package federation_test

import (
	"context"
	"crypto/ecdsa"
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
	"github.com/idfoundry/fapigo/internal/jose"
)

const testTrustMarkType = "https://federation.example.org/marks/certified"

// signTrustMark hand-signs a Trust Mark JWT directly via jose.Sign —
// internal/federation exports no Trust Mark creation API (it only ever
// verifies one someone else issued; see its own doc.go), so a test
// acting as the issuer must build one itself, exactly like a real
// Trust Mark Issuer (an entity outside this module entirely) would.
func signTrustMark(t *testing.T, key *ecdsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal trust mark claims: %v", err)
	}
	token, err := jose.Sign(key, jose.Header{Algorithm: fapi.ES256, Type: "trust-mark+jwt", KeyID: kid}, payload)
	if err != nil {
		t.Fatalf("jose.Sign: %v", err)
	}
	return token
}

// trustMarkFederation is a two-level federation (TA -> LE) where TA
// doubles as the Trust Mark Issuer (the simplest topology that still
// exercises VerifyTrustMark's own recursive resolve of the issuer's
// Trust Chain — here, degenerate, since the issuer IS the Trust
// Anchor). LE's own Entity Configuration declares one Trust Mark,
// issued by TA about LE.
type trustMarkFederation struct {
	taID, leID string
	taKey      *ecdsa.PrivateKey
	taJWKS     json.RawMessage
	fetcher    *fapihttp.Client
	now        time.Time
}

// setupTrustMarkFederation builds the fixture. trustMarkClaims, if
// non-nil, overrides the Trust Mark JWT's own claims (merged over a
// valid baseline) — used by the negative tests to corrupt one field at
// a time.
func setupTrustMarkFederation(t *testing.T, trustMarkClaimOverrides map[string]any) *trustMarkFederation {
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
	})

	trustMarkClaims := map[string]any{
		"iss": taID, "sub": leID, "trust_mark_type": testTrustMarkType,
		"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
	}
	for k, v := range trustMarkClaimOverrides {
		trustMarkClaims[k] = v
	}
	trustMarkJWT := signTrustMark(t, taKey, "ta", trustMarkClaims)

	leConfig := sign(intfed.CreateParams{
		Signer: leKey, Algorithm: fapi.ES256, KeyID: "le",
		Issuer: leID, Subject: leID, Now: now, Lifetime: time.Hour, JWKS: leJWKS,
		AuthorityHints: []string{taID},
		TrustMarks: []intfed.RawTrustMark{
			{TrustMarkType: testTrustMarkType, TrustMark: trustMarkJWT},
		},
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

	return &trustMarkFederation{taID: taID, leID: leID, taKey: taKey, taJWKS: taJWKS, fetcher: fetcher, now: now}
}

func (f *trustMarkFederation) newResolver(t *testing.T) *federation.Resolver {
	t.Helper()
	r, err := federation.NewResolver(federation.Config{
		TrustAnchors: []federation.TrustAnchor{{EntityID: f.taID, JWKS: f.taJWKS}},
		Limits:       federation.Limits{MaxPathLength: 5, MaxStatementLifetime: 2 * time.Hour, MaxClockSkew: 5 * time.Second},
	}, federation.Dependencies{HTTP: f.fetcher, Clock: fixedClock{now: f.now}})
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	return r
}

func TestResolveExposesUnverifiedTrustMarks(t *testing.T) {
	f := setupTrustMarkFederation(t, nil)
	r := f.newResolver(t)

	resolved, err := r.Resolve(context.Background(), f.leID)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(resolved.TrustMarks) != 1 {
		t.Fatalf("TrustMarks = %v, want 1 entry", resolved.TrustMarks)
	}
	if resolved.TrustMarks[0].TrustMarkType != testTrustMarkType {
		t.Errorf("TrustMarks[0].TrustMarkType = %q, want %q", resolved.TrustMarks[0].TrustMarkType, testTrustMarkType)
	}
	if len(resolved.JWKS) == 0 {
		t.Errorf("JWKS is empty, want LE's own trusted federation entity keys")
	}
}

func TestVerifyTrustMarkSucceeds(t *testing.T) {
	f := setupTrustMarkFederation(t, nil)
	r := f.newResolver(t)

	resolved, err := r.Resolve(context.Background(), f.leID)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	claims, err := r.VerifyTrustMark(context.Background(), f.leID, resolved.TrustMarks[0])
	if err != nil {
		t.Fatalf("VerifyTrustMark: %v", err)
	}
	if claims.Issuer != f.taID {
		t.Errorf("claims.Issuer = %q, want %q", claims.Issuer, f.taID)
	}
	if claims.Subject != f.leID {
		t.Errorf("claims.Subject = %q, want %q", claims.Subject, f.leID)
	}
	if claims.TrustMarkType != testTrustMarkType {
		t.Errorf("claims.TrustMarkType = %q, want %q", claims.TrustMarkType, testTrustMarkType)
	}
}

func TestVerifyTrustMarkRejectsSubjectMismatch(t *testing.T) {
	f := setupTrustMarkFederation(t, map[string]any{"sub": "https://someone-else.example.org"})
	r := f.newResolver(t)

	resolved, err := r.Resolve(context.Background(), f.leID)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if _, err := r.VerifyTrustMark(context.Background(), f.leID, resolved.TrustMarks[0]); err == nil {
		t.Fatalf("VerifyTrustMark(sub mismatch) = nil error, want error")
	}
}

func TestVerifyTrustMarkRejectsExpired(t *testing.T) {
	f := setupTrustMarkFederation(t, map[string]any{
		"iat": time.Now().Add(-2 * time.Hour).Unix(),
		"exp": time.Now().Add(-time.Hour).Unix(),
	})
	r := f.newResolver(t)

	resolved, err := r.Resolve(context.Background(), f.leID)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if _, err := r.VerifyTrustMark(context.Background(), f.leID, resolved.TrustMarks[0]); err == nil {
		t.Fatalf("VerifyTrustMark(expired) = nil error, want error")
	}
}

func TestVerifyTrustMarkRejectsUnresolvableIssuer(t *testing.T) {
	f := setupTrustMarkFederation(t, map[string]any{"iss": "https://unreachable-issuer.example.org"})
	r := f.newResolver(t)

	resolved, err := r.Resolve(context.Background(), f.leID)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if _, err := r.VerifyTrustMark(context.Background(), f.leID, resolved.TrustMarks[0]); err == nil {
		t.Fatalf("VerifyTrustMark(unresolvable issuer) = nil error, want error")
	}
}

func TestVerifyTrustMarkRejectsWrongTrustMarkType(t *testing.T) {
	f := setupTrustMarkFederation(t, nil)
	r := f.newResolver(t)

	resolved, err := r.Resolve(context.Background(), f.leID)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	tampered := resolved.TrustMarks[0]
	tampered.TrustMarkType = "https://federation.example.org/marks/different"
	if _, err := r.VerifyTrustMark(context.Background(), f.leID, tampered); err == nil {
		t.Fatalf("VerifyTrustMark(wrapper trust_mark_type does not match the JWT's own) = nil error, want error")
	}
}

func TestVerifyTrustMarkRejectsEmptySubjectID(t *testing.T) {
	f := setupTrustMarkFederation(t, nil)
	r := f.newResolver(t)

	resolved, err := r.Resolve(context.Background(), f.leID)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if _, err := r.VerifyTrustMark(context.Background(), "", resolved.TrustMarks[0]); err == nil {
		t.Fatalf("VerifyTrustMark(empty subjectID) = nil error, want error")
	}
}

func TestVerifyTrustMarkRejectsMalformedTrustMarkJWT(t *testing.T) {
	f := setupTrustMarkFederation(t, nil)
	r := f.newResolver(t)

	malformed := intfed.RawTrustMark{TrustMarkType: testTrustMarkType, TrustMark: "not-a-jwt"}
	if _, err := r.VerifyTrustMark(context.Background(), f.leID, malformed); err == nil {
		t.Fatalf("VerifyTrustMark(malformed trust mark JWT) = nil error, want error")
	}
}
