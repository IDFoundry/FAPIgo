package federation_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
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

// setupTrustMarkFederation builds the fixture. buildOverrides, if
// non-nil, is called once taID/leID are known and its result is merged
// over the Trust Mark JWT's own valid-baseline claims — used by the
// negative tests to corrupt one field at a time, and by the delegation
// tests (which need taID to build a delegation JWT's own "sub" claim).
// taTrustMarkOwners, if non-nil, becomes TA's own "trust_mark_owners"
// claim.
func setupTrustMarkFederation(t *testing.T, buildOverrides func(taID, leID string) map[string]any, taTrustMarkOwners map[string]intfed.TrustMarkOwner) *trustMarkFederation {
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
		Metadata:        federationEntityMetadata(t, taID+"/fetch"),
		TrustMarkOwners: taTrustMarkOwners,
	})
	taAboutLE := sign(intfed.CreateParams{
		Signer: taKey, Algorithm: fapi.ES256, KeyID: "ta",
		Issuer: taID, Subject: leID, Now: now, Lifetime: time.Hour, JWKS: leJWKS,
	})

	trustMarkClaims := map[string]any{
		"iss": taID, "sub": leID, "trust_mark_type": testTrustMarkType,
		"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
	}
	if buildOverrides != nil {
		for k, v := range buildOverrides(taID, leID) {
			trustMarkClaims[k] = v
		}
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
	f := setupTrustMarkFederation(t, nil, nil)
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
	f := setupTrustMarkFederation(t, nil, nil)
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
	f := setupTrustMarkFederation(t, func(taID, leID string) map[string]any {
		return map[string]any{"sub": "https://someone-else.example.org"}
	}, nil)
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
	f := setupTrustMarkFederation(t, func(taID, leID string) map[string]any {
		return map[string]any{
			"iat": time.Now().Add(-2 * time.Hour).Unix(),
			"exp": time.Now().Add(-time.Hour).Unix(),
		}
	}, nil)
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
	f := setupTrustMarkFederation(t, func(taID, leID string) map[string]any {
		return map[string]any{"iss": "https://unreachable-issuer.example.org"}
	}, nil)
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
	f := setupTrustMarkFederation(t, nil, nil)
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
	f := setupTrustMarkFederation(t, nil, nil)
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
	f := setupTrustMarkFederation(t, nil, nil)
	r := f.newResolver(t)

	malformed := intfed.RawTrustMark{TrustMarkType: testTrustMarkType, TrustMark: "not-a-jwt"}
	if _, err := r.VerifyTrustMark(context.Background(), f.leID, malformed); err == nil {
		t.Fatalf("VerifyTrustMark(malformed trust mark JWT) = nil error, want error")
	}
}

// --- Trust Mark Delegation (OpenID Federation 1.0 §7.2) ---------------
//
// The Trust Mark Owner (ownerKey/testOwnerID below) is a third party
// outside the TA -> LE federation entirely — its keys are published
// directly in TA's own "trust_mark_owners" claim (never resolved via a
// separate Trust Chain), exactly as the spec describes.

const testOwnerID = "https://owner.example.org"

func signTrustMarkDelegation(t *testing.T, key *ecdsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal delegation claims: %v", err)
	}
	token, err := jose.Sign(key, jose.Header{Algorithm: fapi.ES256, Type: "trust-mark-delegation+jwt", KeyID: kid}, payload)
	if err != nil {
		t.Fatalf("jose.Sign: %v", err)
	}
	return token
}

func TestVerifyTrustMarkRequiresDelegationWhenOwnerNamesType(t *testing.T) {
	ownerKey := generateKey(t)
	owners := map[string]intfed.TrustMarkOwner{testTrustMarkType: {Subject: testOwnerID, JWKS: jwksFor(t, "owner", ownerKey)}}

	// No delegation claim on the trust mark, even though TA's own
	// trust_mark_owners names this type.
	f := setupTrustMarkFederation(t, nil, owners)
	r := f.newResolver(t)

	resolved, err := r.Resolve(context.Background(), f.leID)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if _, err := r.VerifyTrustMark(context.Background(), f.leID, resolved.TrustMarks[0]); err == nil {
		t.Fatalf("VerifyTrustMark(owner names type, no delegation claim) = nil error, want error")
	}
}

func TestVerifyTrustMarkSucceedsWithValidDelegation(t *testing.T) {
	ownerKey := generateKey(t)
	owners := map[string]intfed.TrustMarkOwner{testTrustMarkType: {Subject: testOwnerID, JWKS: jwksFor(t, "owner", ownerKey)}}
	now := time.Now()

	f := setupTrustMarkFederation(t, func(taID, leID string) map[string]any {
		delegation := signTrustMarkDelegation(t, ownerKey, "owner", map[string]any{
			"iss": testOwnerID, "sub": taID, "trust_mark_type": testTrustMarkType,
			"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
		})
		return map[string]any{"delegation": delegation}
	}, owners)
	r := f.newResolver(t)

	resolved, err := r.Resolve(context.Background(), f.leID)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	claims, err := r.VerifyTrustMark(context.Background(), f.leID, resolved.TrustMarks[0])
	if err != nil {
		t.Fatalf("VerifyTrustMark(valid delegation): %v, want nil error", err)
	}
	if claims.Issuer != f.taID {
		t.Errorf("claims.Issuer = %q, want %q", claims.Issuer, f.taID)
	}
}

func TestVerifyTrustMarkRejectsDelegationWrongSubject(t *testing.T) {
	ownerKey := generateKey(t)
	owners := map[string]intfed.TrustMarkOwner{testTrustMarkType: {Subject: testOwnerID, JWKS: jwksFor(t, "owner", ownerKey)}}
	now := time.Now()

	f := setupTrustMarkFederation(t, func(taID, leID string) map[string]any {
		delegation := signTrustMarkDelegation(t, ownerKey, "owner", map[string]any{
			// sub should be taID (the trust mark's own issuer) — using a
			// different value must fail delegation validation.
			"iss": testOwnerID, "sub": "https://someone-else.example.org", "trust_mark_type": testTrustMarkType,
			"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
		})
		return map[string]any{"delegation": delegation}
	}, owners)
	r := f.newResolver(t)

	resolved, err := r.Resolve(context.Background(), f.leID)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if _, err := r.VerifyTrustMark(context.Background(), f.leID, resolved.TrustMarks[0]); err == nil {
		t.Fatalf("VerifyTrustMark(delegation sub mismatch) = nil error, want error")
	}
}

func TestVerifyTrustMarkRejectsDelegationWrongIssuer(t *testing.T) {
	ownerKey := generateKey(t)
	owners := map[string]intfed.TrustMarkOwner{testTrustMarkType: {Subject: testOwnerID, JWKS: jwksFor(t, "owner", ownerKey)}}
	now := time.Now()

	f := setupTrustMarkFederation(t, func(taID, leID string) map[string]any {
		delegation := signTrustMarkDelegation(t, ownerKey, "owner", map[string]any{
			// iss should be testOwnerID (the real owner per trust_mark_owners).
			"iss": "https://not-the-real-owner.example.org", "sub": taID, "trust_mark_type": testTrustMarkType,
			"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
		})
		return map[string]any{"delegation": delegation}
	}, owners)
	r := f.newResolver(t)

	resolved, err := r.Resolve(context.Background(), f.leID)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if _, err := r.VerifyTrustMark(context.Background(), f.leID, resolved.TrustMarks[0]); err == nil {
		t.Fatalf("VerifyTrustMark(delegation iss mismatch) = nil error, want error")
	}
}

func TestVerifyTrustMarkRejectsDelegationSignedByWrongKey(t *testing.T) {
	ownerKey := generateKey(t)
	wrongKey := generateKey(t)
	owners := map[string]intfed.TrustMarkOwner{testTrustMarkType: {Subject: testOwnerID, JWKS: jwksFor(t, "owner", ownerKey)}}
	now := time.Now()

	f := setupTrustMarkFederation(t, func(taID, leID string) map[string]any {
		delegation := signTrustMarkDelegation(t, wrongKey, "owner", map[string]any{
			"iss": testOwnerID, "sub": taID, "trust_mark_type": testTrustMarkType,
			"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
		})
		return map[string]any{"delegation": delegation}
	}, owners)
	r := f.newResolver(t)

	resolved, err := r.Resolve(context.Background(), f.leID)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if _, err := r.VerifyTrustMark(context.Background(), f.leID, resolved.TrustMarks[0]); err == nil {
		t.Fatalf("VerifyTrustMark(delegation signed by wrong key) = nil error, want error")
	}
}

func TestVerifyTrustMarkRejectsMalformedDelegationJWT(t *testing.T) {
	owners := map[string]intfed.TrustMarkOwner{testTrustMarkType: {Subject: testOwnerID, JWKS: jwksFor(t, "owner", generateKey(t))}}

	f := setupTrustMarkFederation(t, func(taID, leID string) map[string]any {
		return map[string]any{"delegation": "not-a-jwt"}
	}, owners)
	r := f.newResolver(t)

	resolved, err := r.Resolve(context.Background(), f.leID)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if _, err := r.VerifyTrustMark(context.Background(), f.leID, resolved.TrustMarks[0]); err == nil {
		t.Fatalf("VerifyTrustMark(malformed delegation JWT) = nil error, want error")
	}
}

func TestVerifyTrustMarkIgnoresDelegationWhenTypeNotOwned(t *testing.T) {
	// TA's own trust_mark_owners is nil (no type named at all), so no
	// delegation is required and none is present — the existing
	// TestVerifyTrustMarkSucceeds already covers this baseline; this
	// test instead confirms a PRESENT delegation is simply not checked
	// when the type isn't owned, even a broken one.
	f := setupTrustMarkFederation(t, func(taID, leID string) map[string]any {
		return map[string]any{"delegation": "not-a-jwt"}
	}, nil)
	r := f.newResolver(t)

	resolved, err := r.Resolve(context.Background(), f.leID)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if _, err := r.VerifyTrustMark(context.Background(), f.leID, resolved.TrustMarks[0]); err != nil {
		t.Fatalf("VerifyTrustMark(broken delegation, type not owned): %v, want nil error", err)
	}
}

// trustMarkStatusFederation is a one-entity federation: issuerID acts
// as its own Trust Anchor (the simplest topology that still exercises
// CheckTrustMarkStatus's own resolve-the-issuer step) and as the Trust
// Mark Issuer answering the status query.
type trustMarkStatusFederation struct {
	issuerID   string
	issuerKey  *ecdsa.PrivateKey
	issuerJWKS json.RawMessage
	fetcher    *fapihttp.Client
	now        time.Time
	mux        *http.ServeMux
}

// setupTrustMarkStatusFederation builds the fixture and registers the
// well-known/fetch endpoints; statusHandler (if non-nil) is registered
// at /status and declared as the entity's own
// federation_trust_mark_status_endpoint — callers that need to
// exercise a missing/malformed response pass nil and register their
// own handler (or none) directly on the returned mux before use.
func setupTrustMarkStatusFederation(t *testing.T, statusHandler http.HandlerFunc) *trustMarkStatusFederation {
	t.Helper()
	now := time.Now()
	issuerKey := generateKey(t)
	issuerJWKS := jwksFor(t, "issuer", issuerKey)

	mux := http.NewServeMux()
	server := httptest.NewTLSServer(mux)
	t.Cleanup(server.Close)
	issuerID := server.URL

	metadata := map[string]json.RawMessage{}
	entityMeta, err := json.Marshal(map[string]string{
		"federation_fetch_endpoint":             issuerID + "/fetch",
		"federation_trust_mark_status_endpoint": issuerID + "/status",
	})
	if err != nil {
		t.Fatalf("marshal federation_entity metadata: %v", err)
	}
	metadata["federation_entity"] = entityMeta

	issuerConfig, err := intfed.Create(intfed.CreateParams{
		Signer: issuerKey, Algorithm: fapi.ES256, KeyID: "issuer",
		Issuer: issuerID, Subject: issuerID, Now: now, Lifetime: time.Hour,
		JWKS: issuerJWKS, Metadata: metadata,
	})
	if err != nil {
		t.Fatalf("intfed.Create: %v", err)
	}
	mux.HandleFunc("/.well-known/openid-federation", serveStatement(issuerConfig))
	if statusHandler != nil {
		mux.HandleFunc("/status", statusHandler)
	}

	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	httpClient := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}
	fetcher, err := fapihttp.New(httpClient, fapihttp.Config{
		MaxResponseBytes: 1 << 16, RequestTimeout: 5 * time.Second, MaxRedirects: 1,
		AllowLoopbackHTTP: true,
	})
	if err != nil {
		t.Fatalf("fapihttp.New: %v", err)
	}

	return &trustMarkStatusFederation{
		issuerID: issuerID, issuerKey: issuerKey, issuerJWKS: issuerJWKS,
		fetcher: fetcher, now: now, mux: mux,
	}
}

func (f *trustMarkStatusFederation) newResolver(t *testing.T) *federation.Resolver {
	t.Helper()
	r, err := federation.NewResolver(federation.Config{
		TrustAnchors: []federation.TrustAnchor{{EntityID: f.issuerID, JWKS: f.issuerJWKS}},
		Limits:       federation.Limits{MaxPathLength: 5, MaxStatementLifetime: 2 * time.Hour, MaxClockSkew: 5 * time.Second},
	}, federation.Dependencies{HTTP: f.fetcher, Clock: fixedClock{now: f.now}})
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	return r
}

func TestCheckTrustMarkStatusSucceeds(t *testing.T) {
	f := setupTrustMarkStatusFederation(t, nil)
	trustMark := signTrustMark(t, f.issuerKey, "issuer", map[string]any{
		"iss": f.issuerID, "sub": "https://rp.example.org", "trust_mark_type": testTrustMarkType,
		"iat": f.now.Unix(), "exp": f.now.Add(time.Hour).Unix(),
	})
	f.mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil || r.PostFormValue("trust_mark") != trustMark {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		response, err := intfed.CreateTrustMarkStatusResponse(intfed.CreateTrustMarkStatusResponseParams{
			Signer: f.issuerKey, Algorithm: fapi.ES256, KeyID: "issuer",
			Issuer: f.issuerID, TrustMark: trustMark, Status: intfed.TrustMarkStatusActive, Now: f.now,
		})
		if err != nil {
			t.Fatalf("intfed.CreateTrustMarkStatusResponse: %v", err)
		}
		w.Header().Set("Content-Type", "application/trust-mark-status-response+jwt")
		w.Write([]byte(response))
	})

	r := f.newResolver(t)
	claims, err := r.CheckTrustMarkStatus(context.Background(), trustMark)
	if err != nil {
		t.Fatalf("CheckTrustMarkStatus: %v", err)
	}
	if claims.Status != intfed.TrustMarkStatusActive {
		t.Errorf("claims.Status = %q, want active", claims.Status)
	}
	if claims.TrustMark != trustMark {
		t.Errorf("claims.TrustMark does not match the queried trust mark")
	}
}

func TestCheckTrustMarkStatusRejectsEmptyTrustMark(t *testing.T) {
	f := setupTrustMarkStatusFederation(t, nil)
	r := f.newResolver(t)
	if _, err := r.CheckTrustMarkStatus(context.Background(), ""); err == nil {
		t.Fatal("CheckTrustMarkStatus(empty) = nil error, want error")
	}
}

func TestCheckTrustMarkStatusRejectsMalformedTrustMark(t *testing.T) {
	f := setupTrustMarkStatusFederation(t, nil)
	r := f.newResolver(t)
	if _, err := r.CheckTrustMarkStatus(context.Background(), "not-a-jwt"); err == nil {
		t.Fatal("CheckTrustMarkStatus(malformed) = nil error, want error")
	}
}

func TestCheckTrustMarkStatusRejectsUnresolvableIssuer(t *testing.T) {
	f := setupTrustMarkStatusFederation(t, nil)
	r := f.newResolver(t)
	// Signed by a key the resolver's own configured Trust Anchor
	// (f.issuerID) never vouches for — issuer here names a made-up
	// entity that isn't a Trust Anchor and has no authority_hints chain
	// to one, so Resolve itself fails.
	otherKey := generateKey(t)
	trustMark := signTrustMark(t, otherKey, "other", map[string]any{
		"iss": "https://unresolvable.example.org", "sub": "https://rp.example.org", "trust_mark_type": testTrustMarkType,
		"iat": f.now.Unix(), "exp": f.now.Add(time.Hour).Unix(),
	})
	if _, err := r.CheckTrustMarkStatus(context.Background(), trustMark); err == nil {
		t.Fatal("CheckTrustMarkStatus(unresolvable issuer) = nil error, want error")
	}
}

func TestCheckTrustMarkStatusRejectsMalformedIssuerMetadata(t *testing.T) {
	now := time.Now()
	issuerKey := generateKey(t)
	issuerJWKS := jwksFor(t, "issuer", issuerKey)
	mux := http.NewServeMux()
	server := httptest.NewTLSServer(mux)
	t.Cleanup(server.Close)
	issuerID := server.URL

	issuerConfig, err := intfed.Create(intfed.CreateParams{
		Signer: issuerKey, Algorithm: fapi.ES256, KeyID: "issuer",
		Issuer: issuerID, Subject: issuerID, Now: now, Lifetime: time.Hour, JWKS: issuerJWKS,
		Metadata: map[string]json.RawMessage{"federation_entity": json.RawMessage(`"not an object"`)},
	})
	if err != nil {
		t.Fatalf("intfed.Create: %v", err)
	}
	mux.HandleFunc("/.well-known/openid-federation", serveStatement(issuerConfig))

	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	httpClient := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}
	fetcher, err := fapihttp.New(httpClient, fapihttp.Config{
		MaxResponseBytes: 1 << 16, RequestTimeout: 5 * time.Second, MaxRedirects: 1,
		AllowLoopbackHTTP: true,
	})
	if err != nil {
		t.Fatalf("fapihttp.New: %v", err)
	}
	r, err := federation.NewResolver(federation.Config{
		TrustAnchors: []federation.TrustAnchor{{EntityID: issuerID, JWKS: issuerJWKS}},
		Limits:       federation.Limits{MaxPathLength: 5, MaxStatementLifetime: 2 * time.Hour, MaxClockSkew: 5 * time.Second},
	}, federation.Dependencies{HTTP: fetcher, Clock: fixedClock{now: now}})
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}

	trustMark := signTrustMark(t, issuerKey, "issuer", map[string]any{
		"iss": issuerID, "sub": "https://rp.example.org", "trust_mark_type": testTrustMarkType,
		"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
	})
	if _, err := r.CheckTrustMarkStatus(context.Background(), trustMark); err == nil {
		t.Fatal("CheckTrustMarkStatus(malformed federation_entity metadata) = nil error, want error")
	}
}

func TestCheckTrustMarkStatusRejectsMalformedResponseBody(t *testing.T) {
	f := setupTrustMarkStatusFederation(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/trust-mark-status-response+jwt")
		w.Write([]byte("not-a-jwt"))
	})
	trustMark := signTrustMark(t, f.issuerKey, "issuer", map[string]any{
		"iss": f.issuerID, "sub": "https://rp.example.org", "trust_mark_type": testTrustMarkType,
		"iat": f.now.Unix(), "exp": f.now.Add(time.Hour).Unix(),
	})
	r := f.newResolver(t)
	if _, err := r.CheckTrustMarkStatus(context.Background(), trustMark); err == nil {
		t.Fatal("CheckTrustMarkStatus(malformed response body) = nil error, want error")
	}
}

func TestCheckTrustMarkStatusRejectsMissingStatusEndpoint(t *testing.T) {
	// setupTrustMarkStatusFederation with a nil statusHandler still
	// declares federation_trust_mark_status_endpoint in metadata (the
	// handler just isn't registered) — to test the "issuer published no
	// endpoint at all" case, build a fixture with that claim absent
	// entirely.
	now := time.Now()
	issuerKey := generateKey(t)
	issuerJWKS := jwksFor(t, "issuer", issuerKey)
	mux := http.NewServeMux()
	server := httptest.NewTLSServer(mux)
	t.Cleanup(server.Close)
	issuerID := server.URL

	issuerConfig, err := intfed.Create(intfed.CreateParams{
		Signer: issuerKey, Algorithm: fapi.ES256, KeyID: "issuer",
		Issuer: issuerID, Subject: issuerID, Now: now, Lifetime: time.Hour,
		JWKS: issuerJWKS, Metadata: federationEntityMetadata(t, issuerID+"/fetch"),
	})
	if err != nil {
		t.Fatalf("intfed.Create: %v", err)
	}
	mux.HandleFunc("/.well-known/openid-federation", serveStatement(issuerConfig))

	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	httpClient := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}
	fetcher, err := fapihttp.New(httpClient, fapihttp.Config{
		MaxResponseBytes: 1 << 16, RequestTimeout: 5 * time.Second, MaxRedirects: 1,
		AllowLoopbackHTTP: true,
	})
	if err != nil {
		t.Fatalf("fapihttp.New: %v", err)
	}
	r, err := federation.NewResolver(federation.Config{
		TrustAnchors: []federation.TrustAnchor{{EntityID: issuerID, JWKS: issuerJWKS}},
		Limits:       federation.Limits{MaxPathLength: 5, MaxStatementLifetime: 2 * time.Hour, MaxClockSkew: 5 * time.Second},
	}, federation.Dependencies{HTTP: fetcher, Clock: fixedClock{now: now}})
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}

	trustMark := signTrustMark(t, issuerKey, "issuer", map[string]any{
		"iss": issuerID, "sub": "https://rp.example.org", "trust_mark_type": testTrustMarkType,
		"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
	})
	if _, err := r.CheckTrustMarkStatus(context.Background(), trustMark); err == nil {
		t.Fatal("CheckTrustMarkStatus(no status endpoint published) = nil error, want error")
	}
}

func TestCheckTrustMarkStatusRejectsNotFound(t *testing.T) {
	f := setupTrustMarkStatusFederation(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"error":"not_found"}`))
	})
	trustMark := signTrustMark(t, f.issuerKey, "issuer", map[string]any{
		"iss": f.issuerID, "sub": "https://rp.example.org", "trust_mark_type": testTrustMarkType,
		"iat": f.now.Unix(), "exp": f.now.Add(time.Hour).Unix(),
	})
	r := f.newResolver(t)
	if _, err := r.CheckTrustMarkStatus(context.Background(), trustMark); !errors.Is(err, fapihttp.ErrUnexpectedStatus) {
		t.Fatalf("CheckTrustMarkStatus(404) = %v, want fapihttp.ErrUnexpectedStatus", err)
	}
}

func TestCheckTrustMarkStatusRejectsWrongTrustMarkInResponse(t *testing.T) {
	f := setupTrustMarkStatusFederation(t, nil)
	trustMark := signTrustMark(t, f.issuerKey, "issuer", map[string]any{
		"iss": f.issuerID, "sub": "https://rp.example.org", "trust_mark_type": testTrustMarkType,
		"iat": f.now.Unix(), "exp": f.now.Add(time.Hour).Unix(),
	})
	f.mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		response, err := intfed.CreateTrustMarkStatusResponse(intfed.CreateTrustMarkStatusResponseParams{
			Signer: f.issuerKey, Algorithm: fapi.ES256, KeyID: "issuer",
			Issuer: f.issuerID, TrustMark: "a-different-trust-mark", Status: intfed.TrustMarkStatusActive, Now: f.now,
		})
		if err != nil {
			t.Fatalf("intfed.CreateTrustMarkStatusResponse: %v", err)
		}
		w.Header().Set("Content-Type", "application/trust-mark-status-response+jwt")
		w.Write([]byte(response))
	})

	r := f.newResolver(t)
	if _, err := r.CheckTrustMarkStatus(context.Background(), trustMark); err == nil {
		t.Fatal("CheckTrustMarkStatus(response about a different trust mark) = nil error, want error")
	}
}
