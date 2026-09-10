package federation_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/fapihttp"
	"github.com/idfoundry/fapigo/federation"
	intfed "github.com/idfoundry/fapigo/internal/federation"
	"github.com/idfoundry/fapigo/internal/jose"
)

// dummyResolver builds a Resolver whose configured trust anchor is
// unrelated to fetcher's own federation — for tests whose failure
// occurs before a Trust Chain ever reaches a trust anchor, where the
// resolver's own trust anchor configuration is otherwise irrelevant.
func dummyResolver(t *testing.T, fetcher *fapihttp.Client, now time.Time) *federation.Resolver {
	t.Helper()
	anchorKey := generateKey(t)
	r, err := federation.NewResolver(federation.Config{
		TrustAnchors: []federation.TrustAnchor{{EntityID: "https://ta.example.org", JWKS: jwksFor(t, "a", anchorKey)}},
		Limits:       federation.Limits{MaxPathLength: 5, MaxStatementLifetime: 2 * time.Hour, MaxClockSkew: 5 * time.Second},
	}, federation.Dependencies{HTTP: fetcher, Clock: fixedClock{now: now}})
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	return r
}

// setupLeafWithSuperior builds a Leaf entity whose sole authority_hints
// entry is a Superior entity this test fully controls. metadataFn (if
// non-nil) builds the Superior's own declared federation_entity
// metadata from its entity ID — for tests that fail at or before the
// Superior's own statement is actually validated or used, so the
// Superior needs no authority_hints or trust-anchor status of its own.
func setupLeafWithSuperior(t *testing.T, now time.Time, metadataFn func(supID string) map[string]json.RawMessage) (leID, supID string, supMux *http.ServeMux, supKey *ecdsa.PrivateKey, fetcher *fapihttp.Client) {
	t.Helper()
	supKey = generateKey(t)
	supMux = http.NewServeMux()
	supServer := httptest.NewTLSServer(supMux)
	t.Cleanup(supServer.Close)
	supID = supServer.URL
	var metadata map[string]json.RawMessage
	if metadataFn != nil {
		metadata = metadataFn(supID)
	}
	supConfig, err := intfed.Create(intfed.CreateParams{
		Signer: supKey, Algorithm: fapi.ES256, KeyID: "sup",
		Issuer: supID, Subject: supID, Now: now, Lifetime: time.Hour, JWKS: jwksFor(t, "sup", supKey),
		Metadata: metadata,
	})
	if err != nil {
		t.Fatalf("intfed.Create: %v", err)
	}
	supMux.HandleFunc("/.well-known/openid-federation", serveStatement(supConfig))

	leKey := generateKey(t)
	var leTS *httptest.Server
	leID, leTS = singleEntityServer(t, func(id string) string {
		token, err := intfed.Create(intfed.CreateParams{
			Signer: leKey, Algorithm: fapi.ES256, KeyID: "le",
			Issuer: id, Subject: id, Now: now, Lifetime: time.Hour, JWKS: jwksFor(t, "le", leKey),
			AuthorityHints: []string{supID},
		})
		if err != nil {
			t.Fatalf("intfed.Create: %v", err)
		}
		return token
	}, nil)

	return leID, supID, supMux, supKey, fetcherFor(t, supServer, leTS)
}

func TestResolveRejectsMalformedEntityConfigurationBody(t *testing.T) {
	now := time.Now()
	mux := http.NewServeMux()
	ts := httptest.NewTLSServer(mux)
	t.Cleanup(ts.Close)
	entityID := ts.URL
	mux.HandleFunc("/.well-known/openid-federation", serveStatement("not-a-valid-jwt"))

	r := dummyResolver(t, fetcherFor(t, ts), now)
	if _, err := r.Resolve(context.Background(), entityID); err == nil {
		t.Fatalf("Resolve(malformed entity configuration body) = nil error, want error")
	}
}

func TestResolveRejectsMalformedFederationEntityMetadata(t *testing.T) {
	now := time.Now()
	leID, _, _, _, fetcher := setupLeafWithSuperior(t, now, func(string) map[string]json.RawMessage {
		return map[string]json.RawMessage{"federation_entity": json.RawMessage(`123`)}
	})
	r := dummyResolver(t, fetcher, now)
	if _, err := r.Resolve(context.Background(), leID); err == nil {
		t.Fatalf("Resolve(malformed federation_entity metadata) = nil error, want error")
	}
}

func TestResolveRejectsInvalidFetchEndpointURL(t *testing.T) {
	now := time.Now()
	leID, _, _, _, fetcher := setupLeafWithSuperior(t, now, func(supID string) map[string]json.RawMessage {
		return federationEntityMetadata(t, supID+"/%zz")
	})
	r := dummyResolver(t, fetcher, now)
	if _, err := r.Resolve(context.Background(), leID); err == nil {
		t.Fatalf("Resolve(invalid federation_fetch_endpoint URL) = nil error, want error")
	}
}

func TestResolveRejectsNonHTTPSFetchEndpoint(t *testing.T) {
	now := time.Now()
	leID, _, _, _, fetcher := setupLeafWithSuperior(t, now, func(supID string) map[string]json.RawMessage {
		return federationEntityMetadata(t, "http://"+strings.TrimPrefix(supID, "https://")+"/fetch")
	})
	r := dummyResolver(t, fetcher, now)
	if _, err := r.Resolve(context.Background(), leID); err == nil {
		t.Fatalf("Resolve(non-https federation_fetch_endpoint) = nil error, want error")
	}
}

func TestResolveRejectsUnreachableFetchEndpoint(t *testing.T) {
	now := time.Now()
	leID, _, _, _, fetcher := setupLeafWithSuperior(t, now, func(string) map[string]json.RawMessage {
		return federationEntityMetadata(t, "https://nonexistent-fetch-host.example.invalid/fetch")
	})
	r := dummyResolver(t, fetcher, now)
	if _, err := r.Resolve(context.Background(), leID); err == nil {
		t.Fatalf("Resolve(unreachable federation_fetch_endpoint) = nil error, want error")
	}
}

func TestResolveRejectsMalformedSubordinateStatementBody(t *testing.T) {
	now := time.Now()
	leID, _, supMux, _, fetcher := setupLeafWithSuperior(t, now, func(supID string) map[string]json.RawMessage {
		return federationEntityMetadata(t, supID+"/fetch")
	})
	supMux.HandleFunc("/fetch", serveStatement("not-a-valid-jwt"))

	r := dummyResolver(t, fetcher, now)
	if _, err := r.Resolve(context.Background(), leID); err == nil {
		t.Fatalf("Resolve(malformed subordinate statement body) = nil error, want error")
	}
}

func TestResolveRejectsSubordinateStatementIssuerSubjectMismatch(t *testing.T) {
	now := time.Now()
	leID, supID, supMux, supKey, fetcher := setupLeafWithSuperior(t, now, func(supID string) map[string]json.RawMessage {
		return federationEntityMetadata(t, supID+"/fetch")
	})
	badStmt, err := intfed.Create(intfed.CreateParams{
		Signer: supKey, Algorithm: fapi.ES256, KeyID: "sup",
		Issuer: supID, Subject: "https://someone-else.example.org", // wrong: should be leID
		Now: now, Lifetime: time.Hour, JWKS: jwksFor(t, "sup", supKey),
	})
	if err != nil {
		t.Fatalf("intfed.Create: %v", err)
	}
	supMux.HandleFunc("/fetch", serveStatement(badStmt))

	r := dummyResolver(t, fetcher, now)
	if _, err := r.Resolve(context.Background(), leID); err == nil {
		t.Fatalf("Resolve(subordinate statement iss/sub mismatch) = nil error, want error")
	}
}

// setupFlakyIntermediateFederation is a TA -> I1 -> LE federation
// (mirroring threeLevelFederation's own topology) where I1's own
// .well-known endpoint serves a good, self-consistent Entity
// Configuration on its FIRST request — satisfying the "is I1 a
// reachable superior of LE" check findReachableSuperior performs while
// still routing from LE — and secondHandler(i1ID, i1Key, now) on every
// request after that. This isolates failures to Resolve's own SEPARATE
// re-fetch of I1's config once I1 itself becomes entityAt (a
// hop-by-hop self-consistency check distinct from mere routing).
func setupFlakyIntermediateFederation(t *testing.T, secondHandlerFactory func(i1ID string, i1Key *ecdsa.PrivateKey, now time.Time) http.HandlerFunc) *threeLevelFederationHandle {
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
	})
	leConfig := sign(intfed.CreateParams{
		Signer: leKey, Algorithm: fapi.ES256, KeyID: "le",
		Issuer: leID, Subject: leID, Now: now, Lifetime: time.Hour, JWKS: leJWKS,
		AuthorityHints: []string{i1ID},
	})

	taMux.HandleFunc("/.well-known/openid-federation", serveStatement(taConfig))
	taMux.HandleFunc("/fetch", serveFetch(map[string]string{i1ID: taAboutI1}))

	secondHandler := secondHandlerFactory(i1ID, i1Key, now)
	var calls int32
	i1Mux.HandleFunc("/.well-known/openid-federation", func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&calls, 1) == 1 {
			serveStatement(i1Config)(w, r)
			return
		}
		secondHandler(w, r)
	})
	i1Mux.HandleFunc("/fetch", serveFetch(map[string]string{leID: i1AboutLE}))
	leMux.HandleFunc("/.well-known/openid-federation", serveStatement(leConfig))

	fetcher := fetcherFor(t, taServer, i1Server, leServer)
	return &threeLevelFederationHandle{taID: taID, leID: leID, taJWKS: taJWKS, fetcher: fetcher, now: now}
}

// threeLevelFederationHandle carries just enough of a built federation
// for a test to construct a Resolver and call Resolve — a lighter
// counterpart to threeLevelFederation for helpers that don't need every
// key/JWKS exposed.
type threeLevelFederationHandle struct {
	taID, leID string
	taJWKS     json.RawMessage
	fetcher    *fapihttp.Client
	now        time.Time
}

func (h *threeLevelFederationHandle) newResolver(t *testing.T) *federation.Resolver {
	t.Helper()
	r, err := federation.NewResolver(federation.Config{
		TrustAnchors: []federation.TrustAnchor{{EntityID: h.taID, JWKS: h.taJWKS}},
		Limits:       federation.Limits{MaxPathLength: 5, MaxStatementLifetime: 2 * time.Hour, MaxClockSkew: 5 * time.Second},
	}, federation.Dependencies{HTTP: h.fetcher, Clock: fixedClock{now: h.now}})
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	return r
}

func TestResolveRejectsIntermediateSelfConfigFetchError(t *testing.T) {
	f := setupFlakyIntermediateFederation(t, func(string, *ecdsa.PrivateKey, time.Time) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"error":"server_error"}`))
		}
	})
	r := f.newResolver(t)
	if _, err := r.Resolve(context.Background(), f.leID); err == nil {
		t.Fatalf("Resolve(intermediate's own self-config re-fetch fails) = nil error, want error")
	}
}

func TestResolveRejectsIntermediateSelfConfigIssuerSubjectMismatch(t *testing.T) {
	f := setupFlakyIntermediateFederation(t, func(i1ID string, i1Key *ecdsa.PrivateKey, now time.Time) http.HandlerFunc {
		bad, err := intfed.Create(intfed.CreateParams{
			Signer: i1Key, Algorithm: fapi.ES256, KeyID: "i1",
			Issuer: i1ID, Subject: "https://someone-else.example.org",
			Now: now, Lifetime: time.Hour, JWKS: jwksFor(t, "i1", i1Key),
		})
		if err != nil {
			t.Fatalf("intfed.Create: %v", err)
		}
		return serveStatement(bad)
	})
	r := f.newResolver(t)
	if _, err := r.Resolve(context.Background(), f.leID); err == nil {
		t.Fatalf("Resolve(intermediate's own self-config re-fetch has iss/sub mismatch) = nil error, want error")
	}
}

func TestResolveRejectsIntermediateSelfConfigVerifyFailure(t *testing.T) {
	f := setupFlakyIntermediateFederation(t, func(i1ID string, i1Key *ecdsa.PrivateKey, now time.Time) http.HandlerFunc {
		wrongKey := generateKey(t)
		bad, err := intfed.Create(intfed.CreateParams{
			Signer: wrongKey, Algorithm: fapi.ES256, KeyID: "i1",
			Issuer: i1ID, Subject: i1ID, Now: now, Lifetime: time.Hour,
			JWKS: jwksFor(t, "i1", i1Key), // claims i1Key, but signed by wrongKey
		})
		if err != nil {
			t.Fatalf("intfed.Create: %v", err)
		}
		return serveStatement(bad)
	})
	r := f.newResolver(t)
	if _, err := r.Resolve(context.Background(), f.leID); err == nil {
		t.Fatalf("Resolve(intermediate's own self-config re-fetch does not self-verify) = nil error, want error")
	}
}

// threeLevelParams lets a test override individual signed artifacts (or
// timing) in an otherwise-standard TA -> I1 -> LE federation, for tests
// that need to break exactly one link in the chain while leaving the
// rest standard — the same topology setupThreeLevelFederation builds,
// parameterized for the handful of tests that need a deviation from it.
type threeLevelParams struct {
	taLifetime, i1Lifetime, leLifetime time.Duration // zero means 1 hour

	taAboutI1Signer *ecdsa.PrivateKey // zero means the real TA key
	taAboutI1JWKS   json.RawMessage   // zero means I1's own real JWKS

	taAboutI1Policy intfed.MetadataPolicy
	taAboutI1Crit   []string
	i1AboutLEPolicy intfed.MetadataPolicy
	i1AboutLECrit   []string
}

func buildThreeLevelFederation(t *testing.T, p threeLevelParams) *threeLevelFederation {
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

	sign := func(cp intfed.CreateParams) string {
		token, err := intfed.Create(cp)
		if err != nil {
			t.Fatalf("intfed.Create: %v", err)
		}
		return token
	}
	lifetime := func(d time.Duration) time.Duration {
		if d == 0 {
			return time.Hour
		}
		return d
	}

	taAboutI1Signer := taKey
	if p.taAboutI1Signer != nil {
		taAboutI1Signer = p.taAboutI1Signer
	}
	taAboutI1JWKS := i1JWKS
	if p.taAboutI1JWKS != nil {
		taAboutI1JWKS = p.taAboutI1JWKS
	}

	taConfig := sign(intfed.CreateParams{
		Signer: taKey, Algorithm: fapi.ES256, KeyID: "ta",
		Issuer: taID, Subject: taID, Now: now, Lifetime: lifetime(p.taLifetime), JWKS: taJWKS,
		Metadata: federationEntityMetadata(t, taID+"/fetch"),
	})
	taAboutI1 := sign(intfed.CreateParams{
		Signer: taAboutI1Signer, Algorithm: fapi.ES256, KeyID: "ta",
		Issuer: taID, Subject: i1ID, Now: now, Lifetime: lifetime(p.taLifetime), JWKS: taAboutI1JWKS,
		MetadataPolicy: p.taAboutI1Policy, MetadataPolicyCritical: p.taAboutI1Crit,
	})
	i1Config := sign(intfed.CreateParams{
		Signer: i1Key, Algorithm: fapi.ES256, KeyID: "i1",
		Issuer: i1ID, Subject: i1ID, Now: now, Lifetime: lifetime(p.i1Lifetime), JWKS: i1JWKS,
		AuthorityHints: []string{taID},
		Metadata:       federationEntityMetadata(t, i1ID+"/fetch"),
	})
	i1AboutLE := sign(intfed.CreateParams{
		Signer: i1Key, Algorithm: fapi.ES256, KeyID: "i1",
		Issuer: i1ID, Subject: leID, Now: now, Lifetime: lifetime(p.i1Lifetime), JWKS: leJWKS,
		MetadataPolicy: p.i1AboutLEPolicy, MetadataPolicyCritical: p.i1AboutLECrit,
	})
	leConfig := sign(intfed.CreateParams{
		Signer: leKey, Algorithm: fapi.ES256, KeyID: "le",
		Issuer: leID, Subject: leID, Now: now, Lifetime: lifetime(p.leLifetime), JWKS: leJWKS,
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

	return &threeLevelFederation{
		taID: taID, i1ID: i1ID, leID: leID,
		taKey: taKey, i1Key: i1Key, leKey: leKey,
		taJWKS: taJWKS, i1JWKS: i1JWKS, leJWKS: leJWKS,
		fetcher: fetcherFor(t, taServer, i1Server, leServer), now: now,
	}
}

func TestResolveTracksEarliestExpiryAcrossChain(t *testing.T) {
	f := buildThreeLevelFederation(t, threeLevelParams{
		taLifetime: 30 * time.Minute, i1Lifetime: 90 * time.Minute, leLifetime: 2 * time.Hour,
	})
	r, err := federation.NewResolver(federation.Config{
		TrustAnchors: []federation.TrustAnchor{{EntityID: f.taID, JWKS: f.taJWKS}},
		Limits:       federation.Limits{MaxPathLength: 5, MaxStatementLifetime: 3 * time.Hour, MaxClockSkew: 5 * time.Second},
	}, federation.Dependencies{HTTP: f.fetcher, Clock: fixedClock{now: f.now}})
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	result, err := r.Resolve(context.Background(), f.leID)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	// exp is a NumericDate (whole seconds) on the wire, so compare
	// against a similarly truncated expectation rather than f.now's own
	// sub-second precision.
	wantExpiry := f.now.Add(30 * time.Minute).Truncate(time.Second)
	if !result.ExpiresAt.Equal(wantExpiry) {
		t.Errorf("ExpiresAt = %v, want the earliest exp across the chain (TA's own, %v)", result.ExpiresAt, wantExpiry)
	}
}

func TestResolveRejectsSubordinateStatementFromTrustAnchorWrongSignature(t *testing.T) {
	wrongSigner := generateKey(t)
	f := buildThreeLevelFederation(t, threeLevelParams{taAboutI1Signer: wrongSigner})
	r := f.newResolver(t)
	if _, err := r.Resolve(context.Background(), f.leID); err == nil {
		t.Fatalf("Resolve(trust anchor's subordinate statement about I1 signed by the wrong key) = nil error, want error")
	}
}

func TestResolveRejectsSubordinateStatementWithMismatchedVouchedJWKS(t *testing.T) {
	wrongI1Key := generateKey(t)
	f := buildThreeLevelFederation(t, threeLevelParams{
		taAboutI1JWKS: jwksFor(t, "wrong-i1", wrongI1Key),
	})
	r := f.newResolver(t)
	if _, err := r.Resolve(context.Background(), f.leID); err == nil {
		t.Fatalf("Resolve(trust anchor vouches for a different I1 key than I1's own statement about LE was actually signed with) = nil error, want error")
	}
}

func TestResolveMergesMetadataPolicyCritAcrossLevels(t *testing.T) {
	f := buildThreeLevelFederation(t, threeLevelParams{
		taAboutI1Policy: mustPolicy(t, `{"openid_relying_party":{"subject_type":{"value":"pairwise"}}}`),
		taAboutI1Crit:   []string{"a", "b"},
		i1AboutLEPolicy: mustPolicy(t, `{"openid_relying_party":{"subject_type":{"value":"pairwise"}}}`),
		i1AboutLECrit:   []string{"b", "c"},
	})
	r := f.newResolver(t)
	if _, err := r.Resolve(context.Background(), f.leID); err != nil {
		t.Fatalf("Resolve: %v", err)
	}
}

func TestResolveRejectsConflictingMetadataPolicyAcrossLevels(t *testing.T) {
	f := buildThreeLevelFederation(t, threeLevelParams{
		taAboutI1Policy: mustPolicy(t, `{"openid_relying_party":{"subject_type":{"value":"pairwise"}}}`),
		i1AboutLEPolicy: mustPolicy(t, `{"openid_relying_party":{"subject_type":{"value":"public"}}}`),
	})
	r := f.newResolver(t)
	if _, err := r.Resolve(context.Background(), f.leID); err == nil {
		t.Fatalf("Resolve(conflicting \"value\" policy across the chain) = nil error, want error")
	}
}

func TestResolveRejectsMetadataPolicyRequiringAbsentClaim(t *testing.T) {
	f := buildThreeLevelFederation(t, threeLevelParams{
		taAboutI1Policy: mustPolicy(t, `{"openid_relying_party":{"nonexistent_claim":{"essential":true}}}`),
	})
	r := f.newResolver(t)
	if _, err := r.Resolve(context.Background(), f.leID); err == nil {
		t.Fatalf("Resolve(essential claim required by policy but absent from the leaf's own metadata) = nil error, want error")
	}
}

func TestResolveSkipsUnreachableOrInvalidHintsToReachSuperior(t *testing.T) {
	now := time.Now()

	// A hint whose own Entity Configuration has a self-inconsistent
	// iss/sub — findReachableSuperior must skip it and keep trying.
	mismatchKey := generateKey(t)
	mismatchID, mismatchTS := singleEntityServer(t, func(id string) string {
		token, err := intfed.Create(intfed.CreateParams{
			Signer: mismatchKey, Algorithm: fapi.ES256, KeyID: "m",
			Issuer: id, Subject: "https://someone-else.example.org",
			Now: now, Lifetime: time.Hour, JWKS: jwksFor(t, "m", mismatchKey),
		})
		if err != nil {
			t.Fatalf("intfed.Create: %v", err)
		}
		return token
	}, nil)

	// A hint whose Entity Configuration is self-consistent (iss==sub)
	// but doesn't self-verify — signed by a different key than it
	// claims to hold.
	selfSigWrongKey, claimedKey := generateKey(t), generateKey(t)
	selfSigID, selfSigTS := singleEntityServer(t, func(id string) string {
		token, err := intfed.Create(intfed.CreateParams{
			Signer: selfSigWrongKey, Algorithm: fapi.ES256, KeyID: "s",
			Issuer: id, Subject: id, Now: now, Lifetime: time.Hour,
			JWKS: jwksFor(t, "s", claimedKey),
		})
		if err != nil {
			t.Fatalf("intfed.Create: %v", err)
		}
		return token
	}, nil)

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

	sign := func(cp intfed.CreateParams) string {
		token, err := intfed.Create(cp)
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
	})
	i1Config := sign(intfed.CreateParams{
		Signer: i1Key, Algorithm: fapi.ES256, KeyID: "i1",
		Issuer: i1ID, Subject: i1ID, Now: now, Lifetime: time.Hour, JWKS: i1JWKS,
		// leID is already visited by the time I1 becomes entityAt
		// (exercises the visited-skip branch); mismatchID and
		// selfSigID are reachable but invalid, exercising
		// findReachableSuperior's own error-tolerant skip; taID is
		// the only hint that actually succeeds.
		AuthorityHints: []string{leID, mismatchID, selfSigID, taID},
		Metadata:       federationEntityMetadata(t, i1ID+"/fetch"),
	})
	i1AboutLE := sign(intfed.CreateParams{
		Signer: i1Key, Algorithm: fapi.ES256, KeyID: "i1",
		Issuer: i1ID, Subject: leID, Now: now, Lifetime: time.Hour, JWKS: leJWKS,
	})
	leConfig := sign(intfed.CreateParams{
		Signer: leKey, Algorithm: fapi.ES256, KeyID: "le",
		Issuer: leID, Subject: leID, Now: now, Lifetime: time.Hour, JWKS: leJWKS,
		AuthorityHints: []string{i1ID},
	})

	taMux.HandleFunc("/.well-known/openid-federation", serveStatement(taConfig))
	taMux.HandleFunc("/fetch", serveFetch(map[string]string{i1ID: taAboutI1}))
	i1Mux.HandleFunc("/.well-known/openid-federation", serveStatement(i1Config))
	i1Mux.HandleFunc("/fetch", serveFetch(map[string]string{leID: i1AboutLE}))
	leMux.HandleFunc("/.well-known/openid-federation", serveStatement(leConfig))

	fetcher := fetcherFor(t, taServer, i1Server, leServer, mismatchTS, selfSigTS)
	r, err := federation.NewResolver(federation.Config{
		TrustAnchors: []federation.TrustAnchor{{EntityID: taID, JWKS: taJWKS}},
		Limits:       federation.Limits{MaxPathLength: 5, MaxStatementLifetime: 2 * time.Hour, MaxClockSkew: 5 * time.Second},
	}, federation.Dependencies{HTTP: fetcher, Clock: fixedClock{now: now}})
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}

	result, err := r.Resolve(context.Background(), leID)
	if err != nil {
		t.Fatalf("Resolve(should skip the visited/mismatched/unverifiable hints and reach TA via the last hint): %v", err)
	}
	if result.TrustAnchor != taID {
		t.Errorf("TrustAnchor = %q, want %q", result.TrustAnchor, taID)
	}
}

func TestResolveRejectsMalformedTrustAnchorJWKS(t *testing.T) {
	f := setupThreeLevelFederation(t)
	r, err := federation.NewResolver(federation.Config{
		TrustAnchors: []federation.TrustAnchor{{EntityID: f.taID, JWKS: json.RawMessage(`not-json`)}},
		Limits:       federation.Limits{MaxPathLength: 5, MaxStatementLifetime: 2 * time.Hour, MaxClockSkew: 5 * time.Second},
	}, federation.Dependencies{HTTP: f.fetcher, Clock: fixedClock{now: f.now}})
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	if _, err := r.Resolve(context.Background(), f.taID); err == nil {
		t.Fatalf("Resolve(malformed trust anchor jwks) = nil error, want error")
	}
}

func TestResolveSkipsCandidateKeysWithWrongAlgorithm(t *testing.T) {
	f := setupThreeLevelFederation(t)

	wrongAlgPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	wrongJWK, err := jose.NewJWK(wrongAlgPub, fapi.EdDSA)
	if err != nil {
		t.Fatalf("jose.NewJWK: %v", err)
	}
	wrongEntry, err := wrongJWK.WithKeyID("wrong-alg").MarshalJSON()
	if err != nil {
		t.Fatalf("marshal jwk: %v", err)
	}
	realJWK, err := jose.NewJWK(&f.taKey.PublicKey, fapi.ES256)
	if err != nil {
		t.Fatalf("jose.NewJWK: %v", err)
	}
	realEntry, err := realJWK.WithKeyID("ta").MarshalJSON()
	if err != nil {
		t.Fatalf("marshal jwk: %v", err)
	}
	mixedJWKS, err := json.Marshal(map[string][]json.RawMessage{"keys": {wrongEntry, realEntry}})
	if err != nil {
		t.Fatalf("marshal jwk set: %v", err)
	}

	r, err := federation.NewResolver(federation.Config{
		TrustAnchors: []federation.TrustAnchor{{EntityID: f.taID, JWKS: mixedJWKS}},
		Limits:       federation.Limits{MaxPathLength: 5, MaxStatementLifetime: 2 * time.Hour, MaxClockSkew: 5 * time.Second},
	}, federation.Dependencies{HTTP: f.fetcher, Clock: fixedClock{now: f.now}})
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	if _, err := r.Resolve(context.Background(), f.taID); err != nil {
		t.Fatalf("Resolve(trust anchor jwks includes an unrelated-algorithm key alongside the real one): %v", err)
	}
}
