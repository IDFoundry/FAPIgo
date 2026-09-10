package federation_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
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

type fixedClock struct{ now time.Time }

func (c fixedClock) Now() time.Time { return c.now }

func generateKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return key
}

func jwksFor(t *testing.T, kid string, key *ecdsa.PrivateKey) json.RawMessage {
	t.Helper()
	jwk, err := jose.NewJWK(&key.PublicKey, fapi.ES256)
	if err != nil {
		t.Fatalf("jose.NewJWK: %v", err)
	}
	jwkJSON, err := jwk.WithKeyID(kid).MarshalJSON()
	if err != nil {
		t.Fatalf("marshal jwk: %v", err)
	}
	set, err := json.Marshal(map[string][]json.RawMessage{"keys": {jwkJSON}})
	if err != nil {
		t.Fatalf("marshal jwk set: %v", err)
	}
	return set
}

// serveStatement always returns token as an Entity Statement response.
func serveStatement(token string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/entity-statement+jwt")
		w.Write([]byte(token))
	}
}

// serveFetch implements a federation_fetch_endpoint over bySubject,
// keyed by the "sub" query parameter (OpenID Federation 1.0 §8.1.1).
func serveFetch(bySubject map[string]string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sub := r.URL.Query().Get("sub")
		token, ok := bySubject[sub]
		if !ok {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"error":"not_found"}`))
			return
		}
		w.Header().Set("Content-Type", "application/entity-statement+jwt")
		w.Write([]byte(token))
	}
}

func federationEntityMetadata(t *testing.T, fetchEndpoint string) map[string]json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(map[string]string{"federation_fetch_endpoint": fetchEndpoint})
	if err != nil {
		t.Fatalf("marshal federation_entity metadata: %v", err)
	}
	return map[string]json.RawMessage{"federation_entity": raw}
}

// threeLevelFederation sets up a real three-entity federation over
// HTTPS test servers: a Trust Anchor (TA), one Intermediate (I1), and a
// Leaf (LE) — TA -> I1 -> LE, mirroring OpenID Federation 1.0 §9.2's
// own worked example topology. I1's own Subordinate Statement about LE
// carries a metadata_policy (openid_relying_party.subject_type:
// {"value": "pairwise"}) so tests can confirm policy application, not
// just chain validation, actually happened.
type threeLevelFederation struct {
	taID, i1ID, leID       string
	taKey, i1Key, leKey    *ecdsa.PrivateKey
	taJWKS, i1JWKS, leJWKS json.RawMessage
	fetcher                *fapihttp.Client
	now                    time.Time
}

func setupThreeLevelFederation(t *testing.T) *threeLevelFederation {
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
		MetadataPolicy: mustPolicy(t, `{"openid_relying_party":{"subject_type":{"value":"pairwise"}}}`),
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

	return &threeLevelFederation{
		taID: taID, i1ID: i1ID, leID: leID,
		taKey: taKey, i1Key: i1Key, leKey: leKey,
		taJWKS: taJWKS, i1JWKS: i1JWKS, leJWKS: leJWKS,
		fetcher: fetcher, now: now,
	}
}

func (f *threeLevelFederation) newResolver(t *testing.T) *federation.Resolver {
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

func TestResolveThreeLevelChain(t *testing.T) {
	f := setupThreeLevelFederation(t)
	r := f.newResolver(t)

	result, err := r.Resolve(context.Background(), f.leID)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if result.EntityID != f.leID {
		t.Errorf("EntityID = %q, want %q", result.EntityID, f.leID)
	}
	if result.TrustAnchor != f.taID {
		t.Errorf("TrustAnchor = %q, want %q", result.TrustAnchor, f.taID)
	}
	wantChain := []string{f.leID, f.i1ID, f.taID}
	if len(result.Chain) != len(wantChain) {
		t.Fatalf("Chain = %v, want %v", result.Chain, wantChain)
	}
	for i, id := range wantChain {
		if result.Chain[i] != id {
			t.Errorf("Chain[%d] = %q, want %q", i, result.Chain[i], id)
		}
	}

	rp, ok := result.Metadata["openid_relying_party"]
	if !ok {
		t.Fatalf("Metadata missing openid_relying_party: %v", result.Metadata)
	}
	var claims map[string]json.RawMessage
	if err := json.Unmarshal(rp, &claims); err != nil {
		t.Fatalf("unmarshal resolved openid_relying_party: %v", err)
	}
	var subjectType string
	if err := json.Unmarshal(claims["subject_type"], &subjectType); err != nil || subjectType != "pairwise" {
		t.Errorf("subject_type = %s, want \"pairwise\" (from I1's own policy)", claims["subject_type"])
	}
	var redirectURIs []string
	if err := json.Unmarshal(claims["redirect_uris"], &redirectURIs); err != nil || len(redirectURIs) != 1 {
		t.Errorf("redirect_uris = %s, want the leaf's own declared value to pass through", claims["redirect_uris"])
	}
}

func TestResolveSubjectIsTrustAnchor(t *testing.T) {
	f := setupThreeLevelFederation(t)
	r := f.newResolver(t)

	result, err := r.Resolve(context.Background(), f.taID)
	if err != nil {
		t.Fatalf("Resolve(trust anchor itself): %v", err)
	}
	if result.TrustAnchor != f.taID || len(result.Chain) != 1 || result.Chain[0] != f.taID {
		t.Errorf("result = %+v, want a degenerate zero-hop chain naming only the trust anchor", result)
	}
}

func TestResolveRejectsUntrustedFederation(t *testing.T) {
	f := setupThreeLevelFederation(t)
	// A resolver configured with a *different* trust anchor key for the
	// same entity ID must not accept this federation's chain — the
	// live fetch alone must never establish trust.
	wrongKey := generateKey(t)
	r, err := federation.NewResolver(federation.Config{
		TrustAnchors: []federation.TrustAnchor{{EntityID: f.taID, JWKS: jwksFor(t, "wrong", wrongKey)}},
		Limits:       federation.Limits{MaxPathLength: 5, MaxStatementLifetime: 2 * time.Hour, MaxClockSkew: 5 * time.Second},
	}, federation.Dependencies{HTTP: f.fetcher, Clock: fixedClock{now: f.now}})
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	if _, err := r.Resolve(context.Background(), f.leID); err == nil {
		t.Fatalf("Resolve(wrong trust anchor key) = nil error, want error")
	}
}

func TestResolveRejectsUnconfiguredTrustAnchor(t *testing.T) {
	f := setupThreeLevelFederation(t)
	// A resolver that doesn't trust f.taID at all has no path to any
	// trust anchor, and MaxPathLength eventually bounds the walk.
	otherAnchorKey := generateKey(t)
	r, err := federation.NewResolver(federation.Config{
		TrustAnchors: []federation.TrustAnchor{{EntityID: "https://not-this-federation.example.org", JWKS: jwksFor(t, "other", otherAnchorKey)}},
		Limits:       federation.Limits{MaxPathLength: 5, MaxStatementLifetime: 2 * time.Hour, MaxClockSkew: 5 * time.Second},
	}, federation.Dependencies{HTTP: f.fetcher, Clock: fixedClock{now: f.now}})
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	if _, err := r.Resolve(context.Background(), f.leID); err == nil {
		t.Fatalf("Resolve(no configured trust anchor reachable) = nil error, want error")
	}
}

func TestResolveEnforcesMaxPathLength(t *testing.T) {
	f := setupThreeLevelFederation(t)
	r, err := federation.NewResolver(federation.Config{
		TrustAnchors: []federation.TrustAnchor{{EntityID: f.taID, JWKS: f.taJWKS}},
		// LE -> I1 -> TA is already 1 intermediate hop (I1) plus the
		// trust anchor itself; a limit of 1 hop total (the first
		// authority_hints fetch, I1) is exceeded before TA is ever
		// reached.
		Limits: federation.Limits{MaxPathLength: 1, MaxStatementLifetime: 2 * time.Hour, MaxClockSkew: 5 * time.Second},
	}, federation.Dependencies{HTTP: f.fetcher, Clock: fixedClock{now: f.now}})
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	if _, err := r.Resolve(context.Background(), f.leID); err == nil {
		t.Fatalf("Resolve(exceeds max path length) = nil error, want error")
	}
}

func TestResolveRejectsExpiredStatement(t *testing.T) {
	f := setupThreeLevelFederation(t)
	r, err := federation.NewResolver(federation.Config{
		TrustAnchors: []federation.TrustAnchor{{EntityID: f.taID, JWKS: f.taJWKS}},
		Limits:       federation.Limits{MaxPathLength: 5, MaxStatementLifetime: 2 * time.Hour, MaxClockSkew: 5 * time.Second},
	}, federation.Dependencies{
		HTTP: f.fetcher,
		// Every statement was issued "now" (f.now) with a 1-hour
		// lifetime; resolving as of 2 hours later must fail.
		Clock: fixedClock{now: f.now.Add(2 * time.Hour)},
	})
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	if _, err := r.Resolve(context.Background(), f.leID); err == nil {
		t.Fatalf("Resolve(expired chain) = nil error, want error")
	}
}

func TestNewResolverRejectsInvalidConfig(t *testing.T) {
	validTrustAnchors := []federation.TrustAnchor{{EntityID: "https://ta.example.org", JWKS: json.RawMessage(`{"keys":[]}`)}}
	validLimits := federation.Limits{MaxPathLength: 5, MaxStatementLifetime: time.Hour, MaxClockSkew: time.Second}
	validDeps := federation.Dependencies{HTTP: mustFetcher(t), Clock: federation.SystemClock{}}

	cases := map[string]func(*federation.Config, *federation.Dependencies){
		"no trust anchors": func(c *federation.Config, d *federation.Dependencies) { c.TrustAnchors = nil },
		"trust anchor missing id": func(c *federation.Config, d *federation.Dependencies) {
			c.TrustAnchors = []federation.TrustAnchor{{JWKS: json.RawMessage(`{}`)}}
		},
		"trust anchor missing jwks": func(c *federation.Config, d *federation.Dependencies) {
			c.TrustAnchors = []federation.TrustAnchor{{EntityID: "https://ta.example.org"}}
		},
		"zero max path length":        func(c *federation.Config, d *federation.Dependencies) { c.Limits.MaxPathLength = 0 },
		"zero max statement lifetime": func(c *federation.Config, d *federation.Dependencies) { c.Limits.MaxStatementLifetime = 0 },
		"negative max clock skew":     func(c *federation.Config, d *federation.Dependencies) { c.Limits.MaxClockSkew = -time.Second },
		"nil http":                    func(c *federation.Config, d *federation.Dependencies) { d.HTTP = nil },
		"nil clock":                   func(c *federation.Config, d *federation.Dependencies) { d.Clock = nil },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := federation.Config{TrustAnchors: validTrustAnchors, Limits: validLimits}
			deps := validDeps
			mutate(&cfg, &deps)
			if _, err := federation.NewResolver(cfg, deps); err == nil {
				t.Fatalf("NewResolver(%s) = nil error, want error", name)
			}
		})
	}
}

func mustFetcher(t *testing.T) *fapihttp.Client {
	t.Helper()
	c, err := fapihttp.New(http.DefaultClient, fapihttp.Config{
		MaxResponseBytes: 1 << 16, RequestTimeout: 5 * time.Second, MaxRedirects: 1,
	})
	if err != nil {
		t.Fatalf("fapihttp.New: %v", err)
	}
	return c
}

func mustPolicy(t *testing.T, raw string) intfed.MetadataPolicy {
	t.Helper()
	var p intfed.MetadataPolicy
	if err := json.Unmarshal([]byte(raw), &p); err != nil {
		t.Fatalf("unmarshal policy: %v", err)
	}
	return p
}

func TestResolveRejectsEmptySubject(t *testing.T) {
	f := setupThreeLevelFederation(t)
	r := f.newResolver(t)
	if _, err := r.Resolve(context.Background(), ""); err == nil {
		t.Fatalf("Resolve(\"\") = nil error, want error")
	}
}

// singleEntityServer starts one httptest.TLSServer serving a
// caller-controlled Entity Configuration (and, if fetchResponses is
// non-nil, a /fetch endpoint) — for tests that only need to break one
// specific entity's own responses, without standing up a full
// three-level federation.
func singleEntityServer(t *testing.T, configureToken func(entityID string) string, fetchResponses map[string]string) (entityID string, server *httptest.Server) {
	t.Helper()
	mux := http.NewServeMux()
	ts := httptest.NewTLSServer(mux)
	t.Cleanup(ts.Close)
	entityID = ts.URL
	mux.HandleFunc("/.well-known/openid-federation", serveStatement(configureToken(entityID)))
	if fetchResponses != nil {
		mux.HandleFunc("/fetch", serveFetch(fetchResponses))
	}
	return entityID, ts
}

func fetcherFor(t *testing.T, servers ...*httptest.Server) *fapihttp.Client {
	t.Helper()
	pool := x509.NewCertPool()
	for _, s := range servers {
		pool.AddCert(s.Certificate())
	}
	httpClient := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}
	fetcher, err := fapihttp.New(httpClient, fapihttp.Config{
		MaxResponseBytes: 1 << 16, RequestTimeout: 5 * time.Second, MaxRedirects: 1,
		AllowLoopbackHTTP: true,
	})
	if err != nil {
		t.Fatalf("fapihttp.New: %v", err)
	}
	return fetcher
}

func TestResolveRejectsEntityConfigurationIssuerSubjectMismatch(t *testing.T) {
	key := generateKey(t)
	now := time.Now()
	entityID, ts := singleEntityServer(t, func(id string) string {
		token, err := intfed.Create(intfed.CreateParams{
			Signer: key, Algorithm: fapi.ES256, KeyID: "k",
			// sub deliberately wrong (not equal to id, i.e. not equal
			// to this server's own entity identifier).
			Issuer: id, Subject: "https://someone-else.example.org",
			Now: now, Lifetime: time.Hour, JWKS: jwksFor(t, "k", key),
		})
		if err != nil {
			t.Fatalf("intfed.Create: %v", err)
		}
		return token
	}, nil)

	anchorKey := generateKey(t)
	r, err := federation.NewResolver(federation.Config{
		TrustAnchors: []federation.TrustAnchor{{EntityID: "https://ta.example.org", JWKS: jwksFor(t, "a", anchorKey)}},
		Limits:       federation.Limits{MaxPathLength: 5, MaxStatementLifetime: 2 * time.Hour, MaxClockSkew: 5 * time.Second},
	}, federation.Dependencies{HTTP: fetcherFor(t, ts), Clock: fixedClock{now: now}})
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	if _, err := r.Resolve(context.Background(), entityID); err == nil {
		t.Fatalf("Resolve(iss/sub mismatch) = nil error, want error")
	}
}

func TestResolveRejectsSelfSignatureNotMatchingOwnJWKS(t *testing.T) {
	signingKey := generateKey(t)
	claimedKey := generateKey(t) // different key: statement claims these in jwks, but is signed by signingKey
	now := time.Now()
	entityID, ts := singleEntityServer(t, func(id string) string {
		token, err := intfed.Create(intfed.CreateParams{
			Signer: signingKey, Algorithm: fapi.ES256, KeyID: "claimed",
			Issuer: id, Subject: id, Now: now, Lifetime: time.Hour,
			JWKS: jwksFor(t, "claimed", claimedKey), // doesn't match signingKey
		})
		if err != nil {
			t.Fatalf("intfed.Create: %v", err)
		}
		return token
	}, nil)

	anchorKey := generateKey(t)
	r, err := federation.NewResolver(federation.Config{
		TrustAnchors: []federation.TrustAnchor{{EntityID: "https://ta.example.org", JWKS: jwksFor(t, "a", anchorKey)}},
		Limits:       federation.Limits{MaxPathLength: 5, MaxStatementLifetime: 2 * time.Hour, MaxClockSkew: 5 * time.Second},
	}, federation.Dependencies{HTTP: fetcherFor(t, ts), Clock: fixedClock{now: now}})
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	if _, err := r.Resolve(context.Background(), entityID); err == nil {
		t.Fatalf("Resolve(self-signature doesn't match own claimed jwks) = nil error, want error")
	}
}

func TestResolveRejectsNoAuthorityHintsAndNotTrustAnchor(t *testing.T) {
	key := generateKey(t)
	now := time.Now()
	entityID, ts := singleEntityServer(t, func(id string) string {
		token, err := intfed.Create(intfed.CreateParams{
			Signer: key, Algorithm: fapi.ES256, KeyID: "k",
			Issuer: id, Subject: id, Now: now, Lifetime: time.Hour, JWKS: jwksFor(t, "k", key),
			// No AuthorityHints, and this entity isn't a configured
			// trust anchor either: a dead end.
		})
		if err != nil {
			t.Fatalf("intfed.Create: %v", err)
		}
		return token
	}, nil)

	anchorKey := generateKey(t)
	r, err := federation.NewResolver(federation.Config{
		TrustAnchors: []federation.TrustAnchor{{EntityID: "https://ta.example.org", JWKS: jwksFor(t, "a", anchorKey)}},
		Limits:       federation.Limits{MaxPathLength: 5, MaxStatementLifetime: 2 * time.Hour, MaxClockSkew: 5 * time.Second},
	}, federation.Dependencies{HTTP: fetcherFor(t, ts), Clock: fixedClock{now: now}})
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	if _, err := r.Resolve(context.Background(), entityID); err == nil {
		t.Fatalf("Resolve(dead end, no hints, not a trust anchor) = nil error, want error")
	}
}

func TestResolveRejectsUnreachableSuperior(t *testing.T) {
	key := generateKey(t)
	now := time.Now()
	entityID, ts := singleEntityServer(t, func(id string) string {
		token, err := intfed.Create(intfed.CreateParams{
			Signer: key, Algorithm: fapi.ES256, KeyID: "k",
			Issuer: id, Subject: id, Now: now, Lifetime: time.Hour, JWKS: jwksFor(t, "k", key),
			AuthorityHints: []string{"https://nonexistent-superior.example.invalid"},
		})
		if err != nil {
			t.Fatalf("intfed.Create: %v", err)
		}
		return token
	}, nil)

	anchorKey := generateKey(t)
	r, err := federation.NewResolver(federation.Config{
		TrustAnchors: []federation.TrustAnchor{{EntityID: "https://ta.example.org", JWKS: jwksFor(t, "a", anchorKey)}},
		Limits:       federation.Limits{MaxPathLength: 5, MaxStatementLifetime: 2 * time.Hour, MaxClockSkew: 5 * time.Second},
	}, federation.Dependencies{HTTP: fetcherFor(t, ts), Clock: fixedClock{now: now}})
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	if _, err := r.Resolve(context.Background(), entityID); err == nil {
		t.Fatalf("Resolve(unreachable superior) = nil error, want error")
	}
}

func TestResolveRejectsMissingFederationFetchEndpoint(t *testing.T) {
	f := setupThreeLevelFederation(t)
	// Rebuild I1's own server to omit federation_entity metadata
	// entirely (no federation_fetch_endpoint) — TA can no longer fetch
	// a subordinate statement about I1... actually here we exercise the
	// symmetric case: I1 itself never advertises a fetch endpoint, so
	// nothing can ever fetch a statement about LE from I1.
	mux := http.NewServeMux()
	ts := httptest.NewTLSServer(mux)
	t.Cleanup(ts.Close)
	i1ID := ts.URL
	i1Key := generateKey(t)
	i1JWKS := jwksFor(t, "i1", i1Key)
	i1Config, err := intfed.Create(intfed.CreateParams{
		Signer: i1Key, Algorithm: fapi.ES256, KeyID: "i1",
		Issuer: i1ID, Subject: i1ID, Now: f.now, Lifetime: time.Hour, JWKS: i1JWKS,
		AuthorityHints: []string{f.taID},
		// No Metadata at all: no federation_entity.federation_fetch_endpoint.
	})
	if err != nil {
		t.Fatalf("intfed.Create: %v", err)
	}
	mux.HandleFunc("/.well-known/openid-federation", serveStatement(i1Config))

	leKey := generateKey(t)
	leEntityID, leTS := singleEntityServer(t, func(id string) string {
		token, err := intfed.Create(intfed.CreateParams{
			Signer: leKey, Algorithm: fapi.ES256, KeyID: "le",
			Issuer: id, Subject: id, Now: f.now, Lifetime: time.Hour, JWKS: jwksFor(t, "le", leKey),
			AuthorityHints: []string{i1ID},
		})
		if err != nil {
			t.Fatalf("intfed.Create: %v", err)
		}
		return token
	}, nil)

	r, err := federation.NewResolver(federation.Config{
		TrustAnchors: []federation.TrustAnchor{{EntityID: f.taID, JWKS: f.taJWKS}},
		Limits:       federation.Limits{MaxPathLength: 5, MaxStatementLifetime: 2 * time.Hour, MaxClockSkew: 5 * time.Second},
	}, federation.Dependencies{HTTP: fetcherFor(t, ts, leTS), Clock: fixedClock{now: f.now}})
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	if _, err := r.Resolve(context.Background(), leEntityID); err == nil {
		t.Fatalf("Resolve(superior has no federation_fetch_endpoint) = nil error, want error")
	}
}

func TestWellKnownURLRejectsInvalidEntityID(t *testing.T) {
	now := time.Now()
	anchorKey := generateKey(t)
	r, err := federation.NewResolver(federation.Config{
		TrustAnchors: []federation.TrustAnchor{{EntityID: "https://ta.example.org", JWKS: jwksFor(t, "a", anchorKey)}},
		Limits:       federation.Limits{MaxPathLength: 5, MaxStatementLifetime: 2 * time.Hour, MaxClockSkew: 5 * time.Second},
	}, federation.Dependencies{HTTP: fetcherFor(t), Clock: fixedClock{now: now}})
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	for _, id := range []string{
		"not-a-url",
		"http://plain.example.org",   // wrong scheme
		"https://example.org/x#frag", // fragment not allowed
		"https://example.org/%zz",    // invalid percent-encoding: fails url.Parse itself
	} {
		if _, err := r.Resolve(context.Background(), id); err == nil {
			t.Errorf("Resolve(%q) = nil error, want error", id)
		}
	}
}
