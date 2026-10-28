package keys

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/jose"
)

// jwksServer serves each client's JWK Set at /<client ID>, counting
// fetches per path; a test may swap a client's document while it runs.
type jwksServer struct {
	ts *httptest.Server

	mu        sync.Mutex
	documents map[string][]byte
	fetches   map[string]int
}

func newJWKSServer(t *testing.T, documents map[fapi.ClientID][]byte) *jwksServer {
	t.Helper()
	s := &jwksServer{documents: map[string][]byte{}, fetches: map[string]int{}}
	for id, doc := range documents {
		s.documents["/"+id.String()] = doc
	}
	s.ts = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		doc, ok := s.documents[r.URL.Path]
		s.fetches[r.URL.Path]++
		s.mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(doc)
	}))
	t.Cleanup(s.ts.Close)
	return s
}

func (s *jwksServer) set(path string, doc []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.documents[path] = doc
}

func (s *jwksServer) fetchCount(path string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.fetches[path]
}

func (s *jwksServer) url(t *testing.T, path string) fapi.URL {
	t.Helper()
	u, err := fapi.ParseEndpointURL(s.ts.URL+path, fapi.AllowLoopbackHTTP())
	if err != nil {
		t.Fatalf("ParseEndpointURL: %v", err)
	}
	return u
}

// uriLookup registers each client in registrations at its jwks_uri;
// any other client is unknown.
type uriLookup struct {
	mu            sync.Mutex
	registrations map[fapi.ClientID]fapi.URL
}

func (l *uriLookup) lookup(_ context.Context, id fapi.ClientID) (fapi.URL, []byte, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	u, ok := l.registrations[id]
	if !ok {
		return fapi.URL{}, nil, fmt.Errorf("unknown client %q", id)
	}
	return u, nil, nil
}

func (l *uriLookup) register(id fapi.ClientID, u fapi.URL) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.registrations[id] = u
}

// newURISource is a ClientJWKSSource fetching each of documents' clients
// from a test server.
func newURISource(t *testing.T, documents map[fapi.ClientID][]byte, opts ...ClientJWKSOption) (*ClientJWKSSource, *jwksServer, *uriLookup) {
	t.Helper()
	srv := newJWKSServer(t, documents)
	l := &uriLookup{registrations: map[fapi.ClientID]fapi.URL{}}
	for id := range documents {
		l.register(id, srv.url(t, "/"+id.String()))
	}
	src, err := NewClientJWKSSource(testFetcher(t, srv.ts), l.lookup, opts...)
	if err != nil {
		t.Fatalf("NewClientJWKSSource: %v", err)
	}
	return src, srv, l
}

func TestClientJWKSSourceContractWithJWKSURI(t *testing.T) {
	TestClientKeySourceContract(t, func(t *testing.T, clients map[fapi.ClientID][]byte) ClientKeySource {
		src, _, _ := newURISource(t, clients)
		return src
	})
}

func TestClientJWKSSourceContractWithInlineJWKS(t *testing.T) {
	TestClientKeySourceContract(t, func(t *testing.T, clients map[fapi.ClientID][]byte) ClientKeySource {
		src, err := NewClientJWKSSource(nil, func(_ context.Context, id fapi.ClientID) (fapi.URL, []byte, error) {
			doc, ok := clients[id]
			if !ok {
				return fapi.URL{}, nil, errors.New("unknown client")
			}
			return fapi.URL{}, doc, nil
		})
		if err != nil {
			t.Fatalf("NewClientJWKSSource: %v", err)
		}
		return src
	})
}

// es256JWKS returns a JWK Set holding one new ES256 key per kid, and the
// keys.
func es256JWKS(t *testing.T, kids ...string) ([]byte, map[string]*ecdsa.PublicKey) {
	t.Helper()
	var set struct {
		Keys []jose.JWK `json:"keys"`
	}
	pubs := map[string]*ecdsa.PublicKey{}
	for _, kid := range kids {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("GenerateKey: %v", err)
		}
		jwk, err := jose.NewJWK(&k.PublicKey, fapi.ES256)
		if err != nil {
			t.Fatalf("NewJWK: %v", err)
		}
		set.Keys = append(set.Keys, jwk.WithKeyID(kid))
		pubs[kid] = &k.PublicKey
	}
	body, err := json.Marshal(set)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return body, pubs
}

func resolveES256(t *testing.T, src ClientKeySource, id fapi.ClientID, kid string) ([]VerificationKey, error) {
	t.Helper()
	set, err := src.ResolveVerificationKeys(context.Background(), ClientKeyRequest{
		ClientID: id, Purpose: ClientAssertionVerification, Algorithm: fapi.ES256, KeyID: kid,
	})
	return set.Keys, err
}

// TestClientJWKSSourceCachesPerClient: repeated lookups are served from
// one fetch per client, and each client's fetch is its own.
func TestClientJWKSSourceCachesPerClient(t *testing.T) {
	docA, _ := es256JWKS(t, "a1")
	docB, _ := es256JWKS(t, "b1")
	src, srv, _ := newURISource(t, map[fapi.ClientID][]byte{"a": docA, "b": docB})
	for range 5 {
		for _, c := range []struct {
			id  fapi.ClientID
			kid string
		}{{"a", "a1"}, {"b", "b1"}} {
			got, err := resolveES256(t, src, c.id, c.kid)
			if err != nil || len(got) != 1 {
				t.Fatalf("client %q: got %d keys, err %v; want 1", c.id, len(got), err)
			}
		}
	}
	if a, b := srv.fetchCount("/a"), srv.fetchCount("/b"); a != 1 || b != 1 {
		t.Fatalf("fetches a=%d b=%d, want 1 each", a, b)
	}
}

// TestClientJWKSSourceRefetchesOnRotation: a kid the cached set lacks
// (the client rotated keys) forces a refetch, once the minimum refresh
// interval has passed, and the new key then resolves.
func TestClientJWKSSourceRefetchesOnRotation(t *testing.T) {
	doc, _ := es256JWKS(t, "old")
	src, srv, _ := newURISource(t, map[fapi.ClientID][]byte{"a": doc}, WithClientJWKSCacheTTL(time.Hour), WithClientJWKSMinRefreshInterval(time.Minute))
	clock := newManualClock()
	src.now = clock.Now

	if got, err := resolveES256(t, src, "a", "old"); err != nil || len(got) != 1 {
		t.Fatalf("old kid: got %d keys, err %v", len(got), err)
	}
	rotated, pubs := es256JWKS(t, "new")
	srv.set("/a", rotated)

	// Within the minimum refresh interval of the first fetch, the miss
	// doesn't refetch.
	if got, err := resolveES256(t, src, "a", "new"); err != nil || len(got) != 0 {
		t.Fatalf("new kid within the interval: got %d keys, err %v; want none", len(got), err)
	}
	clock.Advance(2 * time.Minute)
	got, err := resolveES256(t, src, "a", "new")
	if err != nil || len(got) != 1 || !got[0].PublicKey.(*ecdsa.PublicKey).Equal(pubs["new"]) {
		t.Fatalf("new kid after the interval: got %+v, err %v; want the rotated key", got, err)
	}
	if n := srv.fetchCount("/a"); n != 2 {
		t.Fatalf("fetches = %d, want 2", n)
	}
}

// TestClientJWKSSourceRateLimitsUnknownKeyIDs: a stream of distinct
// unknown kids for one client (taken from unverified JWT headers) forces
// at most one refetch per minimum refresh interval, and a burst of them
// is single-flighted.
func TestClientJWKSSourceRateLimitsUnknownKeyIDs(t *testing.T) {
	doc, _ := es256JWKS(t, "known")
	src, srv, _ := newURISource(t, map[fapi.ClientID][]byte{"a": doc}, WithClientJWKSCacheTTL(time.Hour), WithClientJWKSMinRefreshInterval(time.Minute))
	clock := newManualClock()
	src.now = clock.Now

	var wg sync.WaitGroup
	var errs atomic.Int32
	for i := range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := resolveES256(t, src, "a", fmt.Sprintf("unknown-%d", i)); err != nil {
				errs.Add(1)
			}
		}()
	}
	wg.Wait()
	if errs.Load() != 0 {
		t.Fatalf("%d resolutions failed", errs.Load())
	}
	if n := srv.fetchCount("/a"); n != 1 {
		t.Fatalf("fetches after a burst of unknown kids = %d, want 1", n)
	}
	clock.Advance(2 * time.Minute)
	for i := range 10 {
		_, _ = resolveES256(t, src, "a", fmt.Sprintf("later-%d", i))
	}
	if n := srv.fetchCount("/a"); n != 2 {
		t.Fatalf("fetches after the interval = %d, want 2", n)
	}
}

// TestClientJWKSSourceFollowsJWKSURIChange: once a client's registered
// jwks_uri changes, its keys come from the new URI only — the old URI's
// keys, still fresh in the cache, never resolve for it again.
func TestClientJWKSSourceFollowsJWKSURIChange(t *testing.T) {
	oldDoc, _ := es256JWKS(t, "old")
	newDoc, pubs := es256JWKS(t, "new")
	src, srv, l := newURISource(t, map[fapi.ClientID][]byte{"a": oldDoc}, WithClientJWKSCacheTTL(time.Hour))
	srv.set("/a-moved", newDoc)

	if got, err := resolveES256(t, src, "a", "old"); err != nil || len(got) != 1 {
		t.Fatalf("before the change: got %d keys, err %v", len(got), err)
	}
	l.register("a", srv.url(t, "/a-moved"))

	if got, err := resolveES256(t, src, "a", "old"); err != nil || len(got) != 0 {
		t.Fatalf("old URI's kid after the change: got %d keys, err %v; want none", len(got), err)
	}
	got, err := resolveES256(t, src, "a", "")
	if err != nil || len(got) != 1 || !got[0].PublicKey.(*ecdsa.PublicKey).Equal(pubs["new"]) {
		t.Fatalf("after the change: got %+v, err %v; want only the new URI's key", got, err)
	}
	if n := srv.fetchCount("/a-moved"); n != 1 {
		t.Fatalf("fetches of the new URI = %d, want 1", n)
	}
}

// TestClientJWKSSourceFollowsInlineJWKSChange: the same for a client's
// inline jwks.
func TestClientJWKSSourceFollowsInlineJWKSChange(t *testing.T) {
	oldDoc, _ := es256JWKS(t, "k")
	newDoc, pubs := es256JWKS(t, "k")
	var mu sync.Mutex
	current := oldDoc
	src, err := NewClientJWKSSource(nil, func(context.Context, fapi.ClientID) (fapi.URL, []byte, error) {
		mu.Lock()
		defer mu.Unlock()
		return fapi.URL{}, current, nil
	})
	if err != nil {
		t.Fatalf("NewClientJWKSSource: %v", err)
	}
	if _, err := resolveES256(t, src, "a", "k"); err != nil {
		t.Fatalf("before: %v", err)
	}
	mu.Lock()
	current = newDoc
	mu.Unlock()
	got, err := resolveES256(t, src, "a", "k")
	if err != nil || len(got) != 1 || !got[0].PublicKey.(*ecdsa.PublicKey).Equal(pubs["k"]) {
		t.Fatalf("after the change: got %+v, err %v; want the new key", got, err)
	}
}

// TestClientJWKSSourceBacksOffAfterFailedFetch: a failing jwks_uri isn't
// refetched on every request, and the source fails closed.
func TestClientJWKSSourceBacksOffAfterFailedFetch(t *testing.T) {
	src, srv, l := newURISource(t, nil, WithClientJWKSRefreshBackoff(time.Minute))
	clock := newManualClock()
	src.now = clock.Now
	l.register("a", srv.url(t, "/missing"))
	for range 5 {
		if _, err := resolveES256(t, src, "a", ""); err == nil {
			t.Fatalf("resolution against a failing jwks_uri succeeded")
		}
	}
	if n := srv.fetchCount("/missing"); n != 1 {
		t.Fatalf("fetches = %d, want 1 within the backoff", n)
	}
	clock.Advance(2 * time.Minute)
	_, _ = resolveES256(t, src, "a", "")
	if n := srv.fetchCount("/missing"); n != 2 {
		t.Fatalf("fetches after the backoff = %d, want 2", n)
	}
}

// TestClientJWKSSourceBoundsCachedClients: past WithClientJWKSMaxClients
// a client's set is dropped and simply fetched again when next needed.
func TestClientJWKSSourceBoundsCachedClients(t *testing.T) {
	docs := map[fapi.ClientID][]byte{}
	for _, id := range []fapi.ClientID{"a", "b", "c"} {
		docs[id], _ = es256JWKS(t, "k")
	}
	src, _, _ := newURISource(t, docs, WithClientJWKSMaxClients(2))
	for _, id := range []fapi.ClientID{"a", "b", "c", "a"} {
		if got, err := resolveES256(t, src, id, "k"); err != nil || len(got) != 1 {
			t.Fatalf("client %q: got %d keys, err %v", id, len(got), err)
		}
		src.mu.Lock()
		n := len(src.entries)
		src.mu.Unlock()
		if n > 2 {
			t.Fatalf("%d clients cached, want at most 2", n)
		}
	}
}

func TestClientJWKSSourceRefusesBadRegistrations(t *testing.T) {
	doc, _ := es256JWKS(t, "k")
	srv := newJWKSServer(t, nil)
	uri := srv.url(t, "/a")
	cases := []struct {
		name    string
		fetcher bool
		uri     fapi.URL
		inline  []byte
		lookErr error
		want    string
	}{
		{name: "unknown client", lookErr: errors.New("no such client"), want: "no such client"},
		{name: "both jwks_uri and jwks", fetcher: true, uri: uri, inline: doc, want: "both jwks_uri and jwks"},
		{name: "jwks_uri without a fetcher", uri: uri, want: "no fetcher"},
		{name: "malformed inline jwks", inline: []byte(`{"keys":`), want: "parse jwks"},
		{name: "inline jwks with no usable key", inline: []byte(`{"keys":[{"kty":"oct","k":"AAAA"}]}`), want: "no usable keys"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var fetcher = testFetcher(t, srv.ts)
			if !c.fetcher {
				fetcher = nil
			}
			src, err := NewClientJWKSSource(fetcher, func(context.Context, fapi.ClientID) (fapi.URL, []byte, error) {
				return c.uri, c.inline, c.lookErr
			})
			if err != nil {
				t.Fatalf("NewClientJWKSSource: %v", err)
			}
			_, err = resolveES256(t, src, "a", "k")
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want one mentioning %q", err, c.want)
			}
		})
	}
}

// TestClientJWKSSourceClientWithNoKeys: a client registered with neither
// jwks_uri nor jwks resolves to an empty set, not an error.
func TestClientJWKSSourceClientWithNoKeys(t *testing.T) {
	src, err := NewClientJWKSSource(nil, func(context.Context, fapi.ClientID) (fapi.URL, []byte, error) {
		return fapi.URL{}, nil, nil
	})
	if err != nil {
		t.Fatalf("NewClientJWKSSource: %v", err)
	}
	got, err := resolveES256(t, src, "mtls-client", "")
	if err != nil || len(got) != 0 {
		t.Fatalf("got %d keys, err %v; want an empty set", len(got), err)
	}
}

func TestClientJWKSSourceResolvesEncryptionKeys(t *testing.T) {
	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	jwk, err := jose.NewEncryptionJWK(priv.PublicKey(), fapi.ECDHESA256KW)
	if err != nil {
		t.Fatalf("NewEncryptionJWK: %v", err)
	}
	body, err := json.Marshal(map[string]any{"keys": []any{jwk.WithKeyID("enc-1")}})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	src, _, _ := newURISource(t, map[fapi.ClientID][]byte{"a": body})
	set, err := src.ResolveEncryptionKeys(context.Background(), ClientEncryptionKeyRequest{ClientID: "a", Purpose: IDTokenEncryption, Algorithm: fapi.ECDHESA256KW})
	if err != nil || len(set.Keys) != 1 || set.Keys[0].KeyID != "enc-1" {
		t.Fatalf("got %+v, err %v; want enc-1", set.Keys, err)
	}
	if _, err := src.ResolveEncryptionKeys(context.Background(), ClientEncryptionKeyRequest{ClientID: "b", Purpose: IDTokenEncryption, Algorithm: fapi.ECDHESA256KW}); err == nil {
		t.Fatalf("unknown client: no error")
	}
}

func TestClientJWKSSourceCapabilities(t *testing.T) {
	lookup := func(context.Context, fapi.ClientID) (fapi.URL, []byte, error) { return fapi.URL{}, nil, nil }
	noFetcher, err := NewClientJWKSSource(nil, lookup)
	if err != nil {
		t.Fatalf("NewClientJWKSSource: %v", err)
	}
	if !noFetcher.Capabilities().LiveFetchHardened {
		t.Fatalf("a source with no fetcher fetches nothing, so should declare LiveFetchHardened")
	}
	srv := newJWKSServer(t, nil)
	loopback, err := NewClientJWKSSource(testFetcher(t, srv.ts), lookup)
	if err != nil {
		t.Fatalf("NewClientJWKSSource: %v", err)
	}
	if loopback.Capabilities().LiveFetchHardened {
		t.Fatalf("a fetcher granting a loopback exception isn't hardened for production")
	}
}

func TestNewClientJWKSSourceRefusesInvalidArguments(t *testing.T) {
	lookup := func(context.Context, fapi.ClientID) (fapi.URL, []byte, error) { return fapi.URL{}, nil, nil }
	cases := map[string]func() (*ClientJWKSSource, error){
		"nil lookup":     func() (*ClientJWKSSource, error) { return NewClientJWKSSource(nil, nil) },
		"zero cache TTL": func() (*ClientJWKSSource, error) { return NewClientJWKSSource(nil, lookup, WithClientJWKSCacheTTL(0)) },
		"zero max clients": func() (*ClientJWKSSource, error) {
			return NewClientJWKSSource(nil, lookup, WithClientJWKSMaxClients(0))
		},
	}
	for name, build := range cases {
		if _, err := build(); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}
