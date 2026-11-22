package server_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"strings"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/fapihttp"
	"github.com/idfoundry/fapigo/internal/jose"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/server"
)

// servedJWKS is a fapihttp.HTTPClient answering every request with its
// JWK Set, without a round trip over the network.
type servedJWKS []byte

func (doc servedJWKS) Do(*http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": {"application/json"}},
		Body:       io.NopCloser(bytes.NewReader(doc)),
	}, nil
}

// longestKeyID is a ClientKeySource recording the longest kid the
// server asks inner about.
type longestKeyID struct {
	inner   *keys.ClientJWKSSource
	longest int
}

func (l *longestKeyID) ResolveVerificationKeys(ctx context.Context, req keys.ClientKeyRequest) (keys.VerificationKeySet, error) {
	l.longest = max(l.longest, len(req.KeyID))
	return l.inner.ResolveVerificationKeys(ctx, req)
}

func (l *longestKeyID) Capabilities() keys.KeySourceCapabilities { return l.inner.Capabilities() }

// unsignedAssertion is a client assertion naming testClientID whose
// header names kid, with a one-byte signature: it parses, so the server
// looks its key up by kid, but it can never verify.
func unsignedAssertion(kid string, jti int) string {
	header := fmt.Sprintf(`{"alg":"ES256","kid":%q}`, kid)
	claims := fmt.Sprintf(`{"iss":%q,"sub":%q,"aud":%q,"jti":"%07d","exp":1}`, testClientID, testClientID, testIssuer, jti)
	return base64.RawURLEncoding.EncodeToString([]byte(header)) + "." + base64.RawURLEncoding.EncodeToString([]byte(claims)) + ".AA"
}

// liveHeap is the heap in use after a full collection.
func liveHeap() int64 {
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return int64(m.HeapAlloc)
}

// TestUnknownLongClientAssertionKeyIDsAreNotKept: pushed authorization
// requests, each with a client assertion naming a different unknown kid
// of 4,000 bytes (a 16 KiB one can carry about 12,000), more of them
// than the 1,024 kids a negative cache remembers, are refused
// invalid_client with the whole kid handed to a jwks_uri client's
// ClientJWKSSource, and leave little in memory: keys' own tests bound
// the cache's bytes exactly, and this checks that nothing on the way
// keeps the kids either. The source refetches the client's set for
// every request (a cache TTL of a nanosecond), so each kid is
// negative-cached as one arriving while a fetch is in flight is, and
// remembered for an hour: the cache fills without a burst or a clock.
func TestUnknownLongClientAssertionKeyIDsAreNotKept(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, false)
	fetcher, err := fapihttp.New(servedJWKS(ecJWKS(t, &h.key.PublicKey, "real-key")), fapihttp.Config{MaxResponseBytes: 1 << 16, RequestTimeout: 10 * time.Second, AllowLoopbackHTTP: true})
	if err != nil {
		t.Fatalf("fapihttp.New: %v", err)
	}
	jwksURI, err := fapi.ParseEndpointURL("http://127.0.0.1/jwks", fapi.AllowLoopbackHTTP())
	if err != nil {
		t.Fatalf("ParseEndpointURL: %v", err)
	}
	src, err := keys.NewClientJWKSSource(fetcher, func(_ context.Context, id fapi.ClientID) (fapi.URL, []byte, error) {
		if id != testClientID {
			return fapi.URL{}, nil, errors.New("unknown client")
		}
		return jwksURI, nil, nil
	}, keys.WithClientJWKSCacheTTL(time.Nanosecond), keys.WithClientJWKSMinRefreshInterval(time.Hour))
	if err != nil {
		t.Fatalf("NewClientJWKSSource: %v", err)
	}
	keyIDs := &longestKeyID{inner: src}
	deps := h.deps
	deps.ClientKeys = keyIDs
	srv, err := server.New(h.cfg, deps)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}

	const kidLength, requests = 4000, 1100
	push := func(i int) {
		kid := fmt.Sprintf("kid-%07d-", i)
		kid += strings.Repeat("A", kidLength-len(kid))
		assertion := unsignedAssertion(kid, i)
		if len(assertion) > jose.DefaultMaxCompactBytes {
			t.Fatalf("assertion is %d bytes, over the %d a JWS may have", len(assertion), jose.DefaultMaxCompactBytes)
		}
		_, err := srv.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
			HTTP: server.FormRequest{Parameters: plainFormParameters(t, assertion, nil)},
		})
		if code := serverErrorCode(t, err); code != server.ErrorInvalidClient {
			t.Fatalf("request %d: error code %q, want %q", i, code, server.ErrorInvalidClient)
		}
	}
	push(requests) // the client's entry in the source, before measuring
	before := liveHeap()
	for i := range requests {
		push(i)
	}
	retained := liveHeap() - before
	runtime.KeepAlive(srv)

	if keyIDs.longest != kidLength {
		t.Fatalf("the key source was asked about kids of up to %d bytes, want the whole %d", keyIDs.longest, kidLength)
	}
	// Kept whole, the cache's 1,024 kids alone would take 3.9 MiB.
	if retained > 1<<20 {
		t.Fatalf("%d requests with %d-byte kids left %d bytes more in use, want at most 1 MiB", requests, kidLength, retained)
	}
}
