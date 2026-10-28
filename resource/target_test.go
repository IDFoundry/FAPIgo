package resource_test

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/dpop"
	"github.com/idfoundry/fapigo/resource"
)

// proofFor signs a DPoP proof with f's key for method at htu, which
// must parse.
func (f fixture) proofFor(t *testing.T, method, htu string) string {
	t.Helper()
	u, err := url.Parse(htu)
	if err != nil {
		t.Fatalf("url.Parse(%q): %v", htu, err)
	}
	proof, err := dpop.CreateProof(dpop.ProofRequest{
		Signer: f.dpopKey, Algorithm: fapi.ES256, Method: method, URL: u,
		AccessToken: f.accessToken, Now: f.now, Random: rand.Reader,
	})
	if err != nil {
		t.Fatalf("CreateProof(%s): %v", htu, err)
	}
	return proof
}

// serveThroughMux sends a GET for rawURL, with f's access token and
// proof, to a ServeMux routing /accounts/{id} to a handler that verifies
// it with VerifyRequestFromHTTP, and returns the response's status. host,
// when set, replaces the request's Host header.
func serveThroughMux(t *testing.T, f fixture, rawURL, host, proof string) int {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /accounts/{id}", func(w http.ResponseWriter, r *http.Request) {
		authz, err := f.verifier.Verify(r.Context(), resource.VerifyRequestFromHTTP(r))
		if err != nil {
			resource.WriteError(w, err)
			return
		}
		_, _ = io.WriteString(w, "account "+r.PathValue("id")+" for "+authz.InternalSubject)
	})
	r := httptest.NewRequest(http.MethodGet, rawURL, nil)
	if host != "" {
		r.Host = host
	}
	r.Header.Set("Authorization", "DPoP "+f.accessToken)
	r.Header.Set("DPoP", proof)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, r)
	return rec.Code
}

// TestVerifyRequestFromHTTPUsesTheEscapedPath: the target is the
// request's escaped path, so a proof for /accounts/a/b doesn't verify at
// /accounts/a%2Fb (one segment, "a/b"), nor one naming "a?b" or "a#b"
// as a query or fragment at the route whose segment holds them encoded;
// a proof naming the encoded segment does.
func TestVerifyRequestFromHTTPUsesTheEscapedPath(t *testing.T) {
	for _, c := range []struct {
		name, path, otherHTU string
	}{
		{"slash", "/accounts/a%2Fb", "https://rs.example.com/accounts/a/b"},
		{"question mark", "/accounts/a%3Fb", "https://rs.example.com/accounts/a?b"},
		{"hash", "/accounts/a%23b", "https://rs.example.com/accounts/a#b"},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t)
			if got := serveThroughMux(t, f, "https://rs.example.com"+c.path, "", f.proofFor(t, "GET", c.otherHTU)); got != http.StatusUnauthorized {
				t.Errorf("proof for %s at %s: status %d, want 401", c.otherHTU, c.path, got)
			}
			if got := serveThroughMux(t, f, "https://rs.example.com"+c.path, "", f.proofFor(t, "GET", "https://rs.example.com"+c.path)); got != http.StatusOK {
				t.Errorf("proof for %s at %s: status %d, want 200", c.path, c.path, got)
			}
		})
	}
}

// TestVerifyRequestFromHTTPIgnoresHost: the request's Host header has no
// effect on the target. A proof another resource server received
// (naming its own origin) is refused here whatever Host the replay
// carries, and a proof naming this resource server verifies whatever
// Host it carries.
func TestVerifyRequestFromHTTPIgnoresHost(t *testing.T) {
	f := newFixture(t)
	stolen := f.proofFor(t, "GET", "https://rs-b.example/accounts/1")
	if got := serveThroughMux(t, f, "https://rs-b.example/accounts/1", "rs-b.example", stolen); got != http.StatusUnauthorized {
		t.Errorf("proof for rs-b.example replayed with Host rs-b.example: status %d, want 401", got)
	}
	own := f.proofFor(t, "GET", "https://rs.example.com/accounts/1")
	if got := serveThroughMux(t, f, "https://rs.example.com/accounts/1", "rs-b.example", own); got != http.StatusOK {
		t.Errorf("proof for rs.example.com with Host rs-b.example: status %d, want 200", got)
	}
}

// TestVerifyRequestFromHTTPAcceptsEachConfiguredOrigin: a proof naming
// any of Config.ResourceURLs' origins verifies.
func TestVerifyRequestFromHTTPAcceptsEachConfiguredOrigin(t *testing.T) {
	f := newFixture(t)
	if got := serveThroughMux(t, f, "/accounts/1", "", f.proofFor(t, "GET", "https://rs.example/accounts/1")); got != http.StatusOK {
		t.Errorf("proof naming the second origin: status %d, want 200", got)
	}
}

// TestVerifyRefusesLowerCaseMethod: htm is compared with the request's
// method exactly (RFC 9110 §9.1).
func TestVerifyRefusesLowerCaseMethod(t *testing.T) {
	f := newFixture(t)
	r := httptest.NewRequest("get", f.target.String(), nil)
	r.Header.Set("Authorization", "DPoP "+f.accessToken)
	r.Header.Set("DPoP", f.dpopProof) // htm "GET"
	_, err := f.verifier.Verify(context.Background(), resource.VerifyRequestFromHTTP(r))
	assertCode(t, "proof for GET on a get request", err, resource.ErrorInvalidDPoPProof)
}

func assertCode(t *testing.T, what string, err error, want resource.ErrorCode) {
	t.Helper()
	var rerr *resource.Error
	if !errors.As(err, &rerr) || rerr.Code() != want {
		t.Errorf("%s: err = %v, want %s", what, err, want)
	}
}

// TestVerifyRefusesATargetOutsideResourceURLs: an explicit
// VerifyRequest.URL must be an absolute http(s) URL under one of
// Config.ResourceURLs — so one built from the Host header can't name
// another resource server — and a relative or non-http(s) one is the
// caller's error.
func TestVerifyRefusesATargetOutsideResourceURLs(t *testing.T) {
	f := newFixture(t)
	for _, c := range []struct {
		target string
		want   resource.ErrorCode
	}{
		{"https://rs-b.example/accounts", resource.ErrorInvalidRequest},
		{"https://rs.example.com:8443/accounts", resource.ErrorInvalidRequest},
		{"http://rs.example.com/accounts", resource.ErrorInvalidRequest},
		{"/accounts", resource.ErrorServerError},
		{"//rs.example.com/accounts", resource.ErrorServerError},
		{"ftp://rs.example.com/accounts", resource.ErrorServerError},
	} {
		u, err := url.Parse(c.target)
		if err != nil {
			t.Fatal(err)
		}
		_, err = f.verifier.Verify(context.Background(), resource.VerifyRequest{
			Method: "GET", URL: u, Authorization: "DPoP " + f.accessToken,
			DPoPProofs: []string{f.proofFor(t, "GET", "https://rs-b.example/accounts")},
		})
		assertCode(t, "target "+c.target, err, c.want)
	}
}

// TestVerifyHoldsATargetToItsPathPrefix: with a ResourceURLs entry
// carrying a path prefix, only paths at or under it are this resource
// server's — through VerifyRequestFromHTTP and as an explicit URL.
func TestVerifyHoldsATargetToItsPathPrefix(t *testing.T) {
	f := newFixture(t)
	cfg := validConfig(t)
	prefix, err := fapi.ParseEndpointURL("https://rs.example.com/accounts")
	if err != nil {
		t.Fatal(err)
	}
	cfg.ResourceURLs = []fapi.URL{prefix}
	f.verifier = newVerifierLike(t, f, cfg)

	for path, ok := range map[string]bool{
		"/accounts":          true,
		"/accounts/1":        true,
		"/accountsx":         false,
		"/admin":             false,
		"/accounts/../admin": false,
		"/accounts%2F1":      false,
		"*":                  false,
	} {
		htu := "https://rs.example.com" + path
		r := httptest.NewRequest(http.MethodGet, "https://rs.example.com/", nil)
		r.URL = &url.URL{Path: path}
		if p, err := url.PathUnescape(path); err == nil && p != path {
			r.URL = &url.URL{Path: p, RawPath: path}
		}
		r.Header.Set("Authorization", "DPoP "+f.accessToken)
		r.Header.Set("DPoP", rawProof(t, f, htu))
		_, err := f.verifier.Verify(context.Background(), resource.VerifyRequestFromHTTP(r))
		if ok && err != nil {
			t.Errorf("path %q: %v, want accepted", path, err)
		}
		if !ok {
			assertCode(t, "path "+path, err, resource.ErrorInvalidRequest)
		}
	}
}

// rawProof is f.proofFor for an htu CreateProof would refuse to write
// (dot segments, "*"), signed as is: whether the target is under a
// prefix is decided before the proof's htu is compared.
func rawProof(t *testing.T, f fixture, htu string) string {
	t.Helper()
	if strings.Contains(htu, "/..") || strings.HasSuffix(htu, "*") {
		return f.proofFor(t, "GET", "https://rs.example.com/accounts")
	}
	return f.proofFor(t, "GET", htu)
}

// newVerifierLike builds a verifier for f's tokens with cfg.
func newVerifierLike(t *testing.T, f fixture, cfg resource.Config) *resource.Verifier {
	t.Helper()
	v, err := resource.NewVerifier(cfg, resource.Dependencies{
		AccessTokens: f.accessTokens, Replay: &fakeReplayStore{},
		Revocation: &fakeRevocationChecker{}, Clock: fixedClock{now: f.now},
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	return v
}

// TestNewVerifierChecksResourceURLs: ResourceURLs is required; each must
// be set, carry no query and have a normal path; and a loopback http URL
// is refused under AssuranceProduction.
func TestNewVerifierChecksResourceURLs(t *testing.T) {
	parse := func(raw string, opts ...fapi.URLOption) fapi.URL {
		u, err := fapi.ParseEndpointURL(raw, opts...)
		if err != nil {
			t.Fatalf("ParseEndpointURL(%q): %v", raw, err)
		}
		return u
	}
	for name, c := range map[string]struct {
		urls       []fapi.URL
		production bool
		want       string
	}{
		"none":                   {nil, false, "resource_urls is required"},
		"unset entry":            {[]fapi.URL{{}}, false, "resource_urls[0] is unset"},
		"query":                  {[]fapi.URL{parse("https://rs.example/api?x=1")}, false, "must not have a query"},
		"dot segments":           {[]fapi.URL{parse("https://rs.example/a/../api")}, false, "dot segments"},
		"loopback in production": {[]fapi.URL{parse("http://127.0.0.1:8080", fapi.AllowLoopbackHTTP())}, true, "AllowLoopbackHTTP"},
	} {
		cfg, deps := validConfig(t), validDependencies(t)
		if c.production {
			cfg, deps = productionSetup(t)
		}
		cfg.ResourceURLs = c.urls
		if _, err := resource.NewVerifier(cfg, deps); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: NewVerifier = %v, want an error containing %q", name, err, c.want)
		}
	}
	cfg := validConfig(t)
	cfg.ResourceURLs = []fapi.URL{parse("http://127.0.0.1:8080", fapi.AllowLoopbackHTTP())}
	if _, err := resource.NewVerifier(cfg, validDependencies(t)); err != nil {
		t.Errorf("loopback http in development: %v", err)
	}
}
