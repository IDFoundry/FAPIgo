package resource_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/resource"
)

// overlappingFixture is newFixture with both of testResourceURLs'
// origins covering every path, plus extra.
func overlappingFixture(t *testing.T, extra ...string) fixture {
	t.Helper()
	f := newFixture(t)
	cfg := validConfig(t)
	cfg.ResourceURLs = testResourceURLs(t)
	for _, raw := range extra {
		cfg.ResourceURLs = append(cfg.ResourceURLs, mustEndpointURL(t, raw))
	}
	f.verifier = newVerifierLike(t, f, cfg)
	return f
}

func mustEndpointURL(t *testing.T, raw string) fapi.URL {
	t.Helper()
	u, err := fapi.ParseEndpointURL(raw)
	if err != nil {
		t.Fatalf("ParseEndpointURL(%q): %v", raw, err)
	}
	return u
}

// verifyAtOrigin verifies a DPoP GET of path, with a proof naming htu,
// read by VerifyRequestFromHTTP under WithResourceOrigin(origin) — or
// unmarked for origin "".
func verifyAtOrigin(t *testing.T, f fixture, origin, path, htu string) error {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, path, nil)
	r.Header.Set("Authorization", "DPoP "+f.accessToken)
	r.Header.Set("DPoP", f.proofFor(t, "GET", htu))
	var err error
	var h http.Handler = http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		_, err = f.verifier.Verify(r.Context(), resource.VerifyRequestFromHTTP(r))
	})
	if origin != "" {
		h = resource.WithResourceOrigin(mustEndpointURL(t, origin), h)
	}
	h.ServeHTTP(httptest.NewRecorder(), r)
	return err
}

// wantResourceError checks err is a *resource.Error with code and
// status whose message names each of causes.
func wantResourceError(t *testing.T, name string, err error, code resource.ErrorCode, status int, causes ...string) {
	t.Helper()
	var rerr *resource.Error
	if !errors.As(err, &rerr) || rerr.Code() != code || rerr.HTTPStatus() != status {
		t.Errorf("%s: err = %v, want %d %s", name, err, status, code)
		return
	}
	for _, c := range causes {
		if !strings.Contains(err.Error(), c) {
			t.Errorf("%s: err = %v, want it to name %q", name, err, c)
		}
	}
}

// TestAmbiguousDPoPTargetNamesTheFix: a DPoP request whose path two
// configured origins cover, with nothing to say which received it, is
// the deployment's to fix: a 500 naming WithResourceOrigin and
// VerifyRequest.URL.
func TestAmbiguousDPoPTargetNamesTheFix(t *testing.T) {
	f := overlappingFixture(t)
	err := verifyAtOrigin(t, f, "", "/accounts/1", "https://rs.example/accounts/1")
	wantResourceError(t, "ambiguous", err, resource.ErrorServerError, 500, "resource.WithResourceOrigin", "VerifyRequest.URL")
}

// TestWithResourceOriginSelectsTheTarget: under WithResourceOrigin, a
// proof must name the marked origin, whatever other configured origin
// covers the path too.
func TestWithResourceOriginSelectsTheTarget(t *testing.T) {
	f := overlappingFixture(t)
	for _, c := range []struct {
		origin, htu string
		ok          bool
	}{
		{"https://rs.example", "https://rs.example/accounts/1", true},
		{"https://rs.example", "https://rs.example.com/accounts/1", false},
		{"https://rs.example.com", "https://rs.example.com/accounts/1", true},
		{"https://rs.example.com", "https://rs.example/accounts/1", false},
		{"https://rs.example.com/ignored/path", "https://rs.example.com/accounts/1", true},
	} {
		err := verifyAtOrigin(t, f, c.origin, "/accounts/1", c.htu)
		if c.ok {
			if err != nil {
				t.Errorf("at %s, proof for %s: %v", c.origin, c.htu, err)
			}
			continue
		}
		wantResourceError(t, "at "+c.origin+", proof for "+c.htu, err, resource.ErrorInvalidDPoPProof, 401)
	}
}

// TestWithResourceOriginOutsideResourceURLs: a mark naming an origin
// none of Config.ResourceURLs is at is the deployment's mistake, a 500
// naming WithResourceOrigin; a path not covered at a configured origin
// is still the client's, 400.
func TestWithResourceOriginOutsideResourceURLs(t *testing.T) {
	f := overlappingFixture(t, "https://api.example/v1")
	err := verifyAtOrigin(t, f, "https://other.example", "/accounts/1", "https://other.example/accounts/1")
	wantResourceError(t, "unconfigured origin", err, resource.ErrorServerError, 500, "resource.WithResourceOrigin", "https://other.example/")
	err = verifyAtOrigin(t, f, "https://api.example", "/v2/accounts", "https://api.example/v2/accounts")
	wantResourceError(t, "uncovered path", err, resource.ErrorInvalidRequest, 400)
	err = verifyAtOrigin(t, f, "", "/", "https://rs.example/")
	wantResourceError(t, "ambiguous root", err, resource.ErrorServerError, 500)

	prefixed := newFixture(t)
	cfg := validConfig(t)
	cfg.ResourceURLs = []fapi.URL{mustEndpointURL(t, "https://api.example/v1")}
	prefixed.verifier = newVerifierLike(t, prefixed, cfg)
	err = verifyAtOrigin(t, prefixed, "", "/v2/accounts", "https://api.example/v2/accounts")
	wantResourceError(t, "uncovered path, unmarked", err, resource.ErrorInvalidRequest, 400)
}

// TestExplicitURLOverridesWithResourceOrigin: VerifyRequest.URL, set
// after VerifyRequestFromHTTP, takes precedence over the mark.
func TestExplicitURLOverridesWithResourceOrigin(t *testing.T) {
	f := overlappingFixture(t)
	r := httptest.NewRequest(http.MethodGet, "/accounts/1", nil)
	r.Header.Set("Authorization", "DPoP "+f.accessToken)
	r.Header.Set("DPoP", f.proofFor(t, "GET", "https://rs.example.com/accounts/1"))
	var err error
	resource.WithResourceOrigin(mustEndpointURL(t, "https://rs.example"), http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		req := resource.VerifyRequestFromHTTP(r)
		req.URL, _ = url.Parse("https://rs.example.com/accounts/1")
		_, err = f.verifier.Verify(r.Context(), req)
	})).ServeHTTP(httptest.NewRecorder(), r)
	if err != nil {
		t.Fatalf("explicit URL under another origin's mark: %v", err)
	}
}
