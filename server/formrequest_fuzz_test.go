package server_test

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/idfoundry/fapigo/server"
)

// FuzzFormRequestFromHTTP exercises FormRequestFromHTTP against an
// arbitrary application/x-www-form-urlencoded body — this package's own
// entry point for every form-encoded endpoint it serves (token, PAR,
// ...), and a deliberately different implementation from
// internal/par.DecodeForm's (already fuzzed): FormRequestFromHTTP's own
// doc comment explains it exists specifically to preserve parameter
// order and every duplicate occurrence, rather than collapsing them the
// way net/url.Values (and internal/par.DecodeForm, built on it) would,
// so this package's own validation — not an HTTP adapter — is what
// detects a duplicated or malformed parameter. That's a hand-rolled
// strings.Cut/url.QueryUnescape loop (decodeFormParameters), not the
// shared jose.ParseCompact-style parsing every other fuzz target in
// this repo goes through. Besides panics and hangs, it checks the
// loop's count: a body within the size limit is taken whole, one
// parameter for each non-empty pair, when it has at most
// server.MaxFormParameters of them, and refused for their number only
// when it has more. The seeds stay within the size limit, so each
// reaches the loop. They are small too: a mutant of a 1 MiB seed that
// reaches new coverage is about 1 MiB as well, and minimizing it a
// byte at a time would take most of a run, so the 1 MiB shapes are
// left to TestFormRequestFromHTTPBoundsParameterCount and
// TestFormRequestFromHTTPAllocationIsBounded.
func FuzzFormRequestFromHTTP(f *testing.F) {
	f.Add([]byte(`grant_type=authorization_code&code=fuzz-code&redirect_uri=https%3A%2F%2Fclient.example%2Fcb`))
	f.Add([]byte(`client_id=a&client_id=b`))
	f.Add([]byte(`a=%zz`))
	f.Add([]byte(`%zz=1`))
	f.Add([]byte(`=&=&=`))
	f.Add([]byte(``))
	f.Add([]byte(`&&&`))
	f.Add([]byte(strings.Repeat("a=1&", server.MaxFormParameters)))
	f.Add([]byte("&" + strings.Repeat("a=1&&", server.MaxFormParameters+1)))
	f.Add([]byte(strings.Repeat("a&", 1<<11))) // 2,048 one-byte parameters, past the bound
	f.Add([]byte(strings.Repeat("&", 1<<12)))  // separators only

	f.Fuzz(func(t *testing.T, body []byte) {
		req, err := http.NewRequest(http.MethodPost, "https://as.example/token", bytes.NewReader(body))
		if err != nil {
			t.Fatalf("http.NewRequest: %v", err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		form, err := server.FormRequestFromHTTP(req)
		if len(body) > 1<<20 {
			return // refused for its size before anything is counted
		}
		pairs := nonEmptyPairs(body)
		var serr *server.Error
		if err == nil && (len(form.Parameters) != pairs || pairs > server.MaxFormParameters) {
			t.Fatalf("took %d parameters from %d non-empty pairs, want each of at most %d", len(form.Parameters), pairs, server.MaxFormParameters)
		}
		if errors.As(err, &serr) && serr.PublicDescription() == "the request body has too many parameters" && pairs <= server.MaxFormParameters {
			t.Fatalf("refused %d non-empty pairs as too many, at most %d", pairs, server.MaxFormParameters)
		}
	})
}

// nonEmptyPairs counts body's non-empty "&"-separated pairs: the
// positions where a run of anything but "&" begins.
func nonEmptyPairs(body []byte) int {
	n := 0
	for i, c := range body {
		if c != '&' && (i == 0 || body[i-1] == '&') {
			n++
		}
	}
	return n
}

// FuzzFormRequestFromHTTPQueryUnescape narrows FuzzFormRequestFromHTTP
// to bodies that are already well-formed name=value&... shapes with
// only the percent-encoding itself fuzzed, since a fully random byte
// string is unlikely to exercise url.QueryUnescape's own error paths
// (a malformed "%" escape) as often as a targeted corpus does. Same
// entry point, same "panics/hangs only" oracle.
func FuzzFormRequestFromHTTPQueryUnescape(f *testing.F) {
	f.Add("client_id", "%")
	f.Add("client_id", "%2")
	f.Add("client_id", "%zz")
	f.Add("client_id", "%2F%2F%2F")
	f.Add("client_id", url.QueryEscape("https://client.example/callback?a=b#frag"))

	f.Fuzz(func(t *testing.T, name, value string) {
		body := []byte(name + "=" + value)
		req, err := http.NewRequest(http.MethodPost, "https://as.example/token", bytes.NewReader(body))
		if err != nil {
			t.Fatalf("http.NewRequest: %v", err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		_, _ = server.FormRequestFromHTTP(req)
	})
}

// TestFormRequestFromHTTPContentType: the media type is matched
// case-insensitively, with any parameters (RFC 9110 §8.3.1), and as a
// whole: a longer type that merely starts with it is another type.
func TestFormRequestFromHTTPContentType(t *testing.T) {
	for contentType, want := range map[string]bool{
		"application/x-www-form-urlencoded":                true,
		"Application/X-WWW-Form-URLEncoded":                true,
		"application/x-www-form-urlencoded; charset=UTF-8": true,
		"application/x-www-form-urlencodedx":               false,
		"application/x-www-form-urlencoded-not; charset=x": false,
		"application/json":                                 false,
		"":                                                 false,
	} {
		req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader("a=b"))
		req.Header.Set("Content-Type", contentType)
		_, err := server.FormRequestFromHTTP(req)
		if (err == nil) != want {
			t.Errorf("Content-Type %q: err = %v, want accepted %v", contentType, err, want)
		}
	}
}
