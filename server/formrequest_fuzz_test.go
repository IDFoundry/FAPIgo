package server_test

import (
	"bytes"
	"net/http"
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
// strings.Split/strings.Cut/url.QueryUnescape loop, not the shared
// jose.ParseCompact-style parsing every other fuzz target in this repo
// goes through, and doesn't match any Parse/Decode/Unmarshal naming
// convention — found only by grepping for strings.Split calls directly.
// Only checks for panics/hangs.
func FuzzFormRequestFromHTTP(f *testing.F) {
	f.Add([]byte(`grant_type=authorization_code&code=fuzz-code&redirect_uri=https%3A%2F%2Fclient.example%2Fcb`))
	f.Add([]byte(`client_id=a&client_id=b`))
	f.Add([]byte(`a=%zz`))
	f.Add([]byte(`%zz=1`))
	f.Add([]byte(`=&=&=`))
	f.Add([]byte(``))
	f.Add([]byte(`&&&`))
	f.Add([]byte(strings.Repeat("a=1&", 300000)))

	f.Fuzz(func(t *testing.T, body []byte) {
		req, err := http.NewRequest(http.MethodPost, "https://as.example/token", bytes.NewReader(body))
		if err != nil {
			t.Fatalf("http.NewRequest: %v", err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		_, _ = server.FormRequestFromHTTP(req)
	})
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
