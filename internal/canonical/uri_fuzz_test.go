package canonical

import (
	"net/url"
	"testing"
)

// FuzzURI checks two properties of URI beyond "does not panic": its
// output must always itself be a valid, re-parseable URL, and
// canonicalizing an already-canonical URL must be a no-op (idempotent).
// Both are load-bearing for this package's whole purpose — doc.go's own
// "client, server and resource agree byte-for-byte on what they are
// signing, verifying or comparing" only holds if canonicalization has a
// single fixed point per input, not one that keeps changing under
// repeated application.
func FuzzURI(f *testing.F) {
	f.Add("https://Example.COM:443/path?query=1#frag")
	f.Add("http://Example.COM:80/")
	f.Add("https://user:pass@example.com/a/b")
	f.Add("https://example.com:8443/x")
	f.Add("https://[::1]:8443/x")
	f.Add("https://[::1]/x")
	f.Add("not a url")
	f.Add("")
	f.Add("https://example.com:99999/")
	f.Add("https://example.com:0/")
	f.Add("https://example.com:/")
	f.Add("HTTPS://EXAMPLE.COM/PATH")
	f.Add("ftp://example.com:21/")
	f.Add("//://%2Fx")

	f.Fuzz(func(t *testing.T, raw string) {
		u, err := url.Parse(raw)
		if err != nil {
			return
		}
		out1 := URI(u)

		u2, err := url.Parse(out1)
		if err != nil {
			t.Fatalf("URI produced an unparseable result %q for input %q: %v", out1, raw, err)
		}
		out2 := URI(u2)
		if out1 != out2 {
			t.Fatalf("URI is not idempotent for input %q: URI(u) = %q, URI(URI(u)) = %q", raw, out1, out2)
		}
	})
}
