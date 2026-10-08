package federation_test

import (
	"testing"

	"github.com/idfoundry/fapigo/federation"
)

// TestValidEntityID covers OpenID Federation 1.0 §1.2: an Entity
// Identifier is an https URL with a host, optionally a port and path,
// and "MUST NOT contain query parameter or fragment components".
func TestValidEntityID(t *testing.T) {
	for _, id := range []string{
		"https://rp.example.org",
		"https://rp.example.org/",
		"https://rp.example.org:8443/tenant/a",
		"https://[::1]",
		"https://127.0.0.1:8443",
		"https://xn--bcher-kva.example", // an internationalized name's A-label form
		"https://RP.Example.org",
	} {
		if err := federation.ValidEntityID(id); err != nil {
			t.Errorf("ValidEntityID(%q) = %v, want nil", id, err)
		}
	}
	for _, id := range []string{
		"http://rp.example.org",
		"https://",
		"https://rp.example.org?x=1",
		"https://rp.example.org/?",
		"https://rp.example.org#",
		"https://rp.example.org/p#f",
		"https://user@rp.example.org",
		"https://user:pass@rp.example.org",
		// Non-ASCII hosts: IDNA maps U+3002 and U+FF0E to ".", so these
		// name rp.banned.example while comparing as different strings.
		"https://rp.banned\u3002example",
		"https://rp.banned\uff0eexample",
		"https://b\u00fccher.example",
		"https://rp.banned%2Eexample", // a percent-escape, which url.Parse refuses
		"https://[fe80::1%25en0]",     // an IPv6 zone
		"https://rp_underscore.example",
	} {
		if err := federation.ValidEntityID(id); err == nil {
			t.Errorf("ValidEntityID(%q) = nil, want error", id)
		}
	}
}
