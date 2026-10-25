package grantrevocation

import (
	"crypto/sha256"
	"strings"
	"testing"
)

// TestBackchannelGrantIDIsDomainSeparated: a CIBA grant's ID and a code
// grant's ID share CodeKey's namespace, so one derived from the same
// hash must never equal the other, and each is stable for its input.
func TestBackchannelGrantIDIsDomainSeparated(t *testing.T) {
	hash := sha256.Sum256([]byte("same input"))
	if BackchannelGrantID(hash) == CodeGrantID(hash) {
		t.Fatal("BackchannelGrantID equals CodeGrantID for the same hash")
	}
	again := sha256.Sum256([]byte("same input"))
	if BackchannelGrantID(hash) != BackchannelGrantID(again) {
		t.Fatal("BackchannelGrantID isn't deterministic")
	}
	if BackchannelGrantID(hash) == BackchannelGrantID(sha256.Sum256([]byte("other input"))) {
		t.Fatal("BackchannelGrantID ignores its input")
	}
}

// TestKeysAreNamespacedByIssuer: the key written for a grant ID names
// its issuer, so two issuers' grants of one ID get different keys, and
// the keys checked are that key and then the legacy un-namespaced one —
// which never equals a namespaced key.
func TestKeysAreNamespacedByIssuer(t *testing.T) {
	const a, b = "https://a.example.com", "https://b.example.com"
	for name, tc := range map[string]struct {
		key  func(issuer, id string) string
		keys func(issuer, id string) []string
		want string
	}{
		"grant":      {Key, Keys, "grant:g1@" + a},
		"code grant": {CodeKey, CodeKeys, "code-grant:g1@" + a},
	} {
		t.Run(name, func(t *testing.T) {
			if got := tc.key(a, "g1"); got != tc.want {
				t.Errorf("key = %q, want %q", got, tc.want)
			}
			if tc.key(a, "g1") == tc.key(b, "g1") {
				t.Error("two issuers' grants of one ID share a key")
			}
			checked := tc.keys(a, "g1")
			if len(checked) != 2 || checked[0] != tc.want || checked[1] != strings.TrimSuffix(tc.want, "@"+a) {
				t.Errorf("keys = %q, want [%q, the legacy key]", checked, tc.want)
			}
		})
	}
}
