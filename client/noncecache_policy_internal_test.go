package client

import (
	"net/http"
	"strings"
	"testing"

	fapi "github.com/idfoundry/fapigo"
)

func TestValidDPoPNonce(t *testing.T) {
	for nonce, want := range map[string]bool{
		"abc-DEF_123.~":                         true,
		"!#[]~":                                 true,
		strings.Repeat("n", maxDPoPNonceLength): true,
		"":                                      false,
		strings.Repeat("n", maxDPoPNonceLength+1): false,
		"has space":     false,
		`has"quote`:     false,
		`has\backslash`: false,
		"has\x7fdel":    false,
		"caf\xc3\xa9":   false,
	} {
		if got := validDPoPNonce(nonce); got != want {
			t.Errorf("validDPoPNonce(%.20q…) = %v, want %v", nonce, got, want)
		}
	}
}

// TestRecordASDPoPNonce: an authorization server's nonce is cached from a
// success or a use_dpop_nonce challenge only, is forgotten after any
// other 4xx, and a malformed one is never cached nor retried with.
func TestRecordASDPoPNonce(t *testing.T) {
	iss, err := fapi.ParseIssuerURL("https://as.example.com")
	if err != nil {
		t.Fatal(err)
	}
	c := &Client{cfg: Config{Issuer: iss}, deps: Dependencies{DPoPNonceCache: NewInMemoryDPoPNonceCache()}}
	withNonce := func(nonce string) http.Header {
		h := http.Header{}
		h.Set(dpopNonceHeader, nonce)
		return h
	}
	challenge := []byte(`{"error":"use_dpop_nonce"}`)
	invalidGrant := []byte(`{"error":"invalid_grant"}`)
	huge := strings.Repeat("n", maxDPoPNonceLength+1)
	for _, step := range []struct {
		name   string
		status int
		header http.Header
		body   []byte
		want   string
	}{
		{"success", http.StatusOK, withNonce("n1"), nil, "n1"},
		{"challenge", http.StatusBadRequest, withNonce("n2"), challenge, "n2"},
		{"5xx leaves it", http.StatusBadGateway, withNonce("n3"), nil, "n2"},
		{"oversized on success", http.StatusOK, withNonce(huge), nil, "n2"},
		{"malformed on challenge", http.StatusBadRequest, withNonce("a b"), challenge, ""},
		{"success again", http.StatusOK, withNonce("n4"), nil, "n4"},
		{"other 4xx forgets it", http.StatusBadRequest, withNonce("n5"), invalidGrant, ""},
		{"success after", http.StatusCreated, withNonce("n6"), nil, "n6"},
		{"431 forgets it", http.StatusRequestHeaderFieldsTooLarge, http.Header{}, nil, ""},
	} {
		c.recordASDPoPNonce(t.Context(), step.status, step.header, step.body)
		if got := c.cachedDPoPNonce(t.Context(), c.asNonceScope()); got != step.want {
			t.Fatalf("%s: cached nonce = %q, want %q", step.name, got, step.want)
		}
	}
	if _, retry := challengeRetry(withNonce(huge), challenge, "old"); retry {
		t.Error("challengeRetry retried with an oversized nonce")
	}
	if next, retry := challengeRetry(withNonce("fresh"), challenge, "old"); !retry || next != "fresh" {
		t.Errorf("challengeRetry = %q, %v; want fresh, true", next, retry)
	}
}

// TestCachedDPoPNonceIgnoresAMalformedValue: a cache other clients write
// to can hold anything; a value that isn't a valid nonce isn't
// presented.
func TestCachedDPoPNonceIgnoresAMalformedValue(t *testing.T) {
	cache := NewInMemoryDPoPNonceCache()
	c := &Client{deps: Dependencies{DPoPNonceCache: cache}}
	cache.Set(t.Context(), "scope", strings.Repeat("n", maxDPoPNonceLength+1))
	if got := c.cachedDPoPNonce(t.Context(), "scope"); got != "" {
		t.Errorf("cachedDPoPNonce = %.20q…, want none", got)
	}
}
