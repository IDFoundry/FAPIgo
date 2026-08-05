package par

import (
	"bytes"
	"strings"
	"testing"
)

func TestGenerateRequestURIHasPrefix(t *testing.T) {
	uri, err := GenerateRequestURI(nil)
	if err != nil {
		t.Fatalf("GenerateRequestURI: %v", err)
	}
	if !strings.HasPrefix(uri, RequestURIPrefix) {
		t.Fatalf("GenerateRequestURI() = %q, want prefix %q", uri, RequestURIPrefix)
	}
}

func TestGenerateRequestURIIsRandom(t *testing.T) {
	a, err := GenerateRequestURI(nil)
	if err != nil {
		t.Fatalf("GenerateRequestURI: %v", err)
	}
	b, err := GenerateRequestURI(nil)
	if err != nil {
		t.Fatalf("GenerateRequestURI: %v", err)
	}
	if a == b {
		t.Fatalf("two calls to GenerateRequestURI produced the same value")
	}
}

func TestGenerateRequestURIUsesSuppliedRandom(t *testing.T) {
	src := bytes.NewReader(make([]byte, referenceSize))
	uri, err := GenerateRequestURI(src)
	if err != nil {
		t.Fatalf("GenerateRequestURI: %v", err)
	}
	ref, ok := SplitRequestURI(uri)
	if !ok {
		t.Fatalf("SplitRequestURI(%q) ok = false, want true", uri)
	}
	if ref == "" {
		t.Fatalf("reference component is empty")
	}
}

func TestSplitRequestURIRoundTrip(t *testing.T) {
	uri, err := GenerateRequestURI(nil)
	if err != nil {
		t.Fatalf("GenerateRequestURI: %v", err)
	}
	ref, ok := SplitRequestURI(uri)
	if !ok {
		t.Fatalf("SplitRequestURI(%q) ok = false, want true", uri)
	}
	if RequestURIPrefix+ref != uri {
		t.Fatalf("prefix + reference = %q, want %q", RequestURIPrefix+ref, uri)
	}
}

func TestSplitRequestURIRejectsWrongPrefix(t *testing.T) {
	cases := []string{
		"",
		"not-a-request-uri",
		"urn:ietf:params:oauth:request_uri:",
		"https://as.example/request/abc123",
		"URN:IETF:PARAMS:OAUTH:REQUEST_URI:abc123",
	}
	for _, c := range cases {
		if _, ok := SplitRequestURI(c); ok {
			t.Fatalf("SplitRequestURI(%q) ok = true, want false", c)
		}
	}
}
