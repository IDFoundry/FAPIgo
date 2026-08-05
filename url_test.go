package fapi

import "testing"

func TestParseEndpointURLAccepts(t *testing.T) {
	u, err := ParseEndpointURL("https://as.example/par")
	if err != nil {
		t.Fatalf("ParseEndpointURL: %v", err)
	}
	if u.String() != "https://as.example/par" {
		t.Fatalf("String() = %q, want %q", u.String(), "https://as.example/par")
	}
}

func TestParseEndpointURLNormalizesCase(t *testing.T) {
	u, err := ParseEndpointURL("HTTPS://AS.Example/par")
	if err != nil {
		t.Fatalf("ParseEndpointURL: %v", err)
	}
	if u.String() != "https://as.example/par" {
		t.Fatalf("String() = %q, want %q", u.String(), "https://as.example/par")
	}
}

func TestParseEndpointURLRejects(t *testing.T) {
	cases := []string{
		"",
		"not-a-url",
		"/relative/path",
		"http://as.example/par",            // http, not loopback
		"https://user:pass@as.example/par", // embedded credentials
		"https://as.example/par#fragment",  // fragment
		"ftp://as.example/par",             // wrong scheme
	}
	for _, c := range cases {
		if _, err := ParseEndpointURL(c); err == nil {
			t.Fatalf("ParseEndpointURL(%q) = nil error, want error", c)
		}
	}
}

func TestParseEndpointURLAllowsLoopbackHTTPWhenEnabled(t *testing.T) {
	cases := []string{
		"http://localhost:8080/par",
		"http://127.0.0.1:8080/par",
		"http://[::1]:8080/par",
	}
	for _, c := range cases {
		if _, err := ParseEndpointURL(c, AllowLoopbackHTTP()); err != nil {
			t.Fatalf("ParseEndpointURL(%q, AllowLoopbackHTTP()) = %v, want nil", c, err)
		}
	}
}

func TestParseEndpointURLRejectsNonLoopbackHTTPEvenWhenEnabled(t *testing.T) {
	if _, err := ParseEndpointURL("http://as.example/par", AllowLoopbackHTTP()); err == nil {
		t.Fatalf("ParseEndpointURL(non-loopback http, AllowLoopbackHTTP()) = nil error, want error")
	}
}

func TestURLIsZero(t *testing.T) {
	var u URL
	if !u.IsZero() {
		t.Fatalf("zero value URL.IsZero() = false, want true")
	}
	parsed, err := ParseEndpointURL("https://as.example/par")
	if err != nil {
		t.Fatalf("ParseEndpointURL: %v", err)
	}
	if parsed.IsZero() {
		t.Fatalf("parsed URL.IsZero() = true, want false")
	}
}
