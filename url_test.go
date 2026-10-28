package fapi

import (
	"encoding/json"
	"net/url"
	"testing"
)

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

// TestParseIssuerURLAccepts through TestParseIssuerURLAllowsLoopbackHTTPWhenEnabled
// mirror ParseEndpointURL's own tests above. Despite sharing the same
// underlying validator (parseSecureURL), ParseIssuerURL itself had no
// direct test of its own — every one of the dozens of call sites
// across this repo that use it (fapitest, cmd/conformance-as, every
// server/client/resource test's own testIssuer) never exercises this
// package's own test suite, since per-package coverage only credits a
// package for what its own tests call directly.
func TestParseIssuerURLAccepts(t *testing.T) {
	u, err := ParseIssuerURL("https://as.example")
	if err != nil {
		t.Fatalf("ParseIssuerURL: %v", err)
	}
	if u.String() != "https://as.example" {
		t.Fatalf("String() = %q, want %q", u.String(), "https://as.example")
	}
}

func TestParseIssuerURLNormalizesCase(t *testing.T) {
	u, err := ParseIssuerURL("HTTPS://AS.Example")
	if err != nil {
		t.Fatalf("ParseIssuerURL: %v", err)
	}
	if u.String() != "https://as.example" {
		t.Fatalf("String() = %q, want %q", u.String(), "https://as.example")
	}
}

func TestParseIssuerURLRejects(t *testing.T) {
	cases := []string{
		"",
		"not-a-url",
		"/relative/path",
		"http://as.example",            // http, not loopback
		"https://user:pass@as.example", // embedded credentials
		"https://as.example#fragment",  // fragment
		"ftp://as.example",             // wrong scheme
	}
	for _, c := range cases {
		if _, err := ParseIssuerURL(c); err == nil {
			t.Fatalf("ParseIssuerURL(%q) = nil error, want error", c)
		}
	}
}

func TestParseIssuerURLAllowsLoopbackHTTPWhenEnabled(t *testing.T) {
	cases := []string{
		"http://localhost:8080",
		"http://127.0.0.1:8080",
		"http://[::1]:8080",
	}
	for _, c := range cases {
		if _, err := ParseIssuerURL(c, AllowLoopbackHTTP()); err != nil {
			t.Fatalf("ParseIssuerURL(%q, AllowLoopbackHTTP()) = %v, want nil", c, err)
		}
	}
}

// TestParseIssuerURLAndParseEndpointURLErrorsAreDistinguishable is the
// one behavioral difference actually unique to ParseIssuerURL as
// opposed to its sibling: each wraps a parseSecureURL failure with its
// own distinct message prefix, so a caller's error log can tell which
// of the two rejected the value without needing surrounding context.
func TestParseIssuerURLAndParseEndpointURLErrorsAreDistinguishable(t *testing.T) {
	_, issuerErr := ParseIssuerURL("not-a-url")
	_, endpointErr := ParseEndpointURL("not-a-url")
	if issuerErr == nil || endpointErr == nil {
		t.Fatalf("ParseIssuerURL/ParseEndpointURL(not-a-url) = nil error, want error from both")
	}
	if issuerErr.Error() == endpointErr.Error() {
		t.Fatalf("ParseIssuerURL and ParseEndpointURL produced identical error text %q, want distinguishable messages", issuerErr.Error())
	}
}

func TestParseEndpointURLAllowsLoopbackHTTPWhenEnabled(t *testing.T) {
	cases := []string{
		"http://localhost:8080/par",
		"http://127.0.0.1:8080/par",
		"http://[::1]:8080/par",
		"http://localhost/par",
		"http://127.0.0.1/par",
		"http://[::1]/par", // bracketed IPv6 with no port — found by FuzzParseEndpointURL
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

func TestURLWithQueryPreservesLoopbackHTTP(t *testing.T) {
	// A caller building on an endpoint URL parsed under AllowLoopbackHTTP
	// (e.g. a client's own authorization-endpoint URL, appended with
	// request_uri/client_id) must not have to re-validate the result
	// through ParseEndpointURL — which would reject it, since that call
	// site generally has no way to know AllowLoopbackHTTP applied to the
	// original. See client.BeginAuthorization.
	base, err := ParseEndpointURL("http://127.0.0.1:8080/authorize", AllowLoopbackHTTP())
	if err != nil {
		t.Fatalf("ParseEndpointURL: %v", err)
	}
	q := url.Values{}
	q.Set("client_id", "abc")
	got := base.WithQuery(q)
	want := "http://127.0.0.1:8080/authorize?client_id=abc"
	if got.String() != want {
		t.Fatalf("WithQuery: String() = %q, want %q", got.String(), want)
	}
}

func TestURLMarshalJSON(t *testing.T) {
	parsed, err := ParseEndpointURL("https://as.example/par")
	if err != nil {
		t.Fatalf("ParseEndpointURL: %v", err)
	}
	b, err := json.Marshal(parsed)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if got, want := string(b), `"https://as.example/par"`; got != want {
		t.Fatalf("Marshal(parsed) = %s, want %s", got, want)
	}
}

func TestURLMarshalJSONZeroValue(t *testing.T) {
	var u URL
	b, err := json.Marshal(u)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if got, want := string(b), `""`; got != want {
		t.Fatalf("Marshal(zero value) = %s, want %s", got, want)
	}
}

func TestURLWithQueryReplacesExistingQuery(t *testing.T) {
	base, err := ParseEndpointURL("https://as.example/authorize?old=1")
	if err != nil {
		t.Fatalf("ParseEndpointURL: %v", err)
	}
	q := url.Values{}
	q.Set("new", "2")
	got := base.WithQuery(q)
	want := "https://as.example/authorize?new=2"
	if got.String() != want {
		t.Fatalf("WithQuery: String() = %q, want %q", got.String(), want)
	}
}

// Non-ASCII letters whose Unicode case mapping lands on, or comes from,
// an ASCII one. net/http dials a host containing any of them through
// IDNA, as a DNS name other than its ASCII look-alike ("İbank.example"
// is "xn--ibank-7fd.example").
const (
	dottedCapitalI = "İ" // "İ": strings.ToLower gives "i"
	kelvinSign     = "K" // "K": strings.ToLower gives "k"
	longS          = "ſ" // "ſ": strings.EqualFold matches "s"
	fullwidthB     = "Ｂ" // "Ｂ"
)

var nonASCIIHostURLs = []string{
	"https://" + dottedCapitalI + "bank.example",
	"https://%C4%B0bank.example/token",
	"https://" + kelvinSign + "ey.example/token",
	"https://" + fullwidthB + "ank.example/token",
	"https://bank.example." + dottedCapitalI + "/token",
}

// parsers is each of ParseIssuerURL, ParseEndpointURL and
// ParseRedirectURL (the last with every option, so only the host can
// make it refuse).
var parsers = map[string]func(string) (URL, error){
	"ParseIssuerURL":   func(raw string) (URL, error) { return ParseIssuerURL(raw) },
	"ParseEndpointURL": func(raw string) (URL, error) { return ParseEndpointURL(raw) },
	"ParseRedirectURL": func(raw string) (URL, error) {
		return ParseRedirectURL(raw, AllowLoopbackHTTP(), AllowPrivateUseScheme())
	},
}

// TestParseURLRefusesNonASCIIHost: a host that isn't ASCII is refused
// rather than lowercased, which would fold "İbank.example" onto
// "ibank.example" while requests to it go to "xn--ibank-7fd.example".
func TestParseURLRefusesNonASCIIHost(t *testing.T) {
	for name, parse := range parsers {
		for _, raw := range nonASCIIHostURLs {
			if u, err := parse(raw); err == nil {
				t.Errorf("%s(%q) = %q, want an error", name, raw, u.String())
			}
		}
	}
}

// TestParseURLLowercasesASCIIHost: a mixed-case ASCII host or scheme is
// lowercased, and an internationalized name in its A-label form is
// accepted.
func TestParseURLLowercasesASCIIHost(t *testing.T) {
	for name, parse := range parsers {
		for raw, want := range map[string]string{
			"HtTpS://IBank.EXAMPLE/cb":              "https://ibank.example/cb",
			"https://XN--IBANK-7FD.example/cb":      "https://xn--ibank-7fd.example/cb",
			"https://Key.Example:8443/cb?State=Abc": "https://key.example:8443/cb?State=Abc",
		} {
			u, err := parse(raw)
			if err != nil {
				t.Errorf("%s(%q): %v", name, raw, err)
				continue
			}
			if u.String() != want {
				t.Errorf("%s(%q) = %q, want %q", name, raw, u.String(), want)
			}
		}
	}
}

// TestParseURLLoopbackHTTPNeedsASCIILocalhost: only "localhost" in ASCII
// (any case) is the loopback name AllowLoopbackHTTP admits over http,
// not a spelling strings.EqualFold matches through a long s.
func TestParseURLLoopbackHTTPNeedsASCIILocalhost(t *testing.T) {
	if _, err := ParseIssuerURL("http://LocalHost:8080/", AllowLoopbackHTTP()); err != nil {
		t.Fatalf("ParseIssuerURL(http://LocalHost:8080/): %v", err)
	}
	if !isLoopbackHost("LOCALHOST") || isLoopbackHost("localho"+longS+"t") {
		t.Fatalf("isLoopbackHost folds beyond ASCII")
	}
	if u, err := ParseIssuerURL("http://localho"+longS+"t:8080/", AllowLoopbackHTTP()); err == nil {
		t.Fatalf("ParseIssuerURL(http://localhoſt:8080/) = %q, want an error", u.String())
	}
}
