package canonical

import (
	"net/url"
	"testing"
)

// Non-ASCII letters whose Unicode case mapping lands on, or comes from,
// an ASCII one. A host with any of them is dialed through IDNA as a
// DNS name other than its ASCII look-alike, so none may fold onto it.
const (
	dottedCapitalI = "İ" // "İ": strings.ToLower gives "i"
	kelvinSign     = "K" // "K": strings.ToLower gives "k"
	longS          = "ſ" // "ſ": strings.EqualFold matches "s"
	fullwidthB     = "Ｂ" // "Ｂ": strings.ToLower gives "ｂ" (U+FF42)
)

func TestLowerASCII(t *testing.T) {
	cases := map[string]string{
		"":                      "",
		"AS.Example":            "as.example",
		"already.lower":         "already.lower",
		dottedCapitalI + "BANK": dottedCapitalI + "bank",
		kelvinSign + "EY":       kelvinSign + "ey",
		fullwidthB + "ANK":      fullwidthB + "ank",
		"\xff\xC4X":             "\xff\xC4x",
		"MiXeD-123_.~":          "mixed-123_.~",
	}
	for in, want := range cases {
		if got := LowerASCII(in); got != want {
			t.Errorf("LowerASCII(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestEqualFoldASCII(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"AS.Example", "as.example", true},
		{"localhost", "LOCALHOST", true},
		{"", "", true},
		{dottedCapitalI + "bank", "ibank", false},
		{kelvinSign + "ey", "key", false},
		{"localho" + longS + "t", "localhost", false},
		{fullwidthB + "ank", "ｂank", false},
		{"a", "ab", false},
		{"@", "`", false},
		{"[", "{", false},
	}
	for _, c := range cases {
		if got := EqualFoldASCII(c.a, c.b); got != c.want {
			t.Errorf("EqualFoldASCII(%q, %q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

func TestIsASCII(t *testing.T) {
	for s, want := range map[string]bool{
		"":                      true,
		"xn--ibank-7fd.example": true,
		dottedCapitalI + "bank": false,
		kelvinSign:              false,
		"\x80":                  false,
	} {
		if got := IsASCII(s); got != want {
			t.Errorf("IsASCII(%q) = %v, want %v", s, got, want)
		}
	}
}

// TestURIFoldsHostCaseInASCIIOnly: URI lowercases a host's ASCII letters
// and nothing else, so a URL naming a non-ASCII host never canonicalizes
// to the same string as one naming an ASCII host it case-maps onto.
func TestURIFoldsHostCaseInASCIIOnly(t *testing.T) {
	cases := []struct {
		name string
		a, b string
		same bool
	}{
		{"mixed-case ASCII", "https://Bank.EXAMPLE/x", "https://bank.example/x", true},
		{"mixed-case ASCII scheme", "HtTpS://bank.example/x", "https://bank.example/x", true},
		{"dotted capital I", "https://" + dottedCapitalI + "bank.example/x", "https://ibank.example/x", false},
		{"percent-encoded dotted capital I", "https://%C4%B0bank.example/x", "https://ibank.example/x", false},
		{"Kelvin sign", "https://" + kelvinSign + "ey.example/x", "https://key.example/x", false},
		{"long s", "https://ba" + longS + "e.example/x", "https://base.example/x", false},
		{"fullwidth letter", "https://" + fullwidthB + "ank.example/x", "https://bank.example/x", false},
		{"fullwidth letter case", "https://" + fullwidthB + "ank.example/x", "https://ｂank.example/x", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := uriOf(t, c.a) == uriOf(t, c.b)
			if got != c.same {
				t.Fatalf("URI(%q) == URI(%q) is %v, want %v (%q, %q)", c.a, c.b, got, c.same, uriOf(t, c.a), uriOf(t, c.b))
			}
		})
	}
}

func uriOf(t *testing.T, raw string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("url.Parse(%q): %v", raw, err)
	}
	return URI(u)
}
