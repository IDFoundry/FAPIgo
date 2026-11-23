package redact

import (
	"fmt"
	"net/url"
	"slices"
	"testing"

	fapi "github.com/idfoundry/fapigo"
)

func TestMask(t *testing.T) {
	if Mask(fapi.Secret{}) != "" || Mask(fapi.NewSecret("value")) != Redacted {
		t.Error("Mask doesn't give an absent value no placeholder and a present one Redacted")
	}
	if MaskString("") != "" || MaskString("value") != Redacted {
		t.Error("MaskString doesn't give an absent value no placeholder and a present one Redacted")
	}
	if MaskStrings(nil) != nil || !slices.Equal(MaskStrings([]string{"a", ""}), []Hidden{Redacted, ""}) {
		t.Error("MaskStrings doesn't mask each value")
	}
}

type exampleShadow struct {
	name  string
	token Hidden
}

// example prints its shadow, as a redacting type does.
type example struct{ shadow exampleShadow }

func (e example) Format(f fmt.State, verb rune) {
	Format(f, verb, e.shadow, "redact.exampleShadow", "redact.example")
}

func TestFormatPrintsTheShadowUnderTheRealName(t *testing.T) {
	e := example{exampleShadow{name: "n", token: Redacted}}
	for format, want := range map[string]string{
		"%v":  "{n [REDACTED]}",
		"%+v": "{name:n token:[REDACTED]}",
		"%#v": `redact.example{name:"n", token:"[REDACTED]"}`,
		"%d":  "{%!d(string=n) %!d(redact.Hidden=[REDACTED])}",
		"%x":  "{6e 5b52454441435445445d}",
	} {
		if got := fmt.Sprintf(format, e); got != want {
			t.Errorf("Sprintf(%q) = %s, want %s", format, got, want)
		}
	}
}

func TestURLSummary(t *testing.T) {
	for _, tc := range []struct{ raw, want string }{
		{"https://rp.example/cb?code=SECRET&state=s&iss=https%3A%2F%2Fas.example", "https://rp.example/cb?code=[REDACTED]&state=[REDACTED]&iss=[REDACTED]"},
		{"https://rp.example:8443/a%2Fb/cb?response=a.b.c", "https://rp.example:8443/a%2Fb/cb?response=[REDACTED]"},
		{"com.example.app:/oauth2redirect?code=SECRET", "com.example.app:/oauth2redirect?code=[REDACTED]"},
		{"http://127.0.0.1:5000/cb?flag&error=access_denied", "http://127.0.0.1:5000/cb?flag&error=[REDACTED]"},
		{"https://rp.example", "https://rp.example"},
	} {
		u, err := url.Parse(tc.raw)
		if err != nil {
			t.Fatal(err)
		}
		if got := URL(*u); got != tc.want {
			t.Errorf("URL(%s) = %s, want %s", tc.raw, got, tc.want)
		}
	}
	credentialed := url.URL{Scheme: "https", Host: "rp.example", Path: "/cb", User: url.UserPassword("user", "pass"), Fragment: "frag", RawQuery: "a=1"}
	if got := URL(credentialed); got != "https://rp.example/cb?a=[REDACTED]" {
		t.Errorf("URL kept user info or a fragment: %s", got)
	}
}

// TestQueryQuotesNamesThatCouldForgeALogLine checks a name with a byte
// a URL query never carries unescaped, a newline say, prints quoted.
func TestQueryQuotesNamesThatCouldForgeALogLine(t *testing.T) {
	if got, want := Query("ok=1&evil\nlevel=INFO msg=forged=2"), `ok=[REDACTED]&"evil\nlevel"=[REDACTED]`; got != want {
		t.Errorf("Query = %q, want %q", got, want)
	}
	if got := Query(""); got != "" {
		t.Errorf("Query(\"\") = %q", got)
	}
	if got := Text("openid accounts"); got != "openid accounts" {
		t.Errorf("Text quoted printable text: %s", got)
	}
	if got := Text("openid\nlevel=INFO"); got != `"openid\nlevel=INFO"` {
		t.Errorf("Text(a newline) = %s, want it quoted", got)
	}
}
