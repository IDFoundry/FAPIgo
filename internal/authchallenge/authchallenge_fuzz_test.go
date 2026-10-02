package authchallenge

import (
	"strings"
	"testing"
)

// FuzzParse checks that Parse never panics and that everything it
// returns is within the grammar it claims to enforce: lower-cased tchar
// scheme and parameter names, and parameter values free of control
// characters and non-ASCII bytes.
func FuzzParse(f *testing.F) {
	f.Add(`Bearer realm="example", error="invalid_token", error_description="The access token expired"`)
	f.Add(`DPoP algs="ES256 PS256", error="use_dpop_nonce", Bearer realm="r"`)
	f.Add(`Bearer error_description="a, \"b\" \\ c", error=invalid_request`)
	f.Add(`Negotiate abc+/def==, Bearer`)
	f.Add(`Bearer error=a, error=b`)
	f.Add(`BEARER Error = "x" ,, Realm=y`)
	f.Add(`Bearer error="unterminated`)
	f.Add(``)
	f.Fuzz(func(t *testing.T, v string) {
		challenges, err := Parse([]string{v})
		if err != nil {
			return
		}
		for _, c := range challenges {
			checkName(t, c.Scheme)
			for name, value := range c.Params {
				checkName(t, name)
				checkValue(t, name, value)
			}
		}
	})
}

// checkValue fails t if value, parameter name's, contains a control
// character other than tab, or a non-ASCII byte.
func checkValue(t *testing.T, name, value string) {
	t.Helper()
	for i := 0; i < len(value); i++ {
		if ch := value[i]; ch != '\t' && (ch < 0x20 || ch > 0x7E) {
			t.Fatalf("param %q value %q contains byte %#x", name, value, ch)
		}
	}
}

func checkName(t *testing.T, name string) {
	t.Helper()
	if name == "" || name != strings.ToLower(name) {
		t.Fatalf("name %q is empty or not lower-cased", name)
	}
	for i := 0; i < len(name); i++ {
		if !isTChar(name[i]) {
			t.Fatalf("name %q contains non-tchar %#x", name, name[i])
		}
	}
}
