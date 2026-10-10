package strictb64

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

// FuzzStrictMatchesCanonical: URL and Std accept exactly the canonical
// encodings: s is accepted iff it re-encodes to itself, and the decoded
// bytes match the standard library's strict decoder.
func FuzzStrictMatchesCanonical(f *testing.F) {
	for _, s := range []string{"", "AA", "AB", "QQ", "QR", "Zm9v", "Zm9vYg", "Zm9vYg==", "Zm9v\nYg", "Zm9v\r\nYg", "-_", "+/", "QUJD", "QUJDRA", "QUJDRA=="} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		check := func(name string, dec func(string) ([]byte, error), enc *base64.Encoding) {
			got, err := dec(s)
			if err != nil {
				return
			}
			if re := enc.EncodeToString(got); re != s {
				t.Fatalf("%s accepted %q, a non-canonical encoding of %x (canonical %q)", name, s, got, re)
			}
			if strings.ContainsAny(s, "\r\n") {
				t.Fatalf("%s accepted %q containing CR/LF", name, s)
			}
			want, err := enc.Strict().DecodeString(s)
			if err != nil || !bytes.Equal(want, got) {
				t.Fatalf("%s(%q) = %x, stdlib strict = %x, %v", name, s, got, want, err)
			}
		}
		check("URL", URL, base64.RawURLEncoding)
		check("Std", Std, base64.StdEncoding)
	})
}
