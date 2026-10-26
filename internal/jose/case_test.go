package jose

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"

	fapi "github.com/idfoundry/fapigo"
)

// JOSE member names are case-sensitive (RFC 7515 §4); a member that only
// case-folds to a known name must not be read as that name.
func TestParsersRejectCaseVariantMemberNames(t *testing.T) {
	cases := map[string]func() error{
		"header": func() error { _, err := parseHeader([]byte(`{"ALG":"none"}`)); return err },
		"header duplicate": func() error {
			_, err := parseHeader([]byte(`{"alg":"ES256","Alg":"none"}`))
			return err
		},
		"jwk": func() error {
			_, err := ParseJWK([]byte(`{"KTY":"EC","crv":"P-256","x":"AA","y":"AA"}`), fapi.ES256)
			return err
		},
		"jwk set": func() error { _, err := ParseJWKSet([]byte(`{"Keys":[]}`)); return err },
	}
	for name, parse := range cases {
		if err := parse(); err == nil || !strings.Contains(err.Error(), "case-sensitive") {
			t.Errorf("%s: err = %v, want case-sensitivity rejection", name, err)
		}
	}
}

// A json.Decoder reads only the first of several top-level values, so a
// case variant followed by a second value must not pass as one value.
func TestParsersRejectTrailingData(t *testing.T) {
	cases := map[string]func() error{
		"header": func() error { _, err := parseHeader([]byte(`{"alg":"ES256","KID":"victim"} {}`)); return err },
		"jwk": func() error {
			_, err := ParseJWK([]byte(`{"kty":"EC","CRV":"P-256","x":"AA","y":"AA"} 1`), fapi.ES256)
			return err
		},
		"jwk set":            func() error { _, err := ParseJWKSet([]byte(`{"keys":[]}"x"`)); return err },
		"encryption jwk set": func() error { _, err := ParseEncryptionJWKSet([]byte(`{"keys":[]} []`)); return err },
	}
	for name, parse := range cases {
		if err := parse(); err == nil || !strings.Contains(err.Error(), "after the top-level") {
			t.Errorf("%s: err = %v, want trailing-data rejection", name, err)
		}
	}
}

// A JWK Set entry's "x5c" is read outside rawJWK, so a case variant must
// be caught there: such an entry is skipped, not read as carrying
// certificates.
func TestParseJWKSetSkipsCaseVariantX5C(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	enc := base64.RawURLEncoding.EncodeToString
	entry := func(x5c string) string {
		return `{"kty":"EC","crv":"P-256","x":"` + enc(key.X.FillBytes(make([]byte, 32))) +
			`","y":"` + enc(key.Y.FillBytes(make([]byte, 32))) + `","kid":"k","` + x5c + `":["AAAA"]}`
	}
	set, err := ParseJWKSet([]byte(`{"keys":[` + entry("x5c") + `]}`))
	if err != nil || len(set) != 1 || len(set[0].Certificates) != 1 {
		t.Fatalf("x5c: set = %+v, err = %v, want one key with one certificate", set, err)
	}
	set, err = ParseJWKSet([]byte(`{"keys":[` + entry("X5C") + `]}`))
	if err != nil || len(set) != 0 {
		t.Fatalf("X5C: set = %+v, err = %v, want the entry skipped", set, err)
	}
}
