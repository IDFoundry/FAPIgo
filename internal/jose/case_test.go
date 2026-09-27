package jose

import (
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
