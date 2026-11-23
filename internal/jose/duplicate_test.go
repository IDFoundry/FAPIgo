package jose

import (
	"encoding/base64"
	"errors"
	"testing"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/strictjson"
)

// TestParseHeaderRefusesDuplicateMembers covers RFC 7515 §4: Header
// Parameter names are unique. A repeated member used to resolve to its
// last copy, where another implementation may read the first, and the
// case check saw only the last; now any repeated name, or two that
// differ only in case, refuses the header, at any depth, "jwk" included.
func TestParseHeaderRefusesDuplicateMembers(t *testing.T) {
	jwk, err := NewJWK(&generateEC(t).PublicKey, fapi.ES256)
	if err != nil {
		t.Fatalf("NewJWK: %v", err)
	}
	key, err := jwk.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}
	open := string(key[:len(key)-1]) // the key without its closing brace
	for name, header := range map[string]string{
		"alg twice":                       `{"alg":"ES256","alg":"ES256"}`,
		"kid twice":                       `{"alg":"ES256","kid":"a","kid":"b"}`,
		"typ, once escaped":               "{\"alg\":\"ES256\",\"typ\":\"JWT\",\"\x5cu0074yp\":\"dpop+jwt\"}",
		"jwk twice":                       `{"alg":"ES256","jwk":` + string(key) + `,"jwk":` + string(key) + `}`,
		"case variant in a non-last jwk":  `{"alg":"ES256","jwk":{"KTY":"EC"},"jwk":` + string(key) + `}`,
		"member repeated inside jwk":      `{"alg":"ES256","jwk":` + open + `,"kty":"EC"}}`,
		"x5c twice":                       `{"alg":"ES256","x5c":["AAAA"],"x5c":[]}`,
		"case variant before kid":         `{"alg":"ES256","KID":"a","kid":"b"}`,
		"private names differing in case": `{"alg":"ES256","ext":1,"EXT":2}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseHeader([]byte(header)); !errors.Is(err, strictjson.ErrDuplicateMember) {
				t.Fatalf("parseHeader(%s) = %v, want ErrDuplicateMember", header, err)
			}
			enc := base64.RawURLEncoding.EncodeToString
			compact := enc([]byte(header)) + "." + enc([]byte(`{}`)) + "." + enc(make([]byte, 64))
			if _, err := ParseCompact(compact); !errors.Is(err, strictjson.ErrDuplicateMember) {
				t.Fatalf("ParseCompact = %v, want ErrDuplicateMember", err)
			}
		})
	}
	if _, err := parseHeader([]byte(`{"alg":"ES256","kid":"a","jwk":` + string(key) + `}`)); err != nil {
		t.Fatalf("parseHeader(no repeats) = %v", err)
	}
}
