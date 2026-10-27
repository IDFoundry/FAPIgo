package jose

import (
	"crypto"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"testing"

	fapi "github.com/idfoundry/fapigo"
)

// rsaJWKJSON is a public RSA JWK whose modulus is an odd number of
// exactly bits bits (2^bits - 1) — not a real key, but parsing checks
// only the modulus length and the exponent, so it exercises both the
// same way a real key of that size would, without generating one.
func rsaJWKJSON(bits int, e int64) string {
	n := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), uint(bits)), big.NewInt(1))
	b64 := base64.RawURLEncoding
	return fmt.Sprintf(`{"kty":"RSA","n":%q,"e":%q}`, b64.EncodeToString(n.Bytes()), b64.EncodeToString(big.NewInt(e).Bytes()))
}

func TestParseJWKAcceptsOnlyExponent65537(t *testing.T) {
	for _, e := range []int64{3, 17, 65539, 1<<31 - 1, 1 << 40} {
		t.Run(fmt.Sprint(e), func(t *testing.T) {
			_, err := ParseJWK([]byte(rsaJWKJSON(2048, e)), fapi.PS256)
			if !errors.Is(err, ErrUnsupportedRSAExponent) {
				t.Fatalf("ParseJWK(e=%d) error = %v, want ErrUnsupportedRSAExponent", e, err)
			}
		})
	}
}

func TestParseJWKCapsCallerRSAKeysAt4096Bits(t *testing.T) {
	for _, bits := range []int{2048, 3072, 4096} {
		if _, err := ParseJWK([]byte(rsaJWKJSON(bits, 65537)), fapi.PS256); err != nil {
			t.Errorf("ParseJWK(%d-bit, e=65537): %v", bits, err)
		}
	}
	for _, bits := range []int{4097, 6144, 8192} {
		_, err := ParseJWK([]byte(rsaJWKJSON(bits, 65537)), fapi.PS256)
		if !errors.Is(err, ErrRSAKeyTooLarge) {
			t.Errorf("ParseJWK(%d-bit) error = %v, want ErrRSAKeyTooLarge", bits, err)
		}
	}
}

func TestParseJWKSetSkipsOversizedRSAKeysButTrustedSetKeepsThem(t *testing.T) {
	body := []byte(`{"keys":[` + rsaJWKJSON(4096, 65537) + `,` + rsaJWKJSON(8192, 65537) + `,` + rsaJWKJSON(2048, 3) + `]}`)

	got, err := ParseJWKSet(body)
	if err != nil {
		t.Fatalf("ParseJWKSet: %v", err)
	}
	assertRSAModulusSizes(t, "ParseJWKSet", got, 4096)

	got, err = ParseTrustedJWKSet(body)
	if err != nil {
		t.Fatalf("ParseTrustedJWKSet: %v", err)
	}
	assertRSAModulusSizes(t, "ParseTrustedJWKSet", got, 4096, 8192)
}

func assertRSAModulusSizes(t *testing.T, name string, got []ParsedJWK, want ...int) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s returned %d keys, want %d", name, len(got), len(want))
	}
	for i, k := range got {
		if bits := rsaBits(t, k.PublicKey); bits != want[i] {
			t.Errorf("%s key %d is %d bits, want %d", name, i, bits, want[i])
		}
	}
}

func TestParseEncryptionJWKSetSkipsOversizedRSAKeys(t *testing.T) {
	entry := func(bits int) string {
		jwk := rsaJWKJSON(bits, 65537)
		return strings.TrimSuffix(jwk, "}") + `,"alg":"RSA-OAEP-256"}`
	}
	got, err := ParseEncryptionJWKSet([]byte(`{"keys":[` + entry(4096) + `,` + entry(8192) + `]}`))
	if err != nil {
		t.Fatalf("ParseEncryptionJWKSet: %v", err)
	}
	if len(got) != 1 || rsaBits(t, got[0].PublicKey) != 4096 {
		t.Fatalf("ParseEncryptionJWKSet = %+v, want only the 4096-bit key", got)
	}
}

// TestParseCompactRefusesExpensiveHeaderJWK checks that a JWS whose
// embedded "jwk" (as a DPoP proof carries) is an expensive RSA key is
// refused while the header is parsed — so there is never a Compact to
// call Verify on, and no RSA operation runs.
func TestParseCompactRefusesExpensiveHeaderJWK(t *testing.T) {
	cases := map[string]struct {
		jwk  string
		want error
	}{
		"8192-bit modulus": {rsaJWKJSON(8192, 65537), ErrRSAKeyTooLarge},
		"e = 2^31-1":       {rsaJWKJSON(2048, 1<<31-1), ErrUnsupportedRSAExponent},
		"both":             {rsaJWKJSON(8192, 1<<31-1), ErrUnsupportedRSAExponent},
	}
	b64 := base64.RawURLEncoding
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			header := `{"alg":"PS256","typ":"dpop+jwt","jwk":` + c.jwk + `}`
			token := b64.EncodeToString([]byte(header)) + "." + b64.EncodeToString([]byte(`{}`)) + "." + b64.EncodeToString(make([]byte, 1024))
			if _, err := ParseCompact(token); !errors.Is(err, c.want) {
				t.Fatalf("ParseCompact error = %v, want %v", err, c.want)
			}
		})
	}
}

func rsaBits(t *testing.T, pub crypto.PublicKey) int {
	t.Helper()
	key, ok := pub.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("key is %T, want *rsa.PublicKey", pub)
	}
	return key.N.BitLen()
}
