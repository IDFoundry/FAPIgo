package jose

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	fapi "github.com/idfoundry/fapigo"
)

const base64URLAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

// nonCanonicalLastChar sets the unused low bits of seg's final
// character, which a lenient decoder ignores: the result decodes to the
// same bytes but is a different string. seg's length must leave unused
// bits (not a multiple of 4).
func nonCanonicalLastChar(t *testing.T, seg string) string {
	t.Helper()
	if len(seg)%4 == 0 {
		t.Fatalf("segment length %d leaves no unused bits", len(seg))
	}
	i := strings.IndexByte(base64URLAlphabet, seg[len(seg)-1])
	return seg[:len(seg)-1] + string(base64URLAlphabet[i|1])
}

func TestParseCompactRefusesNonCanonicalEncodings(t *testing.T) {
	enc := base64.RawURLEncoding.EncodeToString
	header, payload, sig := enc([]byte(`{"alg":"ES256"}`)), enc([]byte(`{"a":1}`)), enc(make([]byte, 64))
	if _, err := ParseCompact(header + "." + payload + "." + sig); err != nil {
		t.Fatalf("ParseCompact(canonical): %v", err)
	}
	malleated := nonCanonicalLastChar(t, sig)
	if lenient, err := base64.RawURLEncoding.DecodeString(malleated); err != nil || len(lenient) != 64 {
		t.Fatalf("premise: lenient decode of the malleated signature = %d bytes, %v", len(lenient), err)
	}
	for name, token := range map[string]string{
		"signature trailing bits": header + "." + payload + "." + malleated,
		"signature line feed":     header + "." + payload + "." + sig[:10] + "\n" + sig[10:],
		"payload line feed":       header + "." + payload[:3] + "\n" + payload[3:] + "." + sig,
		"header carriage return":  header[:4] + "\r" + header[4:] + "." + payload + "." + sig,
		"signature padding":       header + "." + payload + "." + sig + "==",
		"payload std alphabet":    header + "." + strings.NewReplacer("-", "+", "_", "/").Replace(enc([]byte{0xfb, 0xff})) + "." + sig,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseCompact(token); err == nil {
				t.Fatalf("ParseCompact(%q) = nil error, want error", token)
			}
		})
	}
}

func TestParseJWKRefusesNonCanonicalCoordinates(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	enc := base64.RawURLEncoding.EncodeToString
	x, y := enc(key.X.FillBytes(make([]byte, 32))), enc(key.Y.FillBytes(make([]byte, 32)))
	jwk := func(x string) []byte {
		return []byte(fmt.Sprintf(`{"kty":"EC","crv":"P-256","x":%q,"y":%q}`, x, y))
	}
	if _, err := ParseJWK(jwk(x), fapi.ES256); err != nil {
		t.Fatalf("ParseJWK(canonical): %v", err)
	}
	for name, bad := range map[string]string{
		"x trailing bits": nonCanonicalLastChar(t, x),
		"x line feed":     x[:5] + "\n" + x[5:],
		"x padding":       x + "=",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseJWK(jwk(bad), fapi.ES256); err == nil {
				t.Fatalf("ParseJWK(x %q) = nil error, want error", bad)
			}
		})
	}
}
