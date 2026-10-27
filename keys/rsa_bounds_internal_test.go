package keys

import (
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"math/big"
	"testing"
)

// TestParseJWKSDocumentKeepsOperatorTrustedRSAKeysUpTo8192Bits checks
// an authorization server's issuer keys — fetched from a server the
// operator configured — keep the 8192-bit ceiling rather than the 4096
// one a caller-supplied key is held to, while still requiring e = 65537.
func TestParseJWKSDocumentKeepsOperatorTrustedRSAKeysUpTo8192Bits(t *testing.T) {
	entry := func(kid string, bits int, e int64) string {
		n := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), uint(bits)), big.NewInt(1))
		b64 := base64.RawURLEncoding
		return fmt.Sprintf(`{"kty":"RSA","kid":%q,"alg":"PS256","n":%q,"e":%q}`, kid, b64.EncodeToString(n.Bytes()), b64.EncodeToString(big.NewInt(e).Bytes()))
	}
	body := `{"keys":[` + entry("big", 8192, 65537) + `,` + entry("odd-e", 2048, 3) + `]}`
	got, err := parseJWKSDocument([]byte(body))
	if err != nil {
		t.Fatalf("parseJWKSDocument: %v", err)
	}
	if len(got) != 1 || got[0].KeyID != "big" || got[0].PublicKey.(*rsa.PublicKey).N.BitLen() != 8192 {
		t.Fatalf("parseJWKSDocument = %+v, want only the 8192-bit e=65537 key", got)
	}
}
