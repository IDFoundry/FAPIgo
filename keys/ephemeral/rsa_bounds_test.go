package ephemeral

import (
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"math/big"
	"testing"
)

// TestParseClientKeysCapsRSAKeysAt4096Bits checks a client's JWK Set —
// keys a caller publishes — keeps a 4096-bit RSA key and skips an
// 8192-bit one, for verification and encryption alike.
func TestParseClientKeysCapsRSAKeysAt4096Bits(t *testing.T) {
	entry := func(kid, alg string, bits int) string {
		n := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), uint(bits)), big.NewInt(1))
		return fmt.Sprintf(`{"kty":"RSA","kid":%q,"alg":%q,"n":%q,"e":"AQAB"}`, kid, alg, base64.RawURLEncoding.EncodeToString(n.Bytes()))
	}
	body := `{"keys":[` + entry("sig-4096", "PS256", 4096) + `,` + entry("sig-8192", "PS256", 8192) + `,` +
		entry("enc-4096", "RSA-OAEP-256", 4096) + `,` + entry("enc-8192", "RSA-OAEP-256", 8192) + `]}`
	got, err := parseClientKeys([]byte(body))
	if err != nil {
		t.Fatalf("parseClientKeys: %v", err)
	}
	if len(got.verification) != 1 || got.verification[0].KeyID != "sig-4096" || got.verification[0].PublicKey.(*rsa.PublicKey).N.BitLen() != 4096 {
		t.Errorf("verification keys = %+v, want only sig-4096", got.verification)
	}
	if len(got.encryption) != 1 || got.encryption[0].KeyID != "enc-4096" {
		t.Errorf("encryption keys = %+v, want only enc-4096", got.encryption)
	}
}
