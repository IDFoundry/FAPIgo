package jose

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"math/big"
	"strings"
	"testing"

	fapi "github.com/idfoundry/fapigo"
)

// ed25519Encoding encodes y (below 2^255) little-endian with x's sign
// in the top bit.
func ed25519Encoding(y *big.Int, sign bool) []byte {
	be := y.FillBytes(make([]byte, 32))
	le := reverse(be)
	if sign {
		le[31] |= 0x80
	}
	return le
}

func okpJWK(x []byte) []byte {
	return []byte(fmt.Sprintf(`{"kty":"OKP","crv":"Ed25519","x":%q}`, base64.RawURLEncoding.EncodeToString(x)))
}

// TestIdentityEd25519KeyForgesWithoutTheCheck pins the threat the check
// exists for: crypto/ed25519 accepts the identity point as a public key,
// and then R = identity, s = 0 verifies over any message.
func TestIdentityEd25519KeyForgesWithoutTheCheck(t *testing.T) {
	identity := ed25519Encoding(big.NewInt(1), false)
	forged := append(append([]byte{}, identity...), make([]byte, 32)...)
	msg := []byte("any message at all")
	if !ed25519.Verify(ed25519.PublicKey(identity), msg, forged) {
		t.Fatal("crypto/ed25519 refused the identity-key forgery; the premise of this test no longer holds")
	}
	if err := verifyEdDSA(ed25519.PublicKey(identity), msg, forged); err == nil {
		t.Fatal("verifyEdDSA accepted a forged signature for the identity key")
	}
}

func TestEd25519RefusesSmallOrderKeys(t *testing.T) {
	if len(ed25519SmallOrderY) != 5 {
		t.Fatalf("small-order y values = %d, want 5", len(ed25519SmallOrderY))
	}
	for i, y := range ed25519SmallOrderY {
		for _, sign := range []bool{false, true} {
			t.Run(fmt.Sprintf("y%d sign=%v", i, sign), func(t *testing.T) {
				enc := ed25519Encoding(y, sign)
				if _, err := ParseJWK(okpJWK(enc), fapi.EdDSA); err == nil || !strings.Contains(err.Error(), "small order") {
					t.Fatalf("ParseJWK(small-order key) error = %v, want small order", err)
				}
				if err := verifyEdDSA(ed25519.PublicKey(enc), []byte("m"), make([]byte, ed25519.SignatureSize)); err == nil || !strings.Contains(err.Error(), "small order") {
					t.Fatalf("verifyEdDSA(small-order key) error = %v, want small order", err)
				}
			})
		}
	}
}

func TestEd25519RefusesNonCanonicalKeys(t *testing.T) {
	for name, y := range map[string]*big.Int{
		"y = p":       new(big.Int).Set(ed25519P),
		"y = p + 1":   new(big.Int).Add(ed25519P, big.NewInt(1)),
		"y = p + 2":   new(big.Int).Add(ed25519P, big.NewInt(2)),
		"y = 2^255-1": new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(1)),
	} {
		t.Run(name, func(t *testing.T) {
			enc := ed25519Encoding(y, false)
			if _, err := ParseJWK(okpJWK(enc), fapi.EdDSA); err == nil || !strings.Contains(err.Error(), "canonical") {
				t.Fatalf("ParseJWK(non-canonical key) error = %v, want not canonical", err)
			}
		})
	}
}

func TestEd25519AcceptsGeneratedKeys(t *testing.T) {
	for i := 0; i < 32; i++ {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("GenerateKey: %v", err)
		}
		if _, err := ParseJWK(okpJWK(pub), fapi.EdDSA); err != nil {
			t.Fatalf("ParseJWK(generated key): %v", err)
		}
		msg := []byte("signed message")
		if err := verifyEdDSA(pub, msg, ed25519.Sign(priv, msg)); err != nil {
			t.Fatalf("verifyEdDSA(generated key): %v", err)
		}
	}
}
