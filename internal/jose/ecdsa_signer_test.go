package jose

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/asn1"
	"io"
	"math/big"
	"testing"

	fapi "github.com/idfoundry/fapigo"
)

// derSigner is a crypto.Signer for pub that returns der
// instead of a real signature: a misbehaving KMS or HSM.
type derSigner struct {
	pub *ecdsa.PublicKey
	der []byte
}

func (s derSigner) Public() crypto.PublicKey { return s.pub }

func (s derSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) { return s.der, nil }

func mustDER(t *testing.T, r, s *big.Int) []byte {
	t.Helper()
	der, err := asn1.Marshal(struct{ R, S *big.Int }{r, s})
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// TestSignECDSARefusesInvalidSignerOutput: a signer returning a value
// no valid ECDSA signature can have is refused, not panicked on or
// turned into a token that can't verify.
func TestSignECDSARefusesInvalidSignerOutput(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	n := elliptic.P256().Params().N
	one := big.NewInt(1)
	valid := mustDER(t, one, one)
	for name, der := range map[string][]byte{
		"oversized r":   mustDER(t, new(big.Int).Lsh(one, 300), one),
		"r equal to n":  mustDER(t, n, one),
		"negative s":    mustDER(t, one, big.NewInt(-1)),
		"zero r":        mustDER(t, big.NewInt(0), one),
		"trailing data": append(append([]byte{}, valid...), 0),
		"not DER":       {0x01, 0x02, 0x03},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Sign(derSigner{pub: &key.PublicKey, der: der}, Header{Algorithm: fapi.ES256}, []byte("{}")); err == nil {
				t.Fatal("Sign accepted the signer's invalid output")
			}
		})
	}
	if _, err := Sign(derSigner{pub: &key.PublicKey, der: valid}, Header{Algorithm: fapi.ES256}, []byte("{}")); err != nil {
		t.Fatalf("Sign with an in-range signature: %v", err)
	}
}
