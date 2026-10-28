package clientattestation

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/idfoundry/fapigo/internal/jose"
)

// TestPoP_Verify_RefusesExpensiveRSAConfirmationKey checks that an
// attestation's cnf.jwk is held to the caller-supplied RSA limits: a
// PS256 PoP whose confirmation key is over 4096 bits, or has an
// exponent other than 65537, is refused while the key is parsed,
// before its (junk) signature is checked.
func TestPoP_Verify_RefusesExpensiveRSAConfirmationKey(t *testing.T) {
	now := time.Unix(1300816000, 0)
	b64 := base64.RawURLEncoding
	header := b64.EncodeToString([]byte(`{"alg":"PS256","typ":"` + PoPTypHeader + `"}`))
	payload := b64.EncodeToString([]byte(fmt.Sprintf(`{"iss":"https://client.example.com","aud":"https://as.example.com","jti":"jti-1","iat":%d}`, now.Unix())))
	parsed, err := ParsePoP(header + "." + payload + "." + b64.EncodeToString(make([]byte, 1024)))
	if err != nil {
		t.Fatalf("ParsePoP: %v", err)
	}

	cases := map[string]struct {
		bits int
		e    int64
		want error
	}{
		"8192-bit modulus": {8192, 65537, jose.ErrRSAKeyTooLarge},
		"e = 2^31-1":       {2048, 1<<31 - 1, jose.ErrUnsupportedRSAExponent},
		"e = 3":            {2048, 3, jose.ErrUnsupportedRSAExponent},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			n := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), uint(c.bits)), big.NewInt(1))
			cnf := fmt.Sprintf(`{"kty":"RSA","n":%q,"e":%q}`, b64.EncodeToString(n.Bytes()), b64.EncodeToString(big.NewInt(c.e).Bytes()))
			_, err := parsed.Verify(context.Background(), []byte(cnf), basePoPPolicy(now))
			if !errors.Is(err, c.want) || errors.Is(err, jose.ErrInvalidSignature) {
				t.Fatalf("Verify error = %v, want %v and no signature check", err, c.want)
			}
		})
	}
}
