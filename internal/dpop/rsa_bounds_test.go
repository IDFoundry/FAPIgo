package dpop

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/idfoundry/fapigo/internal/canonical"
	"github.com/idfoundry/fapigo/internal/jose"
)

// expensiveRSAProof is a DPoP proof anyone can build without holding a
// key: a PS256 header embedding an RSA "jwk" with an arbitrary odd
// modulus of bits bits and exponent e, otherwise-valid claims, and a
// junk signature.
func expensiveRSAProof(bits int, e int64, now time.Time, htu string) string {
	b64 := base64.RawURLEncoding
	n := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), uint(bits)), big.NewInt(1))
	header := fmt.Sprintf(`{"alg":"PS256","typ":"dpop+jwt","jwk":{"kty":"RSA","n":%q,"e":%q}}`,
		b64.EncodeToString(n.Bytes()), b64.EncodeToString(big.NewInt(e).Bytes()))
	payload := fmt.Sprintf(`{"jti":"x","htm":"POST","htu":%q,"iat":%d}`, htu, now.Unix())
	sig := make([]byte, bits/8)
	sig[len(sig)-1] = 2
	return b64.EncodeToString([]byte(header)) + "." + b64.EncodeToString([]byte(payload)) + "." + b64.EncodeToString(sig)
}

// TestVerifyRefusesExpensiveRSAProofKeyBeforeVerifying checks that a
// proof whose embedded key would make the signature check expensive is
// refused as its header is parsed — the errors are the jose parse-time
// ones, not jose.ErrInvalidSignature, so no RSA operation ran — and
// that nothing reaches the replay store.
func TestVerifyRefusesExpensiveRSAProofKeyBeforeVerifying(t *testing.T) {
	now := time.Now()
	target := mustURL(t, "https://as.example/token")
	cases := map[string]struct {
		bits int
		e    int64
		want error
	}{
		"8192-bit modulus":        {8192, 65537, jose.ErrRSAKeyTooLarge},
		"4097-bit modulus":        {4097, 65537, jose.ErrRSAKeyTooLarge},
		"e = 2^31-1":              {2048, 1<<31 - 1, jose.ErrUnsupportedRSAExponent},
		"e = 3":                   {2048, 3, jose.ErrUnsupportedRSAExponent},
		"8192-bit and e = 2^31-1": {8192, 1<<31 - 1, jose.ErrUnsupportedRSAExponent},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			replay := newMemoryReplayChecker()
			_, err := Verify(context.Background(), VerifyRequest{
				Proof: expensiveRSAProof(c.bits, c.e, now, canonical.URI(target)), Method: "POST", URL: target,
				Now: now, MaxProofAge: time.Minute, Replay: replay,
			})
			if !errors.Is(err, c.want) || errors.Is(err, jose.ErrInvalidSignature) {
				t.Fatalf("Verify error = %v, want %v and no signature check", err, c.want)
			}
			if len(replay.keys) != 0 {
				t.Fatalf("Verify recorded %d replay entries for a refused proof", len(replay.keys))
			}
		})
	}
}

// TestVerifyStillChecksSignatureOfAllowedRSAProofKey is the control: a
// 4096-bit, e = 65537 key is accepted as a key, so the same junk
// signature now fails as a signature.
func TestVerifyStillChecksSignatureOfAllowedRSAProofKey(t *testing.T) {
	now := time.Now()
	target := mustURL(t, "https://as.example/token")
	_, err := Verify(context.Background(), VerifyRequest{
		Proof: expensiveRSAProof(4096, 65537, now, canonical.URI(target)), Method: "POST", URL: target,
		Now: now, MaxProofAge: time.Minute,
	})
	if !errors.Is(err, jose.ErrInvalidSignature) {
		t.Fatalf("Verify(4096-bit key, junk signature) = %v, want ErrInvalidSignature", err)
	}
}
