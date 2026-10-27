package server_test

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/idfoundry/fapigo/internal/jose"
	"github.com/idfoundry/fapigo/server"
)

// expensiveRSADPoPProof is a DPoP proof for htm POST at htu, embedding
// an arbitrary odd bits-bit RSA modulus with exponent e and carrying a
// junk signature.
func expensiveRSADPoPProof(bits int, e int64, now time.Time, htu string) string {
	b64 := base64.RawURLEncoding
	n := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), uint(bits)), big.NewInt(1))
	header := fmt.Sprintf(`{"alg":"PS256","typ":"dpop+jwt","jwk":{"kty":"RSA","n":%q,"e":%q}}`,
		b64.EncodeToString(n.Bytes()), b64.EncodeToString(big.NewInt(e).Bytes()))
	payload := fmt.Sprintf(`{"jti":"x","htm":"POST","htu":%q,"iat":%d}`, htu, now.Unix())
	sig := make([]byte, bits/8)
	sig[len(sig)-1] = 2
	return b64.EncodeToString([]byte(header)) + "." + b64.EncodeToString([]byte(payload)) + "." + b64.EncodeToString(sig)
}

// TestPushAuthorizationRequestRefusesExpensiveRSADPoPKey checks the
// authorization server holds a DPoP proof's embedded key to the
// caller-supplied RSA limits: over 4096 bits, or an exponent other
// than 65537, is invalid_dpop_proof from the key check itself, never
// reaching the signature check.
func TestPushAuthorizationRequestRefusesExpensiveRSADPoPKey(t *testing.T) {
	cases := map[string]struct {
		bits int
		e    int64
		want error
	}{
		"8192-bit modulus": {8192, 65537, jose.ErrRSAKeyTooLarge},
		"e = 2^31-1":       {2048, 1<<31 - 1, jose.ErrUnsupportedRSAExponent},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, server.ProfileFAPISecurity, true)
			_, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
				HTTP:       server.FormRequest{Parameters: plainFormParameters(t, h.clientAssertion(t), nil)},
				DPoPProofs: []string{expensiveRSADPoPProof(c.bits, c.e, h.now, testPAREndpoint)},
			})
			if code := serverErrorCode(t, err); code != server.ErrorInvalidDPoPProof {
				t.Fatalf("error code = %q, want %q", code, server.ErrorInvalidDPoPProof)
			}
			if !errors.Is(err, c.want) || errors.Is(err, jose.ErrInvalidSignature) {
				t.Fatalf("error = %v, want it caused by %v before any signature check", err, c.want)
			}
		})
	}
}
