package resource_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/jose"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/resource"
)

// unauthenticatedRSAProof is a DPoP proof anyone can build without a
// key: a PS256 header embedding an arbitrary odd bits-bit RSA modulus
// with exponent e, valid claims for target, and a junk signature.
func unauthenticatedRSAProof(bits int, e int64, now time.Time, target string) string {
	b64 := base64.RawURLEncoding
	n := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), uint(bits)), big.NewInt(1))
	header := fmt.Sprintf(`{"alg":"PS256","typ":"dpop+jwt","jwk":{"kty":"RSA","n":%q,"e":%q}}`,
		b64.EncodeToString(n.Bytes()), b64.EncodeToString(big.NewInt(e).Bytes()))
	payload := fmt.Sprintf(`{"jti":"x","htm":"GET","htu":%q,"iat":%d}`, target, now.Unix())
	sig := make([]byte, bits/8)
	sig[len(sig)-1] = 2
	return b64.EncodeToString([]byte(header)) + "." + b64.EncodeToString([]byte(payload)) + "." + b64.EncodeToString(sig)
}

// TestVerifyRefusesExpensiveRSAProofKeyWithoutAToken checks that a
// caller with no access token can't make the resource server do an
// RSA operation with a key of its choosing: a DPoP proof embedding an
// RSA key over 4096 bits, or with an exponent other than 65537, is
// refused as invalid_dpop_proof by the key's own check, before any
// signature verification or replay-store write.
func TestVerifyRefusesExpensiveRSAProofKeyWithoutAToken(t *testing.T) {
	now := time.Now()
	target, err := url.Parse("https://rs.example.com/userinfo")
	if err != nil {
		t.Fatal(err)
	}
	replay := &fakeReplayStore{}
	v := newRSABoundsVerifier(t, now, replay)

	cases := map[string]struct {
		bits int
		e    int64
		want error
	}{
		"8192-bit modulus, e = 2^31-1": {8192, 1<<31 - 1, jose.ErrUnsupportedRSAExponent},
		"8192-bit modulus":             {8192, 65537, jose.ErrRSAKeyTooLarge},
		"e = 2^31-1":                   {2048, 1<<31 - 1, jose.ErrUnsupportedRSAExponent},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := v.Verify(context.Background(), resource.VerifyRequest{
				Method: "GET", URL: target, Authorization: "DPoP junk",
				DPoPProofs: []string{unauthenticatedRSAProof(c.bits, c.e, now, target.String())},
			})
			assertRefusedProofKey(t, err, c.want)
			if len(replay.seen) != 0 {
				t.Fatalf("replay store recorded %d entries for a refused proof", len(replay.seen))
			}
		})
	}
}

func assertRefusedProofKey(t *testing.T, err, want error) {
	t.Helper()
	var rerr *resource.Error
	if !errors.As(err, &rerr) || rerr.Code() != resource.ErrorInvalidDPoPProof {
		t.Fatalf("Verify error = %v, want invalid_dpop_proof", err)
	}
	if !errors.Is(err, want) || errors.Is(err, jose.ErrInvalidSignature) {
		t.Fatalf("Verify error = %v, want it caused by %v before any signature check", err, want)
	}
}

func newRSABoundsVerifier(t *testing.T, now time.Time, replay *fakeReplayStore) *resource.Verifier {
	t.Helper()
	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	issuerURL, err := fapi.ParseIssuerURL(testIssuer)
	if err != nil {
		t.Fatal(err)
	}
	accessTokens, err := resource.NewJWTAccessTokens(&fakeIssuerKeySource{set: keys.IssuerKeySet{Keys: []keys.IssuerKey{
		{KeyID: "as-kid", Algorithm: fapi.ES256, PublicKey: issuerKey.Public()},
	}}}, issuerURL, testIssuer, fapi.ES256, 5*time.Minute, 8)
	if err != nil {
		t.Fatal(err)
	}
	v, err := resource.NewVerifier(validConfig(t), resource.Dependencies{
		AccessTokens: accessTokens, Replay: replay, Revocation: &fakeRevocationChecker{},
		Clock: fixedClock{now: now}, Random: rand.Reader,
	})
	if err != nil {
		t.Fatal(err)
	}
	return v
}
