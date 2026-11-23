package dpop

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/idfoundry/fapigo/internal/canonical"
)

// rsaProof is a PS256 DPoP proof signed by key whose header "jwk"
// writes the key's modulus and exponent as n and e, for a spelling
// CreateProof wouldn't use.
func rsaProof(t *testing.T, key *rsa.PrivateKey, n, e, jti, htu string, now time.Time) string {
	t.Helper()
	enc := base64.RawURLEncoding.EncodeToString
	header := fmt.Sprintf(`{"typ":"dpop+jwt","alg":"PS256","jwk":{"kty":"RSA","n":%q,"e":%q}}`, n, e)
	payload := fmt.Sprintf(`{"jti":%q,"htm":"POST","htu":%q,"iat":%d}`, jti, htu, now.Unix())
	input := enc([]byte(header)) + "." + enc([]byte(payload))
	digest := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPSS(rand.Reader, key, crypto.SHA256, digest[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	if err != nil {
		t.Fatalf("SignPSS: %v", err)
	}
	return input + "." + enc(sig)
}

// TestVerifyDetectsReplayUnderARespelledRSAKey: a replay record is kept
// under the thumbprint of the parsed proof key, not of the "jwk" member
// as written, so a proof that re-sends a jti under the same RSA key,
// its "n" or "e" now carrying a leading zero octet, which ParseJWK
// accepts, is still caught replaying it. The re-spelled key signs a
// fresh jti fine, under the same thumbprint.
func TestVerifyDetectsReplayUnderARespelledRSAKey(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	now := time.Now()
	target := mustURL(t, "https://as.example/token")
	replay := newMemoryReplayChecker()
	verify := func(proof string) (VerifiedProof, error) {
		return Verify(context.Background(), VerifyRequest{Proof: proof, Method: "POST", URL: target, Now: now, MaxProofAge: time.Minute, Replay: replay})
	}
	enc := base64.RawURLEncoding.EncodeToString
	n := key.N.Bytes()
	first, err := verify(rsaProof(t, key, enc(n), "AQAB", "jti-1", canonical.URI(target), now))
	if err != nil {
		t.Fatalf("Verify(canonical key) = %v", err)
	}
	for name, ne := range map[string][2]string{
		"257-octet n": {enc(append([]byte{0}, n...)), "AQAB"},
		"e as AAEAAQ": {enc(n), "AAEAAQ"},
	} {
		if _, err := verify(rsaProof(t, key, ne[0], ne[1], "jti-1", canonical.URI(target), now)); !errors.Is(err, errReplayed) {
			t.Errorf("%s: Verify(replayed jti) = %v, want the replay refused", name, err)
		}
		fresh, err := verify(rsaProof(t, key, ne[0], ne[1], "jti-"+name, canonical.URI(target), now))
		if err != nil || fresh.Thumbprint != first.Thumbprint {
			t.Errorf("%s: Verify(fresh jti) = %v, thumbprint %v; want accepted under %v", name, err, fresh.Thumbprint, first.Thumbprint)
		}
	}
}
