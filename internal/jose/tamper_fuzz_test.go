package jose

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/strictjson"
)

// FuzzSignVerifyTamper checks the one property every other JOSE-adjacent
// fuzz target in this module ultimately relies on but none of them
// actually verify: a token Sign produces must round-trip (ParseCompact
// + Verify recovers exactly the payload that was signed), and must
// reject any single-byte change anywhere in its header, payload, or
// signature segment. FuzzParseCompact already covers "does not panic on
// arbitrary input" — the case a fuzzer built purely from arbitrary
// strings essentially never reaches is a well-formed, genuinely signed
// token with exactly one byte wrong, since random mutation almost
// always breaks base64 decoding or the 3-segment shape long before it
// produces something ParseCompact accepts. Mutating already-decoded
// segment bytes (rather than the base64url characters themselves)
// guarantees the mutation survives re-encoding, so tampered inputs that
// still parse are testing a genuine semantic difference, not base64
// noise.
func FuzzSignVerifyTamper(f *testing.F) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatalf("generate key: %v", err)
	}

	f.Add([]byte(`{"hello":"world"}`), uint8(0), 0, uint8(0x01))
	f.Add([]byte(`{}`), uint8(1), 0, uint8(0xFF))
	f.Add([]byte(`{"a":1,"b":2}`), uint8(2), 3, uint8(0x80))

	f.Fuzz(func(t *testing.T, payload []byte, segment uint8, bytePos int, mask uint8) {
		if len(payload) == 0 {
			return // Sign refuses an empty payload — see its own doc comment for why.
		}
		if !strictjson.DecodesLosslessly(payload) {
			return // nor one that isn't valid UTF-8 or has an unpaired surrogate escape.
		}
		token := signAndVerifyUntampered(t, priv, payload)
		tampered, ok := flipOneByte(t, token, segment, bytePos, mask)
		if !ok {
			return
		}
		tc, err := ParseCompact(tampered)
		if err != nil {
			return
		}
		if err := tc.Verify(&priv.PublicKey, fapi.ES256); err == nil {
			t.Fatalf("Verify succeeded after single-byte tamper: original=%q tampered=%q", token, tampered)
		}
	})
}

// signAndVerifyUntampered signs payload and checks the untampered token
// parses, verifies and round-trips it, returning the token.
func signAndVerifyUntampered(t *testing.T, priv *ecdsa.PrivateKey, payload []byte) string {
	t.Helper()
	token, err := Sign(priv, Header{Algorithm: fapi.ES256, Type: "test+jwt"}, payload)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	compact, err := ParseCompact(token)
	if err != nil {
		t.Fatalf("ParseCompact(own Sign output): %v", err)
	}
	if err := compact.Verify(&priv.PublicKey, fapi.ES256); err != nil {
		t.Fatalf("Verify(untampered): %v", err)
	}
	if !bytes.Equal(compact.Payload, payload) {
		t.Fatalf("round-trip payload mismatch: got %q, want %q", compact.Payload, payload)
	}
	return token
}

// flipOneByte XORs mask (or 1, if mask is zero) into one decoded byte of
// one of token's three segments, chosen by segment and bytePos, and
// re-encodes it. It reports false when that segment decodes to nothing.
func flipOneByte(t *testing.T, token string, segment uint8, bytePos int, mask uint8) (string, bool) {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("own Sign output did not split into 3 segments: %q", token)
	}
	segIdx := int(segment) % 3
	raw, err := base64.RawURLEncoding.DecodeString(parts[segIdx])
	if err != nil || len(raw) == 0 {
		return "", false
	}
	if mask == 0 {
		mask = 1
	}
	pos := ((bytePos % len(raw)) + len(raw)) % len(raw)
	raw[pos] ^= mask
	parts[segIdx] = base64.RawURLEncoding.EncodeToString(raw)
	return strings.Join(parts, "."), true
}
