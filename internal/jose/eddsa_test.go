package jose

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"

	fapi "github.com/idfoundry/fapigo"
)

func generateEd25519Key(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	return pub, priv
}

func TestSignVerifyRoundTripEdDSA(t *testing.T) {
	pub, priv := generateEd25519Key(t)
	header := Header{Algorithm: fapi.EdDSA, Type: "test+jwt"}
	payload := []byte(`{"hello":"world"}`)

	token, err := Sign(priv, header, payload)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	compact, err := ParseCompact(token)
	if err != nil {
		t.Fatalf("ParseCompact: %v", err)
	}
	if err := compact.Verify(pub, fapi.EdDSA); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

// TestSignEdDSASignsRawSigningInputNotADigest is the discriminating
// test for this algorithm's one unusual property: RFC 8037 §3.1
// requires pure EdDSA over the JWS Signing Input itself, never a
// pre-hashed digest of it (unlike ES256/PS256). It reconstructs the
// exact signing input Sign uses internally and signs it independently
// with crypto/ed25519 directly — if Sign ever pre-hashed before calling
// the signer (the way it does for ES256/PS256), the two signatures
// would diverge, since Ed25519 is deterministic but only reproduces the
// same output for the same input bytes.
func TestSignEdDSASignsRawSigningInputNotADigest(t *testing.T) {
	_, priv := generateEd25519Key(t)
	header := Header{Algorithm: fapi.EdDSA}
	payload := []byte(`{"hello":"world"}`)

	token, err := Sign(priv, header, payload)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	compact, err := ParseCompact(token)
	if err != nil {
		t.Fatalf("ParseCompact: %v", err)
	}

	headerJSON, err := marshalHeader(header)
	if err != nil {
		t.Fatalf("marshalHeader: %v", err)
	}
	signingInput := base64.RawURLEncoding.EncodeToString(headerJSON) + "." +
		base64.RawURLEncoding.EncodeToString(payload)
	wantSig := ed25519.Sign(priv, []byte(signingInput))

	if !bytes.Equal(compact.signature, wantSig) {
		t.Fatalf("Sign produced a signature over something other than the raw signing input")
	}
}

func TestVerifyRejectsTamperedPayloadEdDSA(t *testing.T) {
	pub, priv := generateEd25519Key(t)
	token, err := Sign(priv, Header{Algorithm: fapi.EdDSA}, []byte(`{"amount":10}`))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	parts := strings.Split(token, ".")
	tamperedPayload := base64.RawURLEncoding.EncodeToString([]byte(`{"amount":10000}`))
	tampered := parts[0] + "." + tamperedPayload + "." + parts[2]

	compact, err := ParseCompact(tampered)
	if err != nil {
		t.Fatalf("ParseCompact: %v", err)
	}
	if err := compact.Verify(pub, fapi.EdDSA); err == nil {
		t.Fatalf("Verify(tampered payload) = nil error, want error")
	}
}

func TestVerifyRejectsTamperedSignatureEdDSA(t *testing.T) {
	pub, priv := generateEd25519Key(t)
	token, err := Sign(priv, Header{Algorithm: fapi.EdDSA}, []byte(`{"hello":"world"}`))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	parts := strings.Split(token, ".")
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("decode sig: %v", err)
	}
	sig[0] ^= 0xFF
	tampered := parts[0] + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString(sig)

	compact, err := ParseCompact(tampered)
	if err != nil {
		t.Fatalf("ParseCompact: %v", err)
	}
	if err := compact.Verify(pub, fapi.EdDSA); err == nil {
		t.Fatalf("Verify(tampered signature) = nil error, want error")
	}
}

func TestVerifyRejectsWrongKeyEdDSA(t *testing.T) {
	_, priv := generateEd25519Key(t)
	wrongPub, _ := generateEd25519Key(t)
	token, err := Sign(priv, Header{Algorithm: fapi.EdDSA}, []byte(`{"hello":"world"}`))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	compact, err := ParseCompact(token)
	if err != nil {
		t.Fatalf("ParseCompact: %v", err)
	}
	if err := compact.Verify(wrongPub, fapi.EdDSA); err == nil {
		t.Fatalf("Verify(wrong key) = nil error, want error")
	}
}

func TestVerifyRejectsAlgorithmMismatchEdDSA(t *testing.T) {
	pub, priv := generateEd25519Key(t)
	token, err := Sign(priv, Header{Algorithm: fapi.EdDSA}, []byte(`{"hello":"world"}`))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	compact, err := ParseCompact(token)
	if err != nil {
		t.Fatalf("ParseCompact: %v", err)
	}
	if err := compact.Verify(pub, fapi.ES256); err == nil {
		t.Fatalf("Verify(algorithm mismatch) = nil error, want error")
	}
}

func TestSignEdDSARejectsWrongKeyType(t *testing.T) {
	_, priv := generateEd25519Key(t)
	// An Ed25519 key used with a different algorithm should be
	// rejected, not silently accepted.
	if _, err := Sign(priv, Header{Algorithm: fapi.ES256}, []byte("x")); err == nil {
		t.Fatalf("Sign(Ed25519 key, ES256 header) = nil error, want error")
	}
}
