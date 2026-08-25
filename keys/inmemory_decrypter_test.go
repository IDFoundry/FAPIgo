package keys_test

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/keys"
)

func TestNewInMemoryECDHRejectsNilKey(t *testing.T) {
	if _, err := keys.NewInMemoryECDH(nil, "kid"); err == nil {
		t.Fatal("NewInMemoryECDH(nil) = nil error, want error")
	}
}

func TestNewInMemoryECDHRejectsNonP256Curve(t *testing.T) {
	priv, err := ecdh.P384().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate p-384 key: %v", err)
	}
	if _, err := keys.NewInMemoryECDH(priv, "kid"); err == nil {
		t.Fatal("NewInMemoryECDH(P-384 key) = nil error, want error")
	}
}

func TestNewInMemoryRSARejectsNilKey(t *testing.T) {
	if _, err := keys.NewInMemoryRSA(nil, "kid"); err == nil {
		t.Fatal("NewInMemoryRSA(nil) = nil error, want error")
	}
}

func TestNewInMemoryRSARejectsSmallKey(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("generate 1024-bit rsa key: %v", err)
	}
	if _, err := keys.NewInMemoryRSA(priv, "kid"); err == nil {
		t.Fatal("NewInMemoryRSA(1024-bit key) = nil error, want error")
	}
}

// TestInMemoryECDHAgreeSharedSecretRejectsMismatchedKeyID confirms this
// single-key backend fails closed on a keyID that doesn't match its
// own, rather than silently agreeing under the wrong key anyway.
func TestInMemoryECDHAgreeSharedSecretRejectsMismatchedKeyID(t *testing.T) {
	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ecdh key: %v", err)
	}
	backend, err := keys.NewInMemoryECDH(priv, "the-real-kid")
	if err != nil {
		t.Fatalf("NewInMemoryECDH: %v", err)
	}
	epk, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate epk: %v", err)
	}
	if _, err := backend.AgreeSharedSecret(context.Background(), "some-other-kid", epk.PublicKey()); err == nil {
		t.Fatal("AgreeSharedSecret(mismatched kid) = nil error, want error")
	}
	// An empty keyID (caller didn't specify one) must still work — the
	// check only fires on an actual mismatch.
	if _, err := backend.AgreeSharedSecret(context.Background(), "", epk.PublicKey()); err != nil {
		t.Fatalf("AgreeSharedSecret(empty kid) = %v, want success", err)
	}
	if _, err := backend.AgreeSharedSecret(context.Background(), "the-real-kid", epk.PublicKey()); err != nil {
		t.Fatalf("AgreeSharedSecret(matching kid) = %v, want success", err)
	}
}

// TestInMemoryRSADecryptKeyRejectsMismatchedKeyID mirrors
// TestInMemoryECDHAgreeSharedSecretRejectsMismatchedKeyID for the RSA
// backend.
func TestInMemoryRSADecryptKeyRejectsMismatchedKeyID(t *testing.T) {
	priv := generateRSAKey(t)
	backend, err := keys.NewInMemoryRSA(priv, "the-real-kid")
	if err != nil {
		t.Fatalf("NewInMemoryRSA: %v", err)
	}
	if _, err := backend.DecryptKey(context.Background(), "some-other-kid", fapi.RSAOAEP256, []byte("wrapped")); err == nil {
		t.Fatal("DecryptKey(mismatched kid) = nil error, want error")
	}
}
