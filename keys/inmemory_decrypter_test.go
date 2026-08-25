package keys_test

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/rsa"
	"testing"

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
