package keys_test

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/keys/ephemeral"
)

func custodyOf(v any) (keys.KeyCustody, bool) {
	a, ok := v.(keys.KeyCustodyAssurance)
	if !ok {
		return keys.KeyCustody{}, false
	}
	return a.KeyCustody(), true
}

func TestNewKeyManagerFromSignersDeclaresCustodyOnlyWhenAsked(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	specs := []keys.SignerSpec{{Purpose: keys.IDTokenSigning, Algorithm: fapi.ES256, Signer: priv, KeyID: "k1"}}

	plain, err := keys.NewKeyManagerFromSigners(specs)
	if err != nil {
		t.Fatalf("NewKeyManagerFromSigners: %v", err)
	}
	if _, ok := custodyOf(plain); ok {
		t.Fatal("undeclared KeyManager implements KeyCustodyAssurance; it must declare nothing")
	}

	want := keys.KeyCustody{Durable: true, CrossInstanceConsistent: true}
	declared, err := keys.NewKeyManagerFromSigners(specs, keys.DeclareCustody(want))
	if err != nil {
		t.Fatalf("NewKeyManagerFromSigners(DeclareCustody): %v", err)
	}
	if got, ok := custodyOf(declared); !ok || got != want {
		t.Fatalf("KeyCustody() = %+v (implements %v), want %+v", got, ok, want)
	}
	// The declaration wraps, rather than replaces, the KeyManager.
	info, err := declared.PublicKey(context.Background(), keys.IDTokenSigning, fapi.ES256)
	if err != nil || info.KeyID != "k1" {
		t.Fatalf("PublicKey() = %+v, %v; want kid k1", info, err)
	}
	if _, err := declared.Sign(context.Background(), keys.NewSigningRequest(keys.IDTokenSigning, fapi.ES256, make([]byte, 32))); err != nil {
		t.Fatalf("Sign(): %v", err)
	}
}

func TestNewDecrypterDeclaresCustodyOnlyWhenAsked(t *testing.T) {
	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	backend, err := keys.NewInMemoryECDH(priv, "enc-1")
	if err != nil {
		t.Fatalf("NewInMemoryECDH: %v", err)
	}
	plain, err := keys.NewSingleKeyDecrypter(backend)
	if err != nil {
		t.Fatalf("NewSingleKeyDecrypter: %v", err)
	}
	if _, ok := custodyOf(plain); ok {
		t.Fatal("undeclared Decrypter implements KeyCustodyAssurance; it must declare nothing")
	}
	declared, err := keys.NewSingleKeyDecrypter(backend, keys.DeclareCustody(keys.KeyCustody{Durable: true}))
	if err != nil {
		t.Fatalf("NewSingleKeyDecrypter(DeclareCustody): %v", err)
	}
	if got, ok := custodyOf(declared); !ok || !got.Durable {
		t.Fatalf("KeyCustody() = %+v (implements %v), want Durable", got, ok)
	}
	if _, err := declared.EncryptionPublicKey(context.Background(), keys.IDTokenDecryption, fapi.ECDHESA256KW); err != nil {
		t.Fatalf("EncryptionPublicKey(): %v", err)
	}
}

// TestEphemeralNeverDeclaresCustody pins what production assurance
// relies on to reject keys/ephemeral.
func TestEphemeralNeverDeclaresCustody(t *testing.T) {
	km, err := ephemeral.NewKeyManager(map[keys.SigningPurpose]fapi.SignatureAlgorithm{keys.IDTokenSigning: fapi.ES256})
	if err != nil {
		t.Fatalf("NewKeyManager: %v", err)
	}
	if _, ok := custodyOf(km); ok {
		t.Fatal("ephemeral.KeyManager implements KeyCustodyAssurance; it must not")
	}
}
