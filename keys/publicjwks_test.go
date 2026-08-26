package keys_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"testing"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/keys"
)

// TestPublicJWKSWorksWithNoEngineAtAll is the proof this function
// exists for: an integrator with only key material and a declared
// algorithm — no client.Client, no server.Server, nothing beyond what
// keys itself already provides — can publish a real JWKS.
// NewKeyManagerFromSigners (#144) supplies the KeyManager; this
// supplies the JWKS. Neither role package is imported at all.
func TestPublicJWKSWorksWithNoEngineAtAll(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ecdsa key: %v", err)
	}
	km, err := keys.NewKeyManagerFromSigners(
		map[keys.SigningPurpose]crypto.Signer{keys.ClientAuthentication: priv},
		map[keys.SigningPurpose]fapi.SignatureAlgorithm{keys.ClientAuthentication: fapi.ES256},
		map[keys.SigningPurpose]string{keys.ClientAuthentication: "onboarding-kid"},
	)
	if err != nil {
		t.Fatalf("NewKeyManagerFromSigners: %v", err)
	}

	set, err := keys.PublicJWKS(context.Background(), []keys.SigningKeyUse{
		{Manager: km, Purpose: keys.ClientAuthentication, Algorithm: fapi.ES256},
	}, nil)
	if err != nil {
		t.Fatalf("PublicJWKS: %v", err)
	}
	if len(set.Keys) != 1 || set.Keys[0].KeyID() != "onboarding-kid" {
		t.Fatalf("Keys = %+v, want one key with kid \"onboarding-kid\"", set.Keys)
	}

	data, err := json.Marshal(set)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	var decoded struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if len(decoded.Keys) != 1 || decoded.Keys[0]["use"] != "sig" || decoded.Keys[0]["alg"] != "ES256" {
		t.Fatalf("decoded JWKS = %v, want one sig/ES256 key", decoded.Keys)
	}
}

func TestPublicJWKSIncludesEncryptionKey(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	backend, err := keys.NewInMemoryRSA(priv, "enc-kid")
	if err != nil {
		t.Fatalf("NewInMemoryRSA: %v", err)
	}
	dec, err := keys.NewSingleKeyDecrypter(backend)
	if err != nil {
		t.Fatalf("NewSingleKeyDecrypter: %v", err)
	}

	set, err := keys.PublicJWKS(context.Background(), nil, []keys.EncryptionKeyUse{
		{Decrypter: dec, Purpose: keys.IDTokenDecryption, Algorithm: fapi.RSAOAEP256},
	})
	if err != nil {
		t.Fatalf("PublicJWKS: %v", err)
	}
	if len(set.Keys) != 1 || set.Keys[0].KeyID() != "enc-kid" {
		t.Fatalf("Keys = %+v, want one key with kid \"enc-kid\"", set.Keys)
	}
}

func TestPublicJWKSDedupesAcrossUses(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ecdsa key: %v", err)
	}
	km, err := keys.NewKeyManagerFromSigners(
		map[keys.SigningPurpose]crypto.Signer{keys.ClientAuthentication: priv, keys.RequestObjectSigning: priv},
		map[keys.SigningPurpose]fapi.SignatureAlgorithm{keys.ClientAuthentication: fapi.ES256, keys.RequestObjectSigning: fapi.ES256},
		map[keys.SigningPurpose]string{keys.ClientAuthentication: "same-kid", keys.RequestObjectSigning: "same-kid"},
	)
	if err != nil {
		t.Fatalf("NewKeyManagerFromSigners: %v", err)
	}

	set, err := keys.PublicJWKS(context.Background(), []keys.SigningKeyUse{
		{Manager: km, Purpose: keys.ClientAuthentication, Algorithm: fapi.ES256},
		{Manager: km, Purpose: keys.RequestObjectSigning, Algorithm: fapi.ES256},
	}, nil)
	if err != nil {
		t.Fatalf("PublicJWKS: %v", err)
	}
	if len(set.Keys) != 1 {
		t.Fatalf("len(Keys) = %d, want 1 (both purposes share a kid)", len(set.Keys))
	}
}

// TestPublicJWKSUsesRotatingKeyManager confirms a SigningKeyUse.Manager
// implementing RotatingKeyManager publishes every key it reports, not
// just the one PublicKey/Sign currently uses.
type rotatingSigner struct {
	outgoing, newest crypto.Signer
	outgoingKID      string
	newestKID        string
}

func (m *rotatingSigner) Sign(context.Context, keys.SigningRequest) (keys.Signature, error) {
	return keys.Signature{}, errors.New("not implemented")
}

func (m *rotatingSigner) PublicKey(_ context.Context, _ keys.SigningPurpose, _ fapi.SignatureAlgorithm) (keys.PublicKeyInfo, error) {
	return keys.PublicKeyInfo{KeyID: m.newestKID, PublicKey: m.newest.Public()}, nil
}

func (m *rotatingSigner) PublicKeys(_ context.Context, _ keys.SigningPurpose, _ fapi.SignatureAlgorithm) (keys.SigningKeySet, error) {
	return keys.SigningKeySet{Keys: []keys.PublicKeyInfo{
		{KeyID: m.outgoingKID, PublicKey: m.outgoing.Public()},
		{KeyID: m.newestKID, PublicKey: m.newest.Public()},
	}}, nil
}

func TestPublicJWKSUsesRotatingKeyManager(t *testing.T) {
	outgoing, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ecdsa key: %v", err)
	}
	newest, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ecdsa key: %v", err)
	}
	m := &rotatingSigner{outgoing: outgoing, newest: newest, outgoingKID: "outgoing-kid", newestKID: "newest-kid"}

	set, err := keys.PublicJWKS(context.Background(), []keys.SigningKeyUse{
		{Manager: m, Purpose: keys.ClientAuthentication, Algorithm: fapi.ES256},
	}, nil)
	if err != nil {
		t.Fatalf("PublicJWKS: %v", err)
	}
	if len(set.Keys) != 2 {
		t.Fatalf("len(Keys) = %d, want 2 (outgoing + newest)", len(set.Keys))
	}
}

func TestPublicJWKSRejectsNilSigningManager(t *testing.T) {
	if _, err := keys.PublicJWKS(context.Background(), []keys.SigningKeyUse{
		{Manager: nil, Purpose: keys.ClientAuthentication, Algorithm: fapi.ES256},
	}, nil); err == nil {
		t.Fatal("PublicJWKS(nil Manager) = nil error, want error")
	}
}

func TestPublicJWKSRejectsNilDecrypter(t *testing.T) {
	if _, err := keys.PublicJWKS(context.Background(), nil, []keys.EncryptionKeyUse{
		{Decrypter: nil, Purpose: keys.IDTokenDecryption, Algorithm: fapi.RSAOAEP256},
	}); err == nil {
		t.Fatal("PublicJWKS(nil Decrypter) = nil error, want error")
	}
}

func TestPublicJWKSRejectsEmptyKeyID(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ecdsa key: %v", err)
	}
	km, err := keys.NewKeyManagerFromSigners(
		map[keys.SigningPurpose]crypto.Signer{keys.ClientAuthentication: priv},
		map[keys.SigningPurpose]fapi.SignatureAlgorithm{keys.ClientAuthentication: fapi.ES256},
		nil, // no kid supplied
	)
	if err != nil {
		t.Fatalf("NewKeyManagerFromSigners: %v", err)
	}
	if _, err := keys.PublicJWKS(context.Background(), []keys.SigningKeyUse{
		{Manager: km, Purpose: keys.ClientAuthentication, Algorithm: fapi.ES256},
	}, nil); err == nil {
		t.Fatal("PublicJWKS(empty kid) = nil error, want error")
	}
}
