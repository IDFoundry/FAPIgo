package server

import (
	"bytes"
	"context"
	"crypto"
	"testing"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/keys"
)

// recordingKeyManager is a keys.KeyManager that records the last
// SigningRequest it received instead of actually signing anything.
type recordingKeyManager struct{ lastReq keys.SigningRequest }

func (m *recordingKeyManager) Sign(_ context.Context, req keys.SigningRequest) (keys.Signature, error) {
	m.lastReq = req
	return keys.Signature{KeyID: "kid", Value: []byte("sig")}, nil
}

func (m *recordingKeyManager) PublicKey(context.Context, keys.SigningPurpose, fapi.SignatureAlgorithm) (keys.PublicKeyInfo, error) {
	return keys.PublicKeyInfo{KeyID: "kid"}, nil
}

// rotatedKeyManager reports kid "old" from PublicKey but signs with
// "new": a rotation between the two calls.
type rotatedKeyManager struct{}

func (*rotatedKeyManager) Sign(context.Context, keys.SigningRequest) (keys.Signature, error) {
	return keys.Signature{KeyID: "new", Value: []byte("sig")}, nil
}

func (*rotatedKeyManager) PublicKey(context.Context, keys.SigningPurpose, fapi.SignatureAlgorithm) (keys.PublicKeyInfo, error) {
	return keys.PublicKeyInfo{KeyID: "old"}, nil
}

// TestKeyManagerSignerRefusesAnotherKeysSignature: a signature made with
// a key other than the one whose kid the token's header names is
// refused, not issued mislabelled.
func TestKeyManagerSignerRefusesAnotherKeysSignature(t *testing.T) {
	signer, kid, err := newSignerFromKeys(context.Background(), &rotatedKeyManager{}, keys.IDTokenSigning, fapi.ES256)
	if err != nil {
		t.Fatalf("newSignerFromKeys: %v", err)
	}
	if kid != "old" {
		t.Fatalf("kid = %q, want old", kid)
	}
	if _, err := signer.Sign(nil, []byte("digest"), crypto.SHA256); err == nil {
		t.Fatal("Sign accepted a signature labelled with another key")
	}
}

// TestNewSignerFromKeysRoutesEdDSAToSigningInput drives
// newSignerFromKeys's production entry point end to end: the
// crypto.Signer it returns must, for EdDSA, deliver
// crypto.Signer.Sign's incoming bytes as SigningRequest.SigningInput —
// never Digest — since RFC 8037 §3.1 requires pure EdDSA over the raw
// message and internal/jose's signEdDSA signals that with
// crypto.Hash(0). A KeyManager that isn't updated for this would
// otherwise silently receive nothing useful in Digest.
func TestNewSignerFromKeysRoutesEdDSAToSigningInput(t *testing.T) {
	manager := &recordingKeyManager{}
	signer, _, err := newSignerFromKeys(context.Background(), manager, keys.JARMSigning, fapi.EdDSA)
	if err != nil {
		t.Fatalf("newSignerFromKeys: %v", err)
	}

	message := []byte("the raw jws signing input")
	if _, err := signer.Sign(nil, message, crypto.Hash(0)); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !bytes.Equal(manager.lastReq.SigningInput, message) {
		t.Fatalf("SigningInput = %q, want %q", manager.lastReq.SigningInput, message)
	}
	if manager.lastReq.Digest != nil {
		t.Fatalf("Digest = %q, want nil", manager.lastReq.Digest)
	}
}
