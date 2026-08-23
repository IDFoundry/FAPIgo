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
	return keys.PublicKeyInfo{}, nil
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
