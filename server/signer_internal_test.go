package server

import (
	"bytes"
	"context"
	"crypto"
	"testing"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/keys"
)

// recordingKeyManager captures the SigningRequest it last received,
// without actually signing anything — for asserting keyManagerSigner
// routes crypto.Signer.Sign's incoming bytes into the right
// SigningRequest field for the algorithm in play.
type recordingKeyManager struct {
	lastReq keys.SigningRequest
}

func (m *recordingKeyManager) Sign(_ context.Context, req keys.SigningRequest) (keys.Signature, error) {
	m.lastReq = req
	return keys.Signature{KeyID: "kid", Value: []byte("sig")}, nil
}

func (m *recordingKeyManager) PublicKey(context.Context, keys.SigningPurpose, fapi.SignatureAlgorithm) (keys.PublicKeyInfo, error) {
	return keys.PublicKeyInfo{}, nil
}

// TestKeyManagerSignerRoutesEdDSAToSigningInput confirms
// keyManagerSigner.Sign puts crypto.Signer.Sign's incoming bytes into
// SigningRequest.SigningInput for EdDSA, not Digest — internal/jose's
// signEdDSA calls Sign with crypto.Hash(0) precisely to signal "this is
// the raw message, not a digest" (RFC 8037 §3.1), so this adapter must
// not treat it like ES256/PS256's pre-hashed case.
func TestKeyManagerSignerRoutesEdDSAToSigningInput(t *testing.T) {
	manager := &recordingKeyManager{}
	signer := keyManagerSigner{
		ctx: context.Background(), manager: manager,
		purpose: keys.JARMSigning, algorithm: fapi.EdDSA,
	}
	message := []byte("the raw jws signing input")

	if _, err := signer.Sign(nil, message, crypto.Hash(0)); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !bytes.Equal(manager.lastReq.SigningInput, message) {
		t.Fatalf("SigningInput = %q, want %q", manager.lastReq.SigningInput, message)
	}
	if manager.lastReq.Digest != nil {
		t.Fatalf("Digest = %q, want nil (EdDSA must not populate Digest)", manager.lastReq.Digest)
	}
}

// TestKeyManagerSignerRoutesES256ToDigest is the counterpart check: a
// hash-based algorithm must still land in Digest, not SigningInput —
// confirming the EdDSA branch didn't regress the existing path.
func TestKeyManagerSignerRoutesES256ToDigest(t *testing.T) {
	manager := &recordingKeyManager{}
	signer := keyManagerSigner{
		ctx: context.Background(), manager: manager,
		purpose: keys.JARMSigning, algorithm: fapi.ES256,
	}
	digest := []byte("a sha-256 digest, 32 bytes long")

	if _, err := signer.Sign(nil, digest, crypto.SHA256); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !bytes.Equal(manager.lastReq.Digest, digest) {
		t.Fatalf("Digest = %q, want %q", manager.lastReq.Digest, digest)
	}
	if manager.lastReq.SigningInput != nil {
		t.Fatalf("SigningInput = %q, want nil (ES256 must not populate SigningInput)", manager.lastReq.SigningInput)
	}
}
