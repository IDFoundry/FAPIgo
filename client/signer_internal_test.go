package client

import (
	"bytes"
	"context"
	"crypto"
	"testing"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/keys"
)

// recordingKeyManager captures the last SigningRequest it received,
// without signing anything, so a test can assert which field
// keyManagerSigner.Sign routed its input into.
type recordingKeyManager struct{ lastReq keys.SigningRequest }

func (m *recordingKeyManager) Sign(_ context.Context, req keys.SigningRequest) (keys.Signature, error) {
	m.lastReq = req
	return keys.Signature{KeyID: "kid", Value: []byte("sig")}, nil
}

func (m *recordingKeyManager) PublicKey(context.Context, keys.SigningPurpose, fapi.SignatureAlgorithm) (keys.PublicKeyInfo, error) {
	return keys.PublicKeyInfo{}, nil
}

// TestKeyManagerSignerRoutesByAlgorithm confirms keyManagerSigner.Sign
// puts crypto.Signer.Sign's incoming bytes into SigningInput for EdDSA
// (RFC 8037 §3.1: pure EdDSA over the raw message, signaled by
// crypto.Hash(0)) and into Digest for ES256 — never the other field.
func TestKeyManagerSignerRoutesByAlgorithm(t *testing.T) {
	cases := []struct {
		name       string
		algorithm  fapi.SignatureAlgorithm
		opts       crypto.SignerOpts
		wantDigest bool
	}{
		{"EdDSA uses SigningInput", fapi.EdDSA, crypto.Hash(0), false},
		{"ES256 uses Digest", fapi.ES256, crypto.SHA256, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			manager := &recordingKeyManager{}
			signer := keyManagerSigner{
				ctx: context.Background(), manager: manager,
				purpose: keys.ClientAuthentication, algorithm: c.algorithm,
			}
			input := []byte("input bytes")

			if _, err := signer.Sign(nil, input, c.opts); err != nil {
				t.Fatalf("Sign: %v", err)
			}
			gotDigest := bytes.Equal(manager.lastReq.Digest, input)
			gotSigningInput := bytes.Equal(manager.lastReq.SigningInput, input)
			if c.wantDigest && (!gotDigest || gotSigningInput) {
				t.Fatalf("%s: Digest=%q SigningInput=%q, want input in Digest only", c.name, manager.lastReq.Digest, manager.lastReq.SigningInput)
			}
			if !c.wantDigest && (gotDigest || !gotSigningInput) {
				t.Fatalf("%s: Digest=%q SigningInput=%q, want input in SigningInput only", c.name, manager.lastReq.Digest, manager.lastReq.SigningInput)
			}
		})
	}
}
