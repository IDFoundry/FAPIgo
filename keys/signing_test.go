package keys

import (
	"bytes"
	"testing"

	fapi "github.com/idfoundry/fapigo"
)

// TestNewSigningRequestRoutesByAlgorithm is the primary test for the
// Digest-vs-SigningInput dispatch every crypto.Signer-over-KeyManager
// adapter relies on (client/server each have their own) — see
// SigningRequest's own doc comment for why EdDSA can't share ES256/
// PS256's Digest field.
func TestNewSigningRequestRoutesByAlgorithm(t *testing.T) {
	input := []byte("digest or message bytes")

	eddsa := NewSigningRequest(ClientAuthentication, fapi.EdDSA, input)
	if !bytes.Equal(eddsa.SigningInput, input) {
		t.Fatalf("EdDSA: SigningInput = %q, want %q", eddsa.SigningInput, input)
	}
	if eddsa.Digest != nil {
		t.Fatalf("EdDSA: Digest = %q, want nil", eddsa.Digest)
	}

	es256 := NewSigningRequest(ClientAuthentication, fapi.ES256, input)
	if !bytes.Equal(es256.Digest, input) {
		t.Fatalf("ES256: Digest = %q, want %q", es256.Digest, input)
	}
	if es256.SigningInput != nil {
		t.Fatalf("ES256: SigningInput = %q, want nil", es256.SigningInput)
	}

	ps256 := NewSigningRequest(ClientAuthentication, fapi.PS256, input)
	if !bytes.Equal(ps256.Digest, input) {
		t.Fatalf("PS256: Digest = %q, want %q", ps256.Digest, input)
	}
	if ps256.SigningInput != nil {
		t.Fatalf("PS256: SigningInput = %q, want nil", ps256.SigningInput)
	}
}
