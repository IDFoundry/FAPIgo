package client

import (
	"context"
	"errors"
	"testing"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/keys"
)

// TestSigningWithoutKeysFailsCleanly covers newSigner and
// dpopKeyThumbprint on a client with no Dependencies.Keys. New never
// builds such a client with a signing configuration (keysNeeded), so
// this is unreachable through the public API; if a future signing path
// forgets keysNeeded, it must fail with an error, not panic.
func TestSigningWithoutKeysFailsCleanly(t *testing.T) {
	c := &Client{}
	if _, _, err := c.newSigner(context.Background(), keys.DPoPProofSigning, fapi.ES256); !errors.Is(err, errNoSigningKeys) {
		t.Errorf("newSigner = %v, want errNoSigningKeys", err)
	}
	if _, err := c.dpopKeyThumbprint(context.Background()); !errors.Is(err, errNoSigningKeys) {
		t.Errorf("dpopKeyThumbprint = %v, want errNoSigningKeys", err)
	}
}
