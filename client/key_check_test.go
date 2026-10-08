package client_test

import (
	"strings"
	"testing"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/client"
	"github.com/idfoundry/fapigo/keys"
)

// TestNewChecksOwnKeysAtStartup: New resolves each key of the client's
// own the configuration calls for, so a KeyManager missing a purpose, a
// key that doesn't suit the configured algorithm, or a decryption key
// of the wrong type is refused at startup, naming the purpose and
// algorithm — each used to surface only at the first request needing it.
func TestNewChecksOwnKeysAtStartup(t *testing.T) {
	for name, tc := range map[string]struct {
		mutate func(*client.Config, *client.Dependencies)
		want   string
	}{
		"no DPoP key": {
			func(_ *client.Config, d *client.Dependencies) {
				d.Keys = newFakeKeyManager(t, keys.ClientAuthentication, keys.RequestObjectSigning)
			},
			"keys has no usable dpop_proof_signing key for ES256",
		},
		"no client authentication key": {
			func(_ *client.Config, d *client.Dependencies) {
				d.Keys = newFakeKeyManager(t, keys.DPoPProofSigning, keys.RequestObjectSigning)
			},
			"keys has no usable client_authentication key for ES256",
		},
		"client authentication over a key of another algorithm": {
			func(c *client.Config, _ *client.Dependencies) { c.Algorithms.ClientAuthentication = fapi.PS256 },
			"keys has no usable client_authentication key for PS256",
		},
		"decryption key of another type": {
			func(c *client.Config, d *client.Dependencies) {
				c.Algorithms.IDTokenKeyManagement = fapi.ECDHESA256KW
				c.Algorithms.IDTokenContentEncryption = fapi.A256GCM
				d.Decryption = fakeDecrypter{} // an RSA key
			},
			"decryption has no usable id_token_decryption key for ECDH-ES+A256KW",
		},
	} {
		t.Run(name, func(t *testing.T) {
			cfg, deps := validConfig(t), validDependencies(t)
			tc.mutate(&cfg, &deps)
			if _, err := client.New(cfg, deps); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("New = %v, want an error containing %q", err, tc.want)
			}
		})
	}
}
