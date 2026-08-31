package main

import (
	"context"
	"fmt"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/jose"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/keys/ephemeral"
)

// ephemeralJWKS builds the "keys" array a suite plan config's
// "client.jwks" needs, one entry per purpose in purposes — the same
// jose.NewJWK/WithKeyID encoding main.go's own inline plan-config
// construction uses for its one-or-two-key case, generalized here since
// runCIBA needs a third purpose (BackchannelAuthenticationRequestSigning)
// alongside ClientAuthentication.
func ephemeralJWKS(ctx context.Context, m *ephemeral.KeyManager, purposes ...keys.SigningPurpose) ([]any, error) {
	out := make([]any, 0, len(purposes))
	for _, purpose := range purposes {
		info, err := m.PublicKey(ctx, purpose, fapi.ES256)
		if err != nil {
			return nil, fmt.Errorf("read public key for purpose %v: %w", purpose, err)
		}
		jwk, err := jose.NewJWK(info.PublicKey, fapi.ES256)
		if err != nil {
			return nil, fmt.Errorf("build jwk for purpose %v: %w", purpose, err)
		}
		out = append(out, jwk.WithKeyID(info.KeyID))
	}
	return out, nil
}
