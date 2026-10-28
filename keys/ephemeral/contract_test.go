package ephemeral

import (
	"testing"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/keys"
)

// TestClientKeySourceContract runs keys.TestClientKeySourceContract
// against ClientKeySource over each client's inline JWK Set.
func TestClientKeySourceContract(t *testing.T) {
	keys.TestClientKeySourceContract(t, func(t *testing.T, clients map[fapi.ClientID][]byte) keys.ClientKeySource {
		specs := make([]ClientKeySpec, 0, len(clients))
		for id, doc := range clients {
			specs = append(specs, ClientKeySpec{ClientID: id, JWKS: doc})
		}
		src, err := NewClientKeySource(nil, specs)
		if err != nil {
			t.Fatalf("NewClientKeySource: %v", err)
		}
		return src
	})
}
