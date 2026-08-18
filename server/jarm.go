package server

import (
	"context"
	"encoding/json"
	"fmt"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/jarm"
	"github.com/idfoundry/fapigo/keys"
)

// signJARMResponse signs an authorization response for clientID carrying
// params as top-level claims.
func (s *Server) signJARMResponse(ctx context.Context, clientID fapi.ClientID, params map[string]string) (string, error) {
	signer, kid, err := s.newSigner(ctx, keys.JARMSigning, s.cfg.Algorithms.JARM)
	if err != nil {
		return "", err
	}

	jsonParams := make(map[string]json.RawMessage, len(params))
	for k, v := range params {
		if v == "" {
			continue
		}
		encoded, err := json.Marshal(v)
		if err != nil {
			return "", fmt.Errorf("marshal %q: %w", k, err)
		}
		jsonParams[k] = encoded
	}

	return jarm.Create(jarm.CreateParams{
		Signer:     signer,
		Algorithm:  s.cfg.Algorithms.JARM,
		KeyID:      kid,
		Issuer:     s.cfg.Issuer.String(),
		Audience:   clientID.String(),
		Now:        s.deps.Clock.Now(),
		Lifetime:   s.cfg.Limits.JARMResponseLifetime,
		Parameters: jsonParams,
	})
}
