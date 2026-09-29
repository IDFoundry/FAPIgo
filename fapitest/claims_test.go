package fapitest_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/idfoundry/fapigo/client"
	"github.com/idfoundry/fapigo/fapitest"
	"github.com/idfoundry/fapigo/server"
)

type staticClaims map[string]json.RawMessage

func (s staticClaims) ResolveIdentityClaims(_ context.Context, _ string, names []string) (map[string]json.RawMessage, error) {
	out := map[string]json.RawMessage{}
	for _, n := range names {
		if v, ok := s[n]; ok {
			out[n] = v
		}
	}
	return out, nil
}

// TestClientRequestsIdentityClaims checks client.BeginAuthorizationRequest.Claims
// end to end, under both PAR encodings: the plain form parameter and the
// signed request object.
func TestClientRequestsIdentityClaims(t *testing.T) {
	for name, profile := range map[string]server.Profile{
		"plain parameters": server.ProfileFAPISecurity,
		"request object":   server.ProfileFAPISecurityWithMessageSigning,
	} {
		t.Run(name, func(t *testing.T) {
			h := fapitest.New(t, fapitest.Config{
				Profile: profile,
				IdentityClaims: staticClaims{
					"email": json.RawMessage(`"user@example.com"`),
					"name":  json.RawMessage(`"Test User"`),
				},
			})
			tokens, err := h.RunAuthorizationCodeFlowWithRequest(context.Background(), client.BeginAuthorizationRequest{
				Scope:  []string{"openid", "accounts"},
				Claims: client.RequestedClaims{IDToken: []string{"email"}},
			})
			if err != nil {
				t.Fatalf("RunAuthorizationCodeFlowWithRequest: %v", err)
			}
			if got := string(tokens.IDTokenClaims.Parameters["email"]); got != `"user@example.com"` {
				t.Errorf("ID token email = %s, want the requested claim", got)
			}
			if _, ok := tokens.IDTokenClaims.Parameters["name"]; ok {
				t.Error("ID token carries name, which wasn't requested")
			}
		})
	}
}
