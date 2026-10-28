package server

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/idfoundry/fapigo/storage"
)

// allowAnyResource is a ResourcePolicy accepting every resource the
// server's own syntax checks pass, so a test reaches every
// resource that got that far rather than stopping at Config.Resources.
type allowAnyResource struct{}

func (allowAnyResource) AllowResources(context.Context, storage.RegisteredClient, []string) error {
	return nil
}

// resourceTestServer has resource indicators enabled and accepts any
// syntactically valid resource.
func resourceTestServer() *Server {
	return &Server{
		cfg:  Config{Resources: []string{"https://rs.example"}},
		deps: Dependencies{ResourcePolicy: allowAnyResource{}},
	}
}

// TestResourcesFromParametersRefusesLossyDecoding confirms a request
// object's resource that encoding/json would alter is refused with
// invalid_target, not accepted as the altered string.
func TestResourcesFromParametersRefusesLossyDecoding(t *testing.T) {
	s := resourceTestServer()
	for _, raw := range []string{"\"https://rs.example/\xff\"", `["https://a.example","https://rs.example/\udc00"]`} {
		resources, err := s.resourcesFromParameters(map[string]json.RawMessage{resourceParameter: json.RawMessage(raw)})
		if err == nil || err.Code() != ErrorInvalidTarget {
			t.Errorf("resourcesFromParameters(%q) = %q, %v; want invalid_target", raw, resources, err)
		}
	}
}
