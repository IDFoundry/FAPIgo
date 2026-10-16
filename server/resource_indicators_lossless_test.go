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

// TestDecodesLosslessly covers what encoding/json would silently alter
// in a request object's "resource" member: invalid UTF-8 and unpaired
// surrogate escapes, which it replaces with U+FFFD.
func TestDecodesLosslessly(t *testing.T) {
	for name, tc := range map[string]struct {
		raw  string
		want bool
	}{
		"plain string":            {`"https://rs.example"`, true},
		"array":                   {`["https://a.example","https://b.example"]`, true},
		"escaped non-ASCII":       {`"https://rs.example/\u00e9"`, true},
		"escaped U+FFFD":          {`"https://rs.example/\ufffd"`, true},
		"surrogate pair":          {`"https://rs.example/\ud83d\ude00"`, true},
		"escaped backslash and u": {`"https://rs.example/\\ud800"`, true},
		"invalid UTF-8":           {"\"https://rs.example/\xff\"", false},
		"lone high surrogate":     {`"https://rs.example/\ud800"`, false},
		"lone low surrogate":      {`"https://rs.example/\udc00"`, false},
		"high then plain":         {`"https://rs.example/\ud83dx"`, false},
		"high then non-low":       {`"https://rs.example/\ud83dA"`, false},
		"high then high":          {`"https://rs.example/\ud83d\ud83d"`, false},
		"truncated escape":        {`"\u00"`, false},
		"non-hex escape":          {`"\uzzzz"`, false},
	} {
		t.Run(name, func(t *testing.T) {
			if got := decodesLosslessly([]byte(tc.raw)); got != tc.want {
				t.Errorf("decodesLosslessly(%q) = %v, want %v", tc.raw, got, tc.want)
			}
		})
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
