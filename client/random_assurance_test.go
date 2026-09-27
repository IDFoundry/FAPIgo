package client_test

import (
	"bytes"
	"crypto/rand"
	"io"
	"strings"
	"testing"

	"github.com/idfoundry/fapigo/client"
)

func TestNewProductionRequiresCryptoRandReader(t *testing.T) {
	cases := map[string]struct {
		random  io.Reader
		wantErr bool
	}{
		"crypto/rand.Reader":  {rand.Reader, false},
		"wrapped crypto/rand": {struct{ io.Reader }{rand.Reader}, true},
		"fixed bytes":         {bytes.NewReader(make([]byte, 4096)), true},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := validConfig(t)
			cfg.Assurance = client.AssuranceProduction
			deps := productionDeps(t)
			deps.Random = tc.random
			_, err := client.New(cfg, deps)
			if tc.wantErr {
				if err == nil || !strings.Contains(err.Error(), "random must be crypto/rand.Reader") {
					t.Fatalf("New(production) error = %v, want a random source error", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("New(production): %v", err)
			}
		})
	}

	// Development accepts any non-nil reader.
	deps := validDependencies(t)
	deps.Random = struct{ io.Reader }{rand.Reader}
	if _, err := client.New(validConfig(t), deps); err != nil {
		t.Fatalf("New(development, wrapped reader): %v", err)
	}
}
