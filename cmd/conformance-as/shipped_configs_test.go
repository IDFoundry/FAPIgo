package main

import (
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/idfoundry/fapigo/fapihttp"
	"github.com/idfoundry/fapigo/keys/ephemeral"
)

// TestShippedConfigsBuildClientKeySources loads every conformance
// profile's checked-in config and builds its client key source, the
// way wiring.go does at startup — so a library change that rejects a
// shipped config fails here, not an hour into a conformance run.
func TestShippedConfigsBuildClientKeySources(t *testing.T) {
	paths, err := filepath.Glob("../../conformance/server/oidf-config/*.config.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) == 0 {
		t.Fatal("no shipped configs found")
	}
	fetcher, err := fapihttp.New(http.DefaultClient, fapihttp.Config{MaxResponseBytes: 1 << 20, RequestTimeout: time.Second, MaxRedirects: 1})
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range paths {
		t.Run(filepath.Base(path), func(t *testing.T) {
			cfg, err := LoadConfig(path)
			if err != nil {
				t.Fatalf("LoadConfig: %v", err)
			}
			// The TLS files are mounted by docker-compose, not named in
			// the config, and Resolve only checks they're set.
			if cfg.TLS.CertFile == "" {
				cfg.TLS.CertFile, cfg.TLS.KeyFile = "tls.crt", "tls.key"
			}
			resolved, err := cfg.Resolve(false, AccessTokenFormatJWT)
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}
			if _, err := ephemeral.NewClientKeySource(fetcher, resolved.ClientKeys); err != nil {
				t.Fatalf("NewClientKeySource: %v", err)
			}
		})
	}
}
