package server_test

import (
	"strings"
	"testing"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/server"
)

// TestNewRefusesIssuerWithQuery: an issuer has no query component (RFC
// 8414 §2, OpenID Connect Core §2), so New refuses one even when it was
// built with a parser that allows a query, under either assurance level.
func TestNewRefusesIssuerWithQuery(t *testing.T) {
	prodCfg, prodDeps := productionConfigAndDeps(t)
	configs := map[string]struct {
		cfg  server.Config
		deps server.Dependencies
	}{
		"development": {validConfig(t), validDependencies()},
		"production":  {prodCfg, prodDeps},
	}
	for level, c := range configs {
		for _, suffix := range []string{"?tenant=a", "?"} {
			t.Run(level+" "+suffix, func(t *testing.T) {
				cfg := c.cfg
				issuer, err := fapi.ParseEndpointURL(cfg.Issuer.String() + suffix)
				if err != nil {
					t.Fatalf("ParseEndpointURL: %v", err)
				}
				cfg.Issuer = issuer
				if _, err := server.New(cfg, c.deps); err == nil || !strings.Contains(err.Error(), "query") {
					t.Fatalf("New(issuer %q) = %v, want the query refused", issuer, err)
				}
			})
		}
	}
}
