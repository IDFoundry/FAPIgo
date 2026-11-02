package client_test

import (
	"strings"
	"testing"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/client"
)

// TestNewRefusesIssuerWithQuery: an issuer has no query component (RFC
// 8414 §2, OpenID Connect Core §2), so New refuses one even when it was
// built with a parser that allows a query, under either assurance level.
func TestNewRefusesIssuerWithQuery(t *testing.T) {
	for _, assurance := range []client.AssuranceLevel{client.AssuranceDevelopment, client.AssuranceProduction} {
		for _, suffix := range []string{"?tenant=a", "?"} {
			t.Run(suffix, func(t *testing.T) {
				cfg := validConfig(t)
				cfg.Assurance = assurance
				issuer, err := fapi.ParseEndpointURL(cfg.Issuer.String() + suffix)
				if err != nil {
					t.Fatalf("ParseEndpointURL: %v", err)
				}
				cfg.Issuer = issuer
				if _, err := client.New(cfg, validDependencies(t)); err == nil || !strings.Contains(err.Error(), "query") {
					t.Fatalf("New(issuer %q, assurance %v) = %v, want the query refused", issuer, assurance, err)
				}
			})
		}
	}
}
