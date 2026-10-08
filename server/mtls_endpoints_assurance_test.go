package server_test

import (
	"strings"
	"testing"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/server"
)

// TestNewRejectsLoopbackHTTPMTLSEndpointsUnderProduction: an
// mtls_endpoint_aliases URL is advertised in Metadata and used by mTLS
// clients exactly as Config.Endpoints are, so production refuses an
// http (fapi.AllowLoopbackHTTP) alias the same way.
func TestNewRejectsLoopbackHTTPMTLSEndpointsUnderProduction(t *testing.T) {
	loopback, err := fapi.ParseEndpointURL("http://localhost:9999/mtls", fapi.AllowLoopbackHTTP())
	if err != nil {
		t.Fatalf("ParseEndpointURL: %v", err)
	}
	cases := map[string]func(*server.MTLSEndpoints){
		"mtls_endpoints.token":                        func(e *server.MTLSEndpoints) { e.Token = loopback },
		"mtls_endpoints.pushed_authorization_request": func(e *server.MTLSEndpoints) { e.PushedAuthorizationRequest = loopback },
		"mtls_endpoints.backchannel_authentication":   func(e *server.MTLSEndpoints) { e.BackchannelAuthentication = loopback },
		"mtls_endpoints.revocation":                   func(e *server.MTLSEndpoints) { e.Revocation = loopback },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := validConfig(t)
			cfg.Assurance = server.AssuranceProduction
			cfg.Deployment = server.DeploymentSingleInstance
			cfg.MTLSEndpoints = productionMTLSEndpoints(t)
			mutate(&cfg.MTLSEndpoints)
			deps := validDependencies()
			deps.Audit = &fakeAuditSink{}
			_, err := server.New(cfg, deps)
			if err == nil || !strings.Contains(err.Error(), name+" was parsed with fapi.AllowLoopbackHTTP") {
				t.Fatalf("New(production, loopback %s) error = %v, want it refused by name", name, err)
			}
		})
	}

	t.Run("https aliases accepted", func(t *testing.T) {
		cfg := validConfig(t)
		cfg.Assurance = server.AssuranceProduction
		cfg.Deployment = server.DeploymentSingleInstance
		cfg.MTLSEndpoints = productionMTLSEndpoints(t)
		deps := validDependencies()
		deps.Audit = &fakeAuditSink{}
		if _, err := server.New(cfg, deps); err != nil {
			t.Fatalf("New(production, https aliases): %v", err)
		}
	})

	t.Run("development accepts loopback aliases", func(t *testing.T) {
		cfg := validConfig(t)
		cfg.MTLSEndpoints = server.MTLSEndpoints{Token: loopback, PushedAuthorizationRequest: loopback, BackchannelAuthentication: loopback, Revocation: loopback}
		if _, err := server.New(cfg, validDependencies()); err != nil {
			t.Fatalf("New(development, loopback aliases): %v", err)
		}
	})
}

func productionMTLSEndpoints(t *testing.T) server.MTLSEndpoints {
	t.Helper()
	u := func(s string) fapi.URL {
		v, err := fapi.ParseEndpointURL(s)
		if err != nil {
			t.Fatalf("ParseEndpointURL(%s): %v", s, err)
		}
		return v
	}
	return server.MTLSEndpoints{
		Token:                      u("https://mtls.as.example.com/token"),
		PushedAuthorizationRequest: u("https://mtls.as.example.com/par"),
		BackchannelAuthentication:  u("https://mtls.as.example.com/bc-authorize"),
		Revocation:                 u("https://mtls.as.example.com/revoke"),
	}
}
