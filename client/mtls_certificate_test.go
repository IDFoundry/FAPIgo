package client_test

import (
	"crypto/tls"
	"strings"
	"testing"

	"github.com/idfoundry/fapigo/client"
	"github.com/idfoundry/fapigo/fapihttp"
	"github.com/idfoundry/fapigo/storage"
)

// TestNewProductionRequiresAClientCertificateForMutualTLS: under
// AssuranceProduction, a client doing mutual TLS (tokens bound to its
// certificate, or certificate client authentication) is refused an HTTP
// client that presents no certificate, since a server that didn't insist
// would answer with a Bearer token bound to nothing. One presenting a
// certificate, a client doing no mutual TLS, and the development level
// are all accepted.
func TestNewProductionRequiresAClientCertificateForMutualTLS(t *testing.T) {
	withCert := fapihttp.RecommendedTransportConfig()
	withCert.Certificates = []tls.Certificate{{}}
	withGetter := fapihttp.RecommendedTransportConfig()
	withGetter.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &tls.Certificate{}, nil }

	mtlsBound := func(c *client.Config) { c.SenderConstrain = storage.SenderConstrainMTLS }
	certAuth := func(c *client.Config) { c.ClientAuthMethod = storage.ClientAuthMethodSelfSignedTLSClientAuth }
	for name, tc := range map[string]struct {
		mutate    func(*client.Config)
		transport fapihttp.TransportConfig
		refused   bool
	}{
		"mTLS-bound, no certificate":       {mtlsBound, fapihttp.RecommendedTransportConfig(), true},
		"certificate auth, no certificate": {certAuth, fapihttp.RecommendedTransportConfig(), true},
		"mTLS-bound, certificate":          {mtlsBound, withCert, false},
		"mTLS-bound, GetClientCertificate": {mtlsBound, withGetter, false},
		"no mutual TLS, no certificate":    {func(*client.Config) {}, fapihttp.RecommendedTransportConfig(), false},
	} {
		t.Run(name, func(t *testing.T) {
			cfg, deps := productionClientSetup(t)
			tc.mutate(&cfg)
			deps.HTTP = hardenedHTTPClient(t, tc.transport)
			assertCertificateRefusal(t, "production", cfg, deps, tc.refused)
			if tc.refused {
				cfg.Assurance = client.AssuranceDevelopment
				assertCertificateRefusal(t, "development", cfg, deps, false)
			}
		})
	}
}

// assertCertificateRefusal checks New(cfg, deps) is refused for a
// missing client certificate when refused, and otherwise not.
func assertCertificateRefusal(t *testing.T, level string, cfg client.Config, deps client.Dependencies, refused bool) {
	t.Helper()
	_, err := client.New(cfg, deps)
	gotRefused := err != nil && strings.Contains(err.Error(), "presents no TLS client certificate")
	switch {
	case gotRefused != refused:
		t.Fatalf("New(%s) = %v, want refused for the missing certificate: %v", level, err, refused)
	case !refused && level == "production" && err != nil:
		t.Fatalf("New(%s): %v", level, err)
	}
}
