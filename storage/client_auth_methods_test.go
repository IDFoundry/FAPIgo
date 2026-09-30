package storage_test

import (
	"slices"
	"testing"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/storage"
)

func baseMultiConfig() storage.RegisteredClientConfig {
	return storage.RegisteredClientConfig{
		ID:                            "client-1",
		RedirectURIs:                  []fapi.RegisteredRedirectURI{"https://client.example/cb"},
		ClientAuthMethods:             []storage.ClientAuthMethod{storage.ClientAuthMethodPrivateKeyJWT, storage.ClientAuthMethodSelfSignedTLSClientAuth},
		ClientAssertionAlgorithms:     []fapi.SignatureAlgorithm{fapi.ES256, fapi.PS256},
		ExpectedCertificateThumbprint: "thumbprint",
	}
}

func TestRegisteredClientSeveralMethodsAndAlgorithms(t *testing.T) {
	c, err := storage.NewRegisteredClient(baseMultiConfig())
	if err != nil {
		t.Fatalf("NewRegisteredClient: %v", err)
	}
	for _, m := range []storage.ClientAuthMethod{storage.ClientAuthMethodPrivateKeyJWT, storage.ClientAuthMethodSelfSignedTLSClientAuth} {
		if !c.AllowsClientAuthMethod(m) {
			t.Errorf("AllowsClientAuthMethod(%v) = false, want true", m)
		}
	}
	if c.AllowsClientAuthMethod(storage.ClientAuthMethodTLSClientAuth) {
		t.Error("AllowsClientAuthMethod(tls_client_auth) = true, want false")
	}
	if c.ClientAuthMethod() != storage.ClientAuthMethodPrivateKeyJWT || c.ClientAssertionAlgorithm() != fapi.ES256 {
		t.Errorf("primary method/algorithm = %v/%v, want the first of each", c.ClientAuthMethod(), c.ClientAssertionAlgorithm())
	}
	if !c.AllowsClientAssertionAlgorithm(fapi.PS256) || c.AllowsClientAssertionAlgorithm(fapi.EdDSA) {
		t.Error("AllowsClientAssertionAlgorithm doesn't match ClientAssertionAlgorithms")
	}
	if got := c.ClientAuthMethods(); len(got) != 2 {
		t.Errorf("ClientAuthMethods() = %v, want both", got)
	}
	if !slices.Equal(c.ClientAssertionAlgorithms(), []fapi.SignatureAlgorithm{fapi.ES256, fapi.PS256}) {
		t.Errorf("ClientAssertionAlgorithms() = %v", c.ClientAssertionAlgorithms())
	}
	// A single-method registration still reports that one method.
	single, err := storage.NewRegisteredClient(storage.RegisteredClientConfig{
		ID: "client-2", RedirectURIs: []fapi.RegisteredRedirectURI{"https://client.example/cb"},
		ClientAssertionAlgorithm: fapi.ES256,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(single.ClientAuthMethods(), []storage.ClientAuthMethod{storage.ClientAuthMethodPrivateKeyJWT}) || !single.AllowsClientAssertionAlgorithm(fapi.ES256) {
		t.Errorf("single-method client = %v / %v", single.ClientAuthMethods(), single.ClientAssertionAlgorithms())
	}
}

func TestRegisteredClientSeveralMethodsValidation(t *testing.T) {
	for name, mutate := range map[string]func(*storage.RegisteredClientConfig){
		"listed method missing its field": func(c *storage.RegisteredClientConfig) { c.ExpectedCertificateThumbprint = "" },
		"singular method not listed":      func(c *storage.RegisteredClientConfig) { c.ClientAuthMethod = storage.ClientAuthMethodTLSClientAuth },
		"singular algorithm not listed":   func(c *storage.RegisteredClientConfig) { c.ClientAssertionAlgorithm = fapi.EdDSA },
		"private_key_jwt with no algorithm": func(c *storage.RegisteredClientConfig) {
			c.ClientAssertionAlgorithms = nil
		},
		"invalid listed algorithm": func(c *storage.RegisteredClientConfig) {
			c.ClientAssertionAlgorithms = []fapi.SignatureAlgorithm{fapi.ES256, 0}
		},
	} {
		cfg := baseMultiConfig()
		mutate(&cfg)
		if _, err := storage.NewRegisteredClient(cfg); err == nil {
			t.Errorf("%s: NewRegisteredClient = nil error, want error", name)
		}
	}
}

func TestNeedsJWKSWithSeveralMethods(t *testing.T) {
	cfg := storage.RegisteredClientConfig{
		ClientAuthMethod:  storage.ClientAuthMethodSelfSignedTLSClientAuth,
		ClientAuthMethods: []storage.ClientAuthMethod{storage.ClientAuthMethodSelfSignedTLSClientAuth, storage.ClientAuthMethodPrivateKeyJWT},
	}
	if !cfg.NeedsJWKS() {
		t.Error("NeedsJWKS() = false for a client that may use private_key_jwt")
	}
	cfg.ClientAuthMethods = []storage.ClientAuthMethod{storage.ClientAuthMethodSelfSignedTLSClientAuth}
	if cfg.NeedsJWKS() {
		t.Error("NeedsJWKS() = true for an mTLS-only client")
	}
}
