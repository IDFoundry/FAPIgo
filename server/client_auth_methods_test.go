package server_test

import (
	"context"
	"crypto/x509"
	"testing"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/mtls"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
)

// registerTestClient replaces the harness's testClientID with one built
// from mutate applied to its usual registration.
func registerTestClient(t *testing.T, h harness, mutate func(*storage.RegisteredClientConfig)) {
	t.Helper()
	cfg := storage.RegisteredClientConfig{
		ID:                       testClientID,
		RedirectURIs:             []fapi.RegisteredRedirectURI{testRedirectURI},
		ClientAssertionAlgorithm: fapi.ES256,
		RequestObjectAlgorithm:   fapi.ES256,
		AllowedScopes:            []string{"openid", "accounts", "offline_access"},
	}
	mutate(&cfg)
	client, err := storage.NewRegisteredClient(cfg)
	if err != nil {
		t.Fatalf("NewRegisteredClient: %v", err)
	}
	h.clients.clients[testClientID] = client
}

// pushWithAssertion makes a pushed authorization request authenticated
// with the harness's ES256 client assertion.
func pushWithAssertion(t *testing.T, h harness) error {
	t.Helper()
	_, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
		HTTP: server.FormRequest{Parameters: plainFormParameters(t, h.clientAssertion(t), nil)},
	})
	return err
}

// pushCert makes a pushed authorization request authenticated with cert.
func pushCert(h harness, cert *x509.Certificate) error {
	_, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
		HTTP:            server.FormRequest{Parameters: certFormParameters(nil)},
		PeerCertificate: cert,
	})
	return err
}

func TestClientAssertionAlgorithmFromTheClientsList(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	registerTestClient(t, h, func(c *storage.RegisteredClientConfig) {
		c.ClientAssertionAlgorithm = 0
		c.ClientAssertionAlgorithms = []fapi.SignatureAlgorithm{fapi.PS256, fapi.ES256}
	})
	if err := pushWithAssertion(t, h); err != nil {
		t.Errorf("ES256 assertion from a client allowing [PS256 ES256] = %v, want accepted", err)
	}
	registerTestClient(t, h, func(c *storage.RegisteredClientConfig) {
		c.ClientAssertionAlgorithm = 0
		c.ClientAssertionAlgorithms = []fapi.SignatureAlgorithm{fapi.PS256}
	})
	if code := serverErrorCode(t, pushWithAssertion(t, h)); code != server.ErrorInvalidClient {
		t.Errorf("ES256 assertion from a client allowing only PS256: code = %q, want %q", code, server.ErrorInvalidClient)
	}
}

func TestClientWithSeveralMethodsUsesEither(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	cert := selfSignedTestClientCert(t)
	registerTestClient(t, h, func(c *storage.RegisteredClientConfig) {
		c.ClientAuthMethods = []storage.ClientAuthMethod{storage.ClientAuthMethodPrivateKeyJWT, storage.ClientAuthMethodSelfSignedTLSClientAuth}
		c.ExpectedCertificateThumbprint = mtls.Thumbprint(cert)
	})
	if err := pushWithAssertion(t, h); err != nil {
		t.Errorf("private_key_jwt = %v, want accepted", err)
	}
	if err := pushCert(h, cert); err != nil {
		t.Errorf("self_signed_tls_client_auth = %v, want accepted", err)
	}
}

func TestClientCertificateMatchingAnyCertificateMethod(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	cert := selfSignedTestClientCert(t)
	// tls_client_auth can't pass (wrong subject, no chain trust); the
	// self-signed thumbprint can.
	registerTestClient(t, h, func(c *storage.RegisteredClientConfig) {
		c.ClientAuthMethod = storage.ClientAuthMethodTLSClientAuth
		c.ClientAuthMethods = []storage.ClientAuthMethod{storage.ClientAuthMethodTLSClientAuth, storage.ClientAuthMethodSelfSignedTLSClientAuth}
		c.ExpectedSubjectDN = "CN=someone else"
		c.ExpectedCertificateThumbprint = mtls.Thumbprint(cert)
	})
	if err := pushCert(h, cert); err != nil {
		t.Errorf("certificate matching the self-signed thumbprint = %v, want accepted", err)
	}
	if code := serverErrorCode(t, pushCert(h, selfSignedTestClientCert(t))); code != server.ErrorInvalidClient {
		t.Errorf("certificate matching neither method: code = %q, want %q", code, server.ErrorInvalidClient)
	}
	// A client with no certificate method at all.
	registerTestClient(t, h, func(*storage.RegisteredClientConfig) {})
	if code := serverErrorCode(t, pushCert(h, cert)); code != server.ErrorInvalidClient {
		t.Errorf("certificate for a private_key_jwt-only client: code = %q, want %q", code, server.ErrorInvalidClient)
	}
}
