package main

import (
	"testing"

	"github.com/idfoundry/fapigo/storage"
)

func validClientConfig() ClientConfig {
	return ClientConfig{
		ID:                       "client-1",
		RedirectURIs:             []string{"https://rp.example/callback"},
		ClientAssertionAlgorithm: "ES256",
		AllowedScopes:            []string{"openid", "accounts"},
		JWKS:                     []byte(`{"keys":[]}`),
	}
}

func TestResolveClientDefaultsToPrivateKeyJWT(t *testing.T) {
	registered, _, err := resolveClient(validClientConfig())
	if err != nil {
		t.Fatalf("resolveClient: %v", err)
	}
	if registered.ClientAuthMethod() != storage.ClientAuthMethodPrivateKeyJWT {
		t.Fatalf("ClientAuthMethod() = %v, want ClientAuthMethodPrivateKeyJWT", registered.ClientAuthMethod())
	}
}

func TestResolveClientSelfSignedTLSClientAuth(t *testing.T) {
	c := validClientConfig()
	c.ClientAssertionAlgorithm = ""
	c.JWKS = nil
	c.ClientAuthMethod = "self_signed_tls_client_auth"
	c.ExpectedCertificateThumbprint = "thumbprint-value"

	registered, _, err := resolveClient(c)
	if err != nil {
		t.Fatalf("resolveClient: %v", err)
	}
	if registered.ClientAuthMethod() != storage.ClientAuthMethodSelfSignedTLSClientAuth {
		t.Fatalf("ClientAuthMethod() = %v, want ClientAuthMethodSelfSignedTLSClientAuth", registered.ClientAuthMethod())
	}
	if registered.ExpectedCertificateThumbprint() != "thumbprint-value" {
		t.Fatalf("ExpectedCertificateThumbprint() = %q, want %q", registered.ExpectedCertificateThumbprint(), "thumbprint-value")
	}
}

func TestResolveClientTLSClientAuth(t *testing.T) {
	c := validClientConfig()
	c.ClientAssertionAlgorithm = ""
	c.JWKS = nil
	c.ClientAuthMethod = "tls_client_auth"
	c.ExpectedSubjectDN = "CN=client-1"

	registered, _, err := resolveClient(c)
	if err != nil {
		t.Fatalf("resolveClient: %v", err)
	}
	if registered.ClientAuthMethod() != storage.ClientAuthMethodTLSClientAuth {
		t.Fatalf("ClientAuthMethod() = %v, want ClientAuthMethodTLSClientAuth", registered.ClientAuthMethod())
	}
	if registered.ExpectedSubjectDN() != "CN=client-1" {
		t.Fatalf("ExpectedSubjectDN() = %q, want %q", registered.ExpectedSubjectDN(), "CN=client-1")
	}
}

func TestResolveClientRejectsInvalidClientAuthMethod(t *testing.T) {
	c := validClientConfig()
	c.ClientAuthMethod = "not_a_real_method"
	if _, _, err := resolveClient(c); err == nil {
		t.Fatalf("resolveClient(invalid client_auth_method) = nil error, want error")
	}
}

func TestResolveClientRejectsSelfSignedWithoutThumbprint(t *testing.T) {
	c := validClientConfig()
	c.ClientAssertionAlgorithm = ""
	c.JWKS = nil
	c.ClientAuthMethod = "self_signed_tls_client_auth"
	if _, _, err := resolveClient(c); err == nil {
		t.Fatalf("resolveClient(self_signed_tls_client_auth, no thumbprint) = nil error, want error")
	}
}

func TestResolveClientRejectsTLSClientAuthWithoutSubjectDN(t *testing.T) {
	c := validClientConfig()
	c.ClientAssertionAlgorithm = ""
	c.JWKS = nil
	c.ClientAuthMethod = "tls_client_auth"
	if _, _, err := resolveClient(c); err == nil {
		t.Fatalf("resolveClient(tls_client_auth, no subject dn) = nil error, want error")
	}
}

// TestResolveClientRejectsJWKSWhenNoSigningNeeded confirms the
// corrected jwks/jwks_uri requirement: a client that does no JWS
// signing at all (cert-based client auth, no request object or CIBA
// signing algorithm) must not declare a jwks/jwks_uri either — it would
// be dead configuration.
func TestResolveClientRejectsJWKSWhenNoSigningNeeded(t *testing.T) {
	c := validClientConfig()
	c.ClientAssertionAlgorithm = ""
	c.ClientAuthMethod = "self_signed_tls_client_auth"
	c.ExpectedCertificateThumbprint = "thumbprint-value"
	// c.JWKS is still set from validClientConfig — must be rejected.
	if _, _, err := resolveClient(c); err == nil {
		t.Fatalf("resolveClient(cert auth, no signing, jwks set) = nil error, want error")
	}
}

// TestResolveClientRequiresJWKSWhenRequestObjectSigningConfigured
// confirms jwks/jwks_uri stays required for a cert-authenticated client
// that also signs request objects — JWKS need is driven by whether the
// client does any JWS signing, not by ClientAuthMethod alone.
func TestResolveClientRequiresJWKSWhenRequestObjectSigningConfigured(t *testing.T) {
	c := validClientConfig()
	c.ClientAssertionAlgorithm = ""
	c.JWKS = nil
	c.ClientAuthMethod = "self_signed_tls_client_auth"
	c.ExpectedCertificateThumbprint = "thumbprint-value"
	c.RequestObjectAlgorithm = "ES256"
	if _, _, err := resolveClient(c); err == nil {
		t.Fatalf("resolveClient(cert auth, request object signing, no jwks) = nil error, want error")
	}
}

func TestResolveClientAllowsJWKSWhenRequestObjectSigningConfiguredUnderCertAuth(t *testing.T) {
	c := validClientConfig()
	c.ClientAssertionAlgorithm = ""
	c.ClientAuthMethod = "self_signed_tls_client_auth"
	c.ExpectedCertificateThumbprint = "thumbprint-value"
	c.RequestObjectAlgorithm = "ES256"
	// c.JWKS is set from validClientConfig — required here since this
	// client signs request objects.
	if _, _, err := resolveClient(c); err != nil {
		t.Fatalf("resolveClient: %v", err)
	}
}

func TestResolveClientBackchannelTokenDeliveryModeDefaultsToPoll(t *testing.T) {
	registered, _, err := resolveClient(validClientConfig())
	if err != nil {
		t.Fatalf("resolveClient: %v", err)
	}
	if registered.BackchannelTokenDeliveryMode() != storage.BackchannelTokenDeliveryModePoll {
		t.Fatalf("BackchannelTokenDeliveryMode() = %v, want BackchannelTokenDeliveryModePoll", registered.BackchannelTokenDeliveryMode())
	}
}

func TestResolveClientBackchannelTokenDeliveryModePing(t *testing.T) {
	c := validClientConfig()
	c.BackchannelAuthenticationRequestAlgorithm = "ES256"
	c.BackchannelTokenDeliveryMode = "ping"
	c.BackchannelClientNotificationEndpoint = "https://rp.example/ciba/notify"
	registered, _, err := resolveClient(c)
	if err != nil {
		t.Fatalf("resolveClient: %v", err)
	}
	if registered.BackchannelTokenDeliveryMode() != storage.BackchannelTokenDeliveryModePing {
		t.Fatalf("BackchannelTokenDeliveryMode() = %v, want BackchannelTokenDeliveryModePing", registered.BackchannelTokenDeliveryMode())
	}
	if registered.BackchannelClientNotificationEndpoint().String() != "https://rp.example/ciba/notify" {
		t.Fatalf("BackchannelClientNotificationEndpoint() = %v, want %q", registered.BackchannelClientNotificationEndpoint(), "https://rp.example/ciba/notify")
	}
}

func TestResolveClientRejectsInvalidBackchannelTokenDeliveryMode(t *testing.T) {
	c := validClientConfig()
	c.BackchannelTokenDeliveryMode = "push"
	if _, _, err := resolveClient(c); err == nil {
		t.Fatalf("resolveClient(invalid backchannel_token_delivery_mode) = nil error, want error")
	}
}

func TestResolveClientRejectsPingWithoutNotificationEndpoint(t *testing.T) {
	c := validClientConfig()
	c.BackchannelAuthenticationRequestAlgorithm = "ES256"
	c.BackchannelTokenDeliveryMode = "ping"
	if _, _, err := resolveClient(c); err == nil {
		t.Fatalf("resolveClient(ping, no notification endpoint) = nil error, want error")
	}
}
