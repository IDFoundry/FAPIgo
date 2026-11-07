package server

import (
	"crypto/x509"
	"slices"
	"testing"

	"github.com/idfoundry/fapigo/storage"
)

// Wrappers embedding ClientCertificateTrust implementations.
type (
	embeddedTrustedClientCAs struct{ TrustedClientCAs }
	embeddedVerifiedUpstream struct {
		ClientCertificateChainVerifiedUpstream
	}
	embeddedNoPKIClientAuthN struct{ NoPKIClientAuthentication }
)

// TestAutomaticClientAuthMethodsClassifiesEmbeddedTrust: a struct
// embedding a ClientCertificateTrust implementation is classified as
// that implementation, whose behaviour it has. Under an embedded
// TrustedClientCAs an empty allowed list stays every method; under an
// embedded NoPKIClientAuthentication naming tls_client_auth is refused.
func TestAutomaticClientAuthMethodsClassifiesEmbeddedTrust(t *testing.T) {
	cas := TrustedClientCAs{Roots: x509.NewCertPool(), Revocation: NoClientCertificateRevocationCheck{}}
	for name, trust := range map[string]ClientCertificateTrust{
		"TrustedClientCAs":          cas,
		"pointer TrustedClientCAs":  &cas,
		"embedded TrustedClientCAs": embeddedTrustedClientCAs{cas},
	} {
		if got, err := automaticClientAuthMethods(nil, trust); err != nil || got != nil {
			t.Errorf("%s: automaticClientAuthMethods(nil) = %v, %v, want every method (nil)", name, got, err)
		}
	}
	upstream, err := automaticClientAuthMethods(nil, embeddedVerifiedUpstream{})
	if err != nil || slices.Contains(upstream, storage.ClientAuthMethodTLSClientAuth) || len(upstream) == 0 {
		t.Errorf("embedded ClientCertificateChainVerifiedUpstream: automaticClientAuthMethods(nil) = %v, %v, want the methods needing no chain trust", upstream, err)
	}
	allowed := []storage.ClientAuthMethod{storage.ClientAuthMethodTLSClientAuth}
	for name, trust := range map[string]ClientCertificateTrust{
		"NoPKIClientAuthentication":          NoPKIClientAuthentication{},
		"pointer NoPKIClientAuthentication":  &NoPKIClientAuthentication{},
		"embedded NoPKIClientAuthentication": embeddedNoPKIClientAuthN{},
	} {
		if _, err := automaticClientAuthMethods(allowed, trust); err == nil {
			t.Errorf("%s: automaticClientAuthMethods(tls_client_auth) = nil error, want it refused", name)
		}
	}
}
