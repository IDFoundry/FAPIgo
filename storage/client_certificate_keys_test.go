package storage

import (
	"slices"
	"testing"

	fapi "github.com/idfoundry/fapigo"
)

// TestRegisteredClientCertificateThumbprintsAndKeys checks the
// self-signed certificate thumbprints and the CA-issued certificate keys
// a client registers come back as given, the primary thumbprint first.
func TestRegisteredClientCertificateThumbprintsAndKeys(t *testing.T) {
	additional := []string{"second", "third"}
	keys := []string{"key-1"}
	c, err := NewRegisteredClient(RegisteredClientConfig{
		ID:                               "rp",
		RedirectURIs:                     []fapi.RegisteredRedirectURI{"https://rp.example/callback"},
		ClientAuthMethod:                 ClientAuthMethodSelfSignedTLSClientAuth,
		ExpectedCertificateThumbprint:    "first",
		AdditionalCertificateThumbprints: additional,
		CertificateKeyThumbprints:        keys,
		RequestObjectAlgorithm:           fapi.ES256,
		AllowedScopes:                    []string{"openid"},
	})
	if err != nil {
		t.Fatalf("NewRegisteredClient: %v", err)
	}
	additional[0], keys[0] = "changed", "changed"
	if got := c.ExpectedCertificateThumbprints(); !slices.Equal(got, []string{"first", "second", "third"}) {
		t.Errorf("ExpectedCertificateThumbprints() = %q", got)
	}
	if got := c.CertificateKeyThumbprints(); !slices.Equal(got, []string{"key-1"}) {
		t.Errorf("CertificateKeyThumbprints() = %q", got)
	}
	var none RegisteredClient
	if got := none.ExpectedCertificateThumbprints(); got != nil {
		t.Errorf("zero client's ExpectedCertificateThumbprints() = %q, want none", got)
	}
}
