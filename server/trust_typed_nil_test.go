package server_test

import (
	"crypto/x509"
	"strings"
	"testing"

	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/server"
)

// TestNewRefusesTypedNilTrustFields covers interface fields nested in
// AttesterTrust and ClientCertificateTrust holding a typed nil (a nil
// *ClientCertificateCRLs, say): New refuses each, naming the field,
// rather than panicking in the field's own validation.
func TestNewRefusesTypedNilTrustFields(t *testing.T) {
	x5c := server.X5CAttesterChain{
		TrustAnchors:  server.StaticAttesterTrustAnchors{Roots: x509.NewCertPool()},
		IssuerBinding: server.AttesterIssuerInCertificate,
		Revocation:    (*server.ClientCertificateCRLs)(nil),
	}
	for name, tc := range map[string]struct {
		attestation bool
		set         func(*server.Dependencies)
		want        string
	}{
		"x5c chain revocation":            {true, func(d *server.Dependencies) { d.AttesterTrust = x5c }, "X5CAttesterChain.Revocation is a nil *ClientCertificateCRLs"},
		"x5c chain by pointer revocation": {true, func(d *server.Dependencies) { d.AttesterTrust = &x5c }, "X5CAttesterChain.Revocation is a nil *ClientCertificateCRLs"},
		"registered attester keys": {true, func(d *server.Dependencies) {
			d.AttesterTrust = server.RegisteredAttesterKeys{Keys: keys.StaticAttesterKeys(nil)}
		}, "RegisteredAttesterKeys.Keys is a nil keys.StaticAttesterKeys"},
		"trusted client CAs revocation": {false, func(d *server.Dependencies) {
			d.ClientCertificateTrust = server.TrustedClientCAs{Roots: x509.NewCertPool(), Revocation: (*server.ClientCertificateCRLs)(nil)}
		}, "trusted client CAs: revocation is a nil *ClientCertificateCRLs"},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := validConfig(t)
			if tc.attestation {
				cfg = validAttestationConfig(t)
			}
			deps := validDependencies()
			tc.set(&deps)
			assertNewRefuses(t, cfg, deps, tc.want)
		})
	}
}

// assertNewRefuses checks New refuses deps with an error containing
// want, rather than accepting them or panicking.
func assertNewRefuses(t *testing.T, cfg server.Config, deps server.Dependencies, want string) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("New panicked: %v", r)
		}
	}()
	_, err := server.New(cfg, deps)
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("New = %v, want an error containing %q", err, want)
	}
}
