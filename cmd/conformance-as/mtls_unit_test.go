package main

import (
	"testing"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/storage"
)

func TestBuildMTLSEndpoints(t *testing.T) {
	issuer, err := fapi.ParseIssuerURL("https://as.example:8443")
	if err != nil {
		t.Fatalf("ParseIssuerURL: %v", err)
	}

	t.Run("without ciba", func(t *testing.T) {
		got, err := buildMTLSEndpoints(issuer, "0.0.0.0:8444", false)
		if err != nil {
			t.Fatalf("buildMTLSEndpoints: %v", err)
		}
		if got.Token.String() != "https://as.example:8444/token" {
			t.Errorf("Token = %q", got.Token.String())
		}
		if got.PushedAuthorizationRequest.String() != "https://as.example:8444/par" {
			t.Errorf("PushedAuthorizationRequest = %q", got.PushedAuthorizationRequest.String())
		}
		if !got.BackchannelAuthentication.IsZero() {
			t.Errorf("BackchannelAuthentication = %q, want zero", got.BackchannelAuthentication.String())
		}
	})

	t.Run("with ciba", func(t *testing.T) {
		got, err := buildMTLSEndpoints(issuer, "0.0.0.0:8444", true)
		if err != nil {
			t.Fatalf("buildMTLSEndpoints: %v", err)
		}
		if got.BackchannelAuthentication.String() != "https://as.example:8444/backchannel-authenticate" {
			t.Errorf("BackchannelAuthentication = %q", got.BackchannelAuthentication.String())
		}
	})

	t.Run("rejects a malformed mtls listen addr", func(t *testing.T) {
		if _, err := buildMTLSEndpoints(issuer, "not-a-host-port", false); err == nil {
			t.Fatalf("buildMTLSEndpoints(malformed addr) = nil error, want error")
		}
	})
}

func TestResolveClientSenderConstrain(t *testing.T) {
	base := ClientConfig{
		ID:                       "client-1",
		RedirectURIs:             []string{"https://rp.example/callback"},
		ClientAssertionAlgorithm: "ES256",
		JWKSURI:                  "https://rp.example/jwks",
	}

	t.Run("empty defaults to dpop", func(t *testing.T) {
		registered, _, err := resolveClient(base)
		if err != nil {
			t.Fatalf("resolveClient: %v", err)
		}
		if registered.SenderConstrain() != storage.SenderConstrainDPoP {
			t.Fatalf("SenderConstrain() = %v, want SenderConstrainDPoP", registered.SenderConstrain())
		}
	})

	t.Run("dpop explicit", func(t *testing.T) {
		c := base
		c.SenderConstrain = "dpop"
		registered, _, err := resolveClient(c)
		if err != nil {
			t.Fatalf("resolveClient: %v", err)
		}
		if registered.SenderConstrain() != storage.SenderConstrainDPoP {
			t.Fatalf("SenderConstrain() = %v, want SenderConstrainDPoP", registered.SenderConstrain())
		}
	})

	t.Run("mtls", func(t *testing.T) {
		c := base
		c.SenderConstrain = "mtls"
		registered, _, err := resolveClient(c)
		if err != nil {
			t.Fatalf("resolveClient: %v", err)
		}
		if registered.SenderConstrain() != storage.SenderConstrainMTLS {
			t.Fatalf("SenderConstrain() = %v, want SenderConstrainMTLS", registered.SenderConstrain())
		}
	})

	t.Run("rejects an unknown value", func(t *testing.T) {
		c := base
		c.SenderConstrain = "bogus"
		if _, _, err := resolveClient(c); err == nil {
			t.Fatalf("resolveClient(sender_constrain=bogus) = nil error, want error")
		}
	})
}
