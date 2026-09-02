package main

import (
	"strings"
	"testing"
)

func TestFixedIdentityConfigValidate(t *testing.T) {
	base := fixedIdentityConfig{
		ClientID: "client-1", RedirectURI: "http://localhost:8088/callback",
		AccountsEndpoint: "https://suite.example/accounts",
		ClientJWKSFile:   "/tmp/client.jwks",
	}

	t.Run("all required fields present, no mTLS", func(t *testing.T) {
		if err := base.validate(); err != nil {
			t.Fatalf("validate() = %v, want nil", err)
		}
	})

	t.Run("missing client id", func(t *testing.T) {
		c := base
		c.ClientID = ""
		err := c.validate()
		if err == nil {
			t.Fatal("validate() = nil, want error")
		}
		if got := err.Error(); got == "" {
			t.Fatalf("validate() error message is empty")
		}
	})

	t.Run("missing redirect uri", func(t *testing.T) {
		c := base
		c.RedirectURI = ""
		if err := c.validate(); err == nil {
			t.Fatal("validate() = nil, want error")
		}
	})

	t.Run("missing accounts endpoint", func(t *testing.T) {
		c := base
		c.AccountsEndpoint = ""
		if err := c.validate(); err == nil {
			t.Fatal("validate() = nil, want error")
		}
	})

	t.Run("mTLS client auth requires cert and key", func(t *testing.T) {
		c := base
		c.ClientAuthMTLS = true
		err := c.validate()
		if err == nil {
			t.Fatal("validate() = nil, want error (missing -client-cert/-client-key)")
		}
	})

	t.Run("sender-constrain mTLS requires cert and key", func(t *testing.T) {
		c := base
		c.SenderConstrainMTLS = true
		err := c.validate()
		if err == nil {
			t.Fatal("validate() = nil, want error (missing -client-cert/-client-key)")
		}
	})

	t.Run("mTLS with cert and key present succeeds", func(t *testing.T) {
		c := base
		c.ClientAuthMTLS = true
		c.SenderConstrainMTLS = true
		c.ClientCertFile = "/tmp/cert.pem"
		c.ClientKeyFile = "/tmp/key.pem"
		if err := c.validate(); err != nil {
			t.Fatalf("validate() = %v, want nil", err)
		}
	})

	t.Run("private_key_jwt requires client jwks", func(t *testing.T) {
		c := base
		c.ClientJWKSFile = ""
		err := c.validate()
		if err == nil {
			t.Fatal("validate() = nil, want error (missing -client-jwks)")
		}
		if !strings.Contains(err.Error(), "-client-jwks") {
			t.Fatalf("validate() error %q does not mention -client-jwks", err.Error())
		}
	})

	t.Run("mTLS client auth does not require client jwks", func(t *testing.T) {
		c := base
		c.ClientAuthMTLS = true
		c.ClientCertFile = "/tmp/cert.pem"
		c.ClientKeyFile = "/tmp/key.pem"
		c.ClientJWKSFile = ""
		if err := c.validate(); err != nil {
			t.Fatalf("validate() = %v, want nil (client_auth_type=mtls needs no signed assertion)", err)
		}
	})

	t.Run("reports every missing field at once", func(t *testing.T) {
		c := fixedIdentityConfig{ClientAuthMTLS: true}
		err := c.validate()
		if err == nil {
			t.Fatal("validate() = nil, want error")
		}
		msg := err.Error()
		for _, want := range []string{"-client-id", "-redirect-uri", "-accounts-endpoint", "-client-cert", "-client-key"} {
			if !strings.Contains(msg, want) {
				t.Errorf("validate() error %q does not mention %q", msg, want)
			}
		}
	})
}
