package storage

import (
	"testing"

	fapi "github.com/idfoundry/fapigo"
)

func TestNewRegisteredClient(t *testing.T) {
	c, err := NewRegisteredClient(RegisteredClientConfig{
		ID:                       "client-123",
		RedirectURIs:             []fapi.RegisteredRedirectURI{"https://rp.example/callback"},
		ClientAssertionAlgorithm: fapi.ES256,
		RequestObjectAlgorithm:   fapi.ES256,
		AllowedScopes:            []string{"openid", "accounts"},
	})
	if err != nil {
		t.Fatalf("NewRegisteredClient: %v", err)
	}
	if c.ID() != "client-123" {
		t.Fatalf("ID() = %q, want %q", c.ID(), "client-123")
	}
	if !c.HasRedirectURI("https://rp.example/callback") {
		t.Fatalf("HasRedirectURI(registered) = false, want true")
	}
	if c.HasRedirectURI("https://rp.example/callback/") {
		t.Fatalf("HasRedirectURI(trailing slash) = true, want false")
	}
	if !c.AllowsScope("openid") {
		t.Fatalf("AllowsScope(openid) = false, want true")
	}
	if c.AllowsScope("payments") {
		t.Fatalf("AllowsScope(payments) = true, want false")
	}
	alg, ok := c.RequestObjectAlgorithm()
	if !ok || alg != fapi.ES256 {
		t.Fatalf("RequestObjectAlgorithm() = (%v, %v), want (ES256, true)", alg, ok)
	}
	if c.ClientAssertionAlgorithm() != fapi.ES256 {
		t.Fatalf("ClientAssertionAlgorithm() = %v, want ES256", c.ClientAssertionAlgorithm())
	}
}

func TestNewRegisteredClientRequestObjectAlgorithmOptional(t *testing.T) {
	c, err := NewRegisteredClient(RegisteredClientConfig{
		ID:                       "client-123",
		RedirectURIs:             []fapi.RegisteredRedirectURI{"https://rp.example/callback"},
		ClientAssertionAlgorithm: fapi.ES256,
	})
	if err != nil {
		t.Fatalf("NewRegisteredClient: %v", err)
	}
	_, ok := c.RequestObjectAlgorithm()
	if ok {
		t.Fatalf("RequestObjectAlgorithm() permitted = true, want false")
	}
}

func TestNewRegisteredClientRejectsInvalid(t *testing.T) {
	cases := []RegisteredClientConfig{
		{RedirectURIs: []fapi.RegisteredRedirectURI{"https://rp.example/callback"}, ClientAssertionAlgorithm: fapi.ES256},
		{ID: "client-123", ClientAssertionAlgorithm: fapi.ES256},
		{ID: "client-123", RedirectURIs: []fapi.RegisteredRedirectURI{"https://rp.example/callback"}},
		{
			ID: "client-123", RedirectURIs: []fapi.RegisteredRedirectURI{"https://rp.example/callback"},
			ClientAssertionAlgorithm: fapi.ES256, AllowedScopes: []string{""},
		},
		{
			ID: "client-123", RedirectURIs: []fapi.RegisteredRedirectURI{"https://rp.example/callback"},
			ClientAssertionAlgorithm: fapi.ES256, RequestObjectAlgorithm: fapi.SignatureAlgorithm(99),
		},
	}
	for i, c := range cases {
		if _, err := NewRegisteredClient(c); err == nil {
			t.Fatalf("case %d: NewRegisteredClient(%+v) = nil error, want error", i, c)
		}
	}
}
