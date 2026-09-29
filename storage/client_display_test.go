package storage_test

import (
	"strings"
	"testing"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/storage"
)

func TestValidateClientName(t *testing.T) {
	for _, name := range []string{"", "Southport Savings Bank", "Banque d'Épargne", "東方銀行", strings.Repeat("a", storage.MaxClientNameBytes)} {
		if err := storage.ValidateClientName(name); err != nil {
			t.Errorf("ValidateClientName(%q) = %v, want nil", name, err)
		}
	}
	for label, name := range map[string]string{
		"too long":      strings.Repeat("a", storage.MaxClientNameBytes+1),
		"invalid UTF-8": "Bank\xff",
		"newline":       "Bank\nPay here",
		"NUL":           "Bank\x00",
		"bidi override": "Bank \u202egnp.exe",
		"bidi isolate":  "Bank \u2066x\u2069",
		"C1 control":    "Bank\u0085",
	} {
		if err := storage.ValidateClientName(name); err == nil {
			t.Errorf("ValidateClientName(%s) = nil, want error", label)
		}
	}
}

func TestRegisteredClientDisplay(t *testing.T) {
	logo, err := fapi.ParseEndpointURL("https://client.example/logo.png")
	if err != nil {
		t.Fatal(err)
	}
	cfg := storage.RegisteredClientConfig{
		ID:                       "client-1",
		RedirectURIs:             []fapi.RegisteredRedirectURI{"https://client.example/cb"},
		ClientAssertionAlgorithm: fapi.ES256,
		Display:                  storage.ClientDisplay{Name: "Example", LogoURI: logo},
	}
	client, err := storage.NewRegisteredClient(cfg)
	if err != nil {
		t.Fatalf("NewRegisteredClient: %v", err)
	}
	if got := client.Display(); got.Name != "Example" || got.LogoURI.String() != logo.String() || got.IsZero() {
		t.Errorf("Display() = %+v, want the configured name and logo", got)
	}

	cfg.Display.Name = "Example\u202e"
	if _, err := storage.NewRegisteredClient(cfg); err == nil {
		t.Error("NewRegisteredClient(name with a bidi override) = nil error, want error")
	}
	if !(storage.ClientDisplay{}).IsZero() {
		t.Error("zero ClientDisplay.IsZero() = false")
	}
}
