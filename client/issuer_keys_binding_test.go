package client_test

import (
	"context"
	"strings"
	"testing"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/client"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/keys/ephemeral"
)

// boundIssuerKeys is an IssuerKeySource reporting a binding through
// keys.IssuerBound, without resolving anything.
type boundIssuerKeys struct{ issuer string }

func (boundIssuerKeys) ResolveIssuerKeys(context.Context, keys.IssuerKeyRequest) (keys.IssuerKeySet, error) {
	return keys.IssuerKeySet{}, nil
}

func (b boundIssuerKeys) BoundIssuer() string { return b.issuer }

func localIssuerKeysFor(t *testing.T, issuer string) *keys.LocalIssuerKeys {
	t.Helper()
	iss, err := fapi.ParseIssuerURL(issuer)
	if err != nil {
		t.Fatalf("ParseIssuerURL: %v", err)
	}
	km, err := ephemeral.NewKeyManager(map[keys.SigningPurpose]fapi.SignatureAlgorithm{keys.IDTokenSigning: fapi.ES256})
	if err != nil {
		t.Fatalf("NewKeyManager: %v", err)
	}
	l, err := keys.NewLocalIssuerKeys(iss, km)
	if err != nil {
		t.Fatalf("NewLocalIssuerKeys: %v", err)
	}
	return l
}

// TestNewRefusesIssuerKeysBoundToAnotherIssuer: an issuer key source
// bound to a different issuer would refuse every lookup the client
// makes, so New refuses it, naming both issuers.
func TestNewRefusesIssuerKeysBoundToAnotherIssuer(t *testing.T) {
	const other = "https://other-as.example.com"
	for name, src := range map[string]keys.IssuerKeySource{
		"stub":            boundIssuerKeys{issuer: other},
		"LocalIssuerKeys": localIssuerKeysFor(t, other),
		"trailing slash":  boundIssuerKeys{issuer: testIssuer + "/"},
	} {
		t.Run(name, func(t *testing.T) {
			deps := validDependencies(t)
			deps.IssuerKeys = src
			_, err := client.New(validConfig(t), deps)
			if err == nil {
				t.Fatal("New = nil error, want refusal of a source bound to another issuer")
			}
			want := src.(keys.IssuerBound).BoundIssuer()
			if !strings.Contains(err.Error(), want) || !strings.Contains(err.Error(), `"`+testIssuer+`"`) {
				t.Errorf("New error = %q, want it to name %q and %q", err, want, testIssuer)
			}
		})
	}
}

// TestNewAcceptsMatchingOrUnboundIssuerKeys: a source bound to the
// client's own issuer, an unbound one, and one not implementing
// keys.IssuerBound are all accepted.
func TestNewAcceptsMatchingOrUnboundIssuerKeys(t *testing.T) {
	for name, src := range map[string]keys.IssuerKeySource{
		"bound to own issuer": boundIssuerKeys{issuer: testIssuer},
		"LocalIssuerKeys":     localIssuerKeysFor(t, testIssuer),
		"unbound":             boundIssuerKeys{},
		"no IssuerBound":      validDependencies(t).IssuerKeys,
	} {
		t.Run(name, func(t *testing.T) {
			deps := validDependencies(t)
			deps.IssuerKeys = src
			if _, err := client.New(validConfig(t), deps); err != nil {
				t.Fatalf("New: %v", err)
			}
		})
	}
}
