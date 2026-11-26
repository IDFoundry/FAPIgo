package resource_test

import (
	"context"
	"strings"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/resource"
)

// boundIssuerKeys is an IssuerKeySource reporting a binding through
// keys.IssuerBound (or none, when issuer is ""), without resolving
// anything.
type boundIssuerKeys struct{ issuer string }

func (boundIssuerKeys) ResolveIssuerKeys(context.Context, keys.IssuerKeyRequest) (keys.IssuerKeySet, error) {
	return keys.IssuerKeySet{}, nil
}

func (b boundIssuerKeys) BoundIssuer() string { return b.issuer }

// unmarkedIssuerKeys is an IssuerKeySource not implementing
// keys.IssuerBound.
type unmarkedIssuerKeys struct{}

func (unmarkedIssuerKeys) ResolveIssuerKeys(context.Context, keys.IssuerKeyRequest) (keys.IssuerKeySet, error) {
	return keys.IssuerKeySet{}, nil
}

// TestJWTAccessTokensRefuseIssuerKeysBoundToAnotherIssuer: a source
// bound to another issuer would refuse every lookup, so both
// NewJWTAccessTokens and NewVerifier (for a literal) refuse it, naming
// both issuers.
func TestJWTAccessTokensRefuseIssuerKeysBoundToAnotherIssuer(t *testing.T) {
	issuer, err := fapi.ParseIssuerURL(testIssuer)
	if err != nil {
		t.Fatal(err)
	}
	const other = "https://other-as.example.com"
	src := boundIssuerKeys{issuer: other}
	wantErr := func(t *testing.T, err error) {
		t.Helper()
		if err == nil {
			t.Fatal("error = nil, want refusal of a source bound to another issuer")
		}
		if !strings.Contains(err.Error(), `"`+other+`"`) || !strings.Contains(err.Error(), `"`+testIssuer+`"`) {
			t.Errorf("error = %q, want it to name %q and %q", err, other, testIssuer)
		}
	}
	_, err = resource.NewJWTAccessTokens(src, issuer, testIssuer, fapi.ES256, 5*time.Minute, 8)
	wantErr(t, err)

	deps := validDependencies(t)
	deps.AccessTokens = resource.JWTAccessTokens{
		IssuerKeys: src, Issuer: issuer, Audience: testIssuer,
		Algorithm: fapi.ES256, MaxTokenLifetime: 5 * time.Minute, MaxKeyCandidates: 8,
	}
	_, err = resource.NewVerifier(validConfig(t), deps)
	wantErr(t, err)
}

// TestJWTAccessTokensAcceptMatchingOrUnboundIssuerKeys: a source bound
// to the configured issuer, an unbound one, and one not implementing
// keys.IssuerBound are all accepted.
func TestJWTAccessTokensAcceptMatchingOrUnboundIssuerKeys(t *testing.T) {
	issuer, err := fapi.ParseIssuerURL(testIssuer)
	if err != nil {
		t.Fatal(err)
	}
	for name, src := range map[string]keys.IssuerKeySource{
		"bound to own issuer": boundIssuerKeys{issuer: testIssuer},
		"unbound":             boundIssuerKeys{},
		"no IssuerBound":      unmarkedIssuerKeys{},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := resource.NewJWTAccessTokens(src, issuer, testIssuer, fapi.ES256, 5*time.Minute, 8); err != nil {
				t.Fatalf("NewJWTAccessTokens: %v", err)
			}
		})
	}
}
