package client_test

import (
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/client"
)

// TestRecommendedPresetsProduceAWorkingClient is the real end-to-end
// check that RecommendedLimits/RecommendedAlgorithms aren't just
// individually-plausible values: combined with each other, plus the
// two fields this module can't recommend in the abstract
// (MaxIDTokenLifetime, IDToken — both properties of whatever specific
// authorization server this client is configured against), client.New
// must actually accept the result.
func TestRecommendedPresetsProduceAWorkingClient(t *testing.T) {
	issuer, err := fapi.ParseIssuerURL(testIssuer)
	if err != nil {
		t.Fatalf("ParseIssuerURL: %v", err)
	}
	authz, err := fapi.ParseEndpointURL(testIssuer + "/authorize")
	if err != nil {
		t.Fatalf("ParseEndpointURL(authorize): %v", err)
	}
	tok, err := fapi.ParseEndpointURL(testIssuer + "/token")
	if err != nil {
		t.Fatalf("ParseEndpointURL(token): %v", err)
	}
	par, err := fapi.ParseEndpointURL(testIssuer + "/par")
	if err != nil {
		t.Fatalf("ParseEndpointURL(par): %v", err)
	}

	algorithms := client.RecommendedAlgorithms()
	algorithms.IDToken = fapi.ES256 // the one algorithm field this preset can't guess

	limits := client.RecommendedLimits()
	limits.MaxIDTokenLifetime = 5 * time.Minute // the one limit this preset can't guess

	cfg := client.Config{
		Issuer:      issuer,
		ClientID:    testClientID,
		RedirectURI: testRedirect,
		Endpoints:   client.Endpoints{Authorization: authz, Token: tok, PushedAuthorizationRequest: par},
		Profile:     client.ProfileFAPISecurity,
		Algorithms:  algorithms,
		Limits:      limits,
	}

	if _, err := client.New(cfg, validDependencies(t)); err != nil {
		t.Fatalf("New(RecommendedAlgorithms + RecommendedLimits): %v", err)
	}
}

// TestRecommendedLimitsRejectsWithoutMaxIDTokenLifetime confirms
// RecommendedLimits deliberately leaves MaxIDTokenLifetime at zero —
// New must still reject it until a caller sets that one field.
func TestRecommendedLimitsRejectsWithoutMaxIDTokenLifetime(t *testing.T) {
	limits := client.RecommendedLimits()
	if limits.MaxIDTokenLifetime != 0 {
		t.Fatalf("RecommendedLimits().MaxIDTokenLifetime = %v, want 0 (deliberately left for the caller)", limits.MaxIDTokenLifetime)
	}

	cfg := validConfig(t)
	cfg.Limits = limits
	if _, err := client.New(cfg, validDependencies(t)); err == nil {
		t.Fatal("New(RecommendedLimits, MaxIDTokenLifetime unset) = nil error, want error")
	}
}

// TestRecommendedAlgorithmsLeavesServerVerifiedAlgorithmsZero confirms
// RecommendedAlgorithms only ever fills in this client's own signing
// algorithms, never the ones it only verifies.
func TestRecommendedAlgorithmsLeavesServerVerifiedAlgorithmsZero(t *testing.T) {
	algs := client.RecommendedAlgorithms()
	if algs.ClientAuthentication != fapi.ES256 {
		t.Fatalf("ClientAuthentication = %v, want ES256", algs.ClientAuthentication)
	}
	if algs.DPoP != fapi.ES256 {
		t.Fatalf("DPoP = %v, want ES256", algs.DPoP)
	}
	if algs.IDToken != 0 {
		t.Fatalf("IDToken = %v, want 0 (depends on the specific authorization server)", algs.IDToken)
	}
	if algs.RequestObject != 0 || algs.JARM != 0 || algs.UserInfo != 0 {
		t.Fatalf("RequestObject/JARM/UserInfo = %v/%v/%v, want all 0", algs.RequestObject, algs.JARM, algs.UserInfo)
	}
	if algs.IDTokenKeyManagement != 0 || algs.UserInfoKeyManagement != 0 {
		t.Fatalf("IDTokenKeyManagement/UserInfoKeyManagement = %v/%v, want both 0 (encryption is opt-in)", algs.IDTokenKeyManagement, algs.UserInfoKeyManagement)
	}
}
