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
// one field this module can't recommend in the abstract (IDToken, a
// property of whatever specific authorization server this client is
// configured against, which NewFromDiscovery fills in when the server
// advertises only one), client.New must actually accept the result.
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

	cfg := client.Config{
		Issuer:                         issuer,
		ClientID:                       testClientID,
		RedirectURI:                    testRedirect,
		Endpoints:                      client.Endpoints{Authorization: authz, Token: tok, PushedAuthorizationRequest: par},
		Profile:                        client.ProfileFAPISecurity,
		Assurance:                      client.AssuranceDevelopment,
		AuthorizationResponseIssPolicy: client.TolerateAbsentAuthorizationResponseIss,
		Algorithms:                     algorithms,
		Limits:                         limits,
	}

	if _, err := client.New(cfg, validDependencies(t)); err != nil {
		t.Fatalf("New(RecommendedAlgorithms + RecommendedLimits): %v", err)
	}
}

// TestRecommendedLimitsBoundIDTokenLifetime: RecommendedLimits sets a
// MaxIDTokenLifetime, so a client built from it can receive ID tokens
// without another limit to set, and the value admits both
// server.RecommendedLimits' 10-minute ID tokens and the hour OpenID
// Providers commonly issue, within production's 24-hour ceiling.
func TestRecommendedLimitsBoundIDTokenLifetime(t *testing.T) {
	got := client.RecommendedLimits().MaxIDTokenLifetime
	if got < time.Hour || got > 24*time.Hour {
		t.Fatalf("RecommendedLimits().MaxIDTokenLifetime = %v, want from an hour to 24 hours", got)
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
