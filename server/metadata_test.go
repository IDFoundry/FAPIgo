package server_test

import (
	"context"
	"testing"

	"github.com/idfoundry/fapigo/server"
)

func containsString(list []string, target string) bool {
	for _, s := range list {
		if s == target {
			return true
		}
	}
	return false
}

func TestMetadataSecurityProfile(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	md := h.server.Metadata(context.Background())

	if md.Issuer.String() != testIssuer {
		t.Fatalf("Issuer = %q, want %q", md.Issuer.String(), testIssuer)
	}
	if md.AuthorizationEndpoint.String() != testAuthorizationEndpoint {
		t.Fatalf("AuthorizationEndpoint = %q, want %q", md.AuthorizationEndpoint.String(), testAuthorizationEndpoint)
	}
	if md.TokenEndpoint.String() != testTokenEndpoint {
		t.Fatalf("TokenEndpoint = %q, want %q", md.TokenEndpoint.String(), testTokenEndpoint)
	}
	if md.PushedAuthorizationRequestEndpoint.String() != testPAREndpoint {
		t.Fatalf("PushedAuthorizationRequestEndpoint = %q, want %q", md.PushedAuthorizationRequestEndpoint.String(), testPAREndpoint)
	}
	if md.JWKSURI.String() != testJWKSEndpoint {
		t.Fatalf("JWKSURI = %q, want %q", md.JWKSURI.String(), testJWKSEndpoint)
	}

	if !containsString(md.ResponseTypesSupported, "code") || len(md.ResponseTypesSupported) != 1 {
		t.Fatalf("ResponseTypesSupported = %v, want [code]", md.ResponseTypesSupported)
	}
	if !containsString(md.GrantTypesSupported, "authorization_code") || !containsString(md.GrantTypesSupported, "refresh_token") {
		t.Fatalf("GrantTypesSupported = %v, want to contain authorization_code and refresh_token", md.GrantTypesSupported)
	}
	if !containsString(md.CodeChallengeMethodsSupported, "S256") {
		t.Fatalf("CodeChallengeMethodsSupported = %v, want to contain S256", md.CodeChallengeMethodsSupported)
	}
	if !containsString(md.TokenEndpointAuthMethodsSupported, "private_key_jwt") {
		t.Fatalf("TokenEndpointAuthMethodsSupported = %v, want to contain private_key_jwt", md.TokenEndpointAuthMethodsSupported)
	}
	if !containsString(md.TokenEndpointAuthSigningAlgValuesSupported, "ES256") {
		t.Fatalf("TokenEndpointAuthSigningAlgValuesSupported = %v, want to contain ES256", md.TokenEndpointAuthSigningAlgValuesSupported)
	}
	if !containsString(md.RequestObjectSigningAlgValuesSupported, "ES256") {
		t.Fatalf("RequestObjectSigningAlgValuesSupported = %v, want to contain ES256", md.RequestObjectSigningAlgValuesSupported)
	}
	if !containsString(md.IDTokenSigningAlgValuesSupported, "ES256") {
		t.Fatalf("IDTokenSigningAlgValuesSupported = %v, want to contain ES256", md.IDTokenSigningAlgValuesSupported)
	}
	if !containsString(md.SubjectTypesSupported, "public") {
		t.Fatalf("SubjectTypesSupported = %v, want to contain public", md.SubjectTypesSupported)
	}
	if !md.RequirePushedAuthorizationRequests {
		t.Fatalf("RequirePushedAuthorizationRequests = false, want true")
	}
	if !md.AuthorizationResponseIssParameterSupported {
		t.Fatalf("AuthorizationResponseIssParameterSupported = false, want true")
	}

	// FAPISecurity does not require signed request objects, and does
	// not sign authorization responses.
	if md.RequireSignedRequestObject {
		t.Fatalf("RequireSignedRequestObject = true, want false under ProfileFAPISecurity")
	}
	if len(md.AuthorizationSigningAlgValuesSupported) != 0 {
		t.Fatalf("AuthorizationSigningAlgValuesSupported = %v, want empty under ProfileFAPISecurity", md.AuthorizationSigningAlgValuesSupported)
	}
	if !containsString(md.ResponseModesSupported, "query") {
		t.Fatalf("ResponseModesSupported = %v, want to contain query", md.ResponseModesSupported)
	}
}

func TestMetadataMessageSigningProfile(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurityWithMessageSigning, true)
	md := h.server.Metadata(context.Background())

	if !md.RequireSignedRequestObject {
		t.Fatalf("RequireSignedRequestObject = false, want true under ProfileFAPISecurityWithMessageSigning")
	}
	if !containsString(md.AuthorizationSigningAlgValuesSupported, "ES256") {
		t.Fatalf("AuthorizationSigningAlgValuesSupported = %v, want to contain ES256", md.AuthorizationSigningAlgValuesSupported)
	}
	if !containsString(md.ResponseModesSupported, "jwt") {
		t.Fatalf("ResponseModesSupported = %v, want to contain jwt", md.ResponseModesSupported)
	}
}
