package server_test

import (
	"context"
	"testing"

	fapi "github.com/idfoundry/fapigo"
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

// TestMetadataOmitsIDTokenEncryptionWhenNotConfigured confirms a server
// that never enabled encrypted ID tokens (the default, and the common
// case) doesn't advertise either *_values_supported field — OIDC
// Discovery 1.0 §3 leaves both optional/absent in that case.
func TestMetadataOmitsIDTokenEncryptionWhenNotConfigured(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	md := h.server.Metadata(context.Background())

	if len(md.IDTokenEncryptionAlgValuesSupported) != 0 {
		t.Fatalf("IDTokenEncryptionAlgValuesSupported = %v, want empty", md.IDTokenEncryptionAlgValuesSupported)
	}
	if len(md.IDTokenEncryptionEncValuesSupported) != 0 {
		t.Fatalf("IDTokenEncryptionEncValuesSupported = %v, want empty", md.IDTokenEncryptionEncValuesSupported)
	}
}

// TestMetadataAdvertisesIDTokenEncryptionWhenConfigured confirms the
// server-wide allow-lists in Config.Algorithms are what's advertised —
// not any per-client RegisteredClient setting, which is a separate,
// narrower concern (see storage.RegisteredClient.IDTokenEncryption).
func TestMetadataAdvertisesIDTokenEncryptionWhenConfigured(t *testing.T) {
	cfg := validConfig(t)
	cfg.Algorithms.IDTokenEncryptionKeyManagement = server.KeyManagementAlgorithmSet{fapi.RSAOAEP256, fapi.ECDHESA256KW}
	cfg.Algorithms.IDTokenEncryptionContentEncryption = server.ContentEncryptionAlgorithmSet{fapi.A256GCM}
	deps := validDependencies()
	deps.ClientEncryptionKeys = fakeClientEncryptionKeySource{}

	srv, err := server.New(cfg, deps)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	md := srv.Metadata(context.Background())

	if !containsString(md.IDTokenEncryptionAlgValuesSupported, "RSA-OAEP-256") || !containsString(md.IDTokenEncryptionAlgValuesSupported, "ECDH-ES+A256KW") {
		t.Fatalf("IDTokenEncryptionAlgValuesSupported = %v, want to contain RSA-OAEP-256 and ECDH-ES+A256KW", md.IDTokenEncryptionAlgValuesSupported)
	}
	if !containsString(md.IDTokenEncryptionEncValuesSupported, "A256GCM") {
		t.Fatalf("IDTokenEncryptionEncValuesSupported = %v, want to contain A256GCM", md.IDTokenEncryptionEncValuesSupported)
	}
}
