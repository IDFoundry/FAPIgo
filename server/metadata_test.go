package server_test

import (
	"context"
	"encoding/json"
	"testing"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
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

// TestMetadataOmitsUserInfoAlgorithmsWhenNotConfigured confirms a server
// that never enabled UserInfo signing/encryption (the default, and the
// common case) doesn't advertise any of the three fields — OIDC
// Discovery 1.0 §3 leaves them all optional/absent in that case.
func TestMetadataOmitsUserInfoAlgorithmsWhenNotConfigured(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	md := h.server.Metadata(context.Background())

	if len(md.UserinfoSigningAlgValuesSupported) != 0 {
		t.Fatalf("UserinfoSigningAlgValuesSupported = %v, want empty", md.UserinfoSigningAlgValuesSupported)
	}
	if len(md.UserinfoEncryptionAlgValuesSupported) != 0 {
		t.Fatalf("UserinfoEncryptionAlgValuesSupported = %v, want empty", md.UserinfoEncryptionAlgValuesSupported)
	}
	if len(md.UserinfoEncryptionEncValuesSupported) != 0 {
		t.Fatalf("UserinfoEncryptionEncValuesSupported = %v, want empty", md.UserinfoEncryptionEncValuesSupported)
	}
}

// TestMetadataAdvertisesUserInfoAlgorithmsWhenConfigured confirms the
// server-wide Config.Algorithms.UserInfo* values are what's advertised —
// the same conditional-field shape already used for ID token encryption.
func TestMetadataAdvertisesUserInfoAlgorithmsWhenConfigured(t *testing.T) {
	cfg := validConfig(t)
	cfg.Algorithms.UserInfo = fapi.ES256
	cfg.Algorithms.UserInfoEncryptionKeyManagement = server.KeyManagementAlgorithmSet{fapi.RSAOAEP256, fapi.ECDHESA256KW}
	cfg.Algorithms.UserInfoEncryptionContentEncryption = server.ContentEncryptionAlgorithmSet{fapi.A256GCM}
	deps := validDependencies()
	deps.ClientEncryptionKeys = fakeClientEncryptionKeySource{}

	srv, err := server.New(cfg, deps)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	md := srv.Metadata(context.Background())

	if !containsString(md.UserinfoSigningAlgValuesSupported, "ES256") || len(md.UserinfoSigningAlgValuesSupported) != 1 {
		t.Fatalf("UserinfoSigningAlgValuesSupported = %v, want [ES256]", md.UserinfoSigningAlgValuesSupported)
	}
	if !containsString(md.UserinfoEncryptionAlgValuesSupported, "RSA-OAEP-256") || !containsString(md.UserinfoEncryptionAlgValuesSupported, "ECDH-ES+A256KW") {
		t.Fatalf("UserinfoEncryptionAlgValuesSupported = %v, want to contain RSA-OAEP-256 and ECDH-ES+A256KW", md.UserinfoEncryptionAlgValuesSupported)
	}
	if !containsString(md.UserinfoEncryptionEncValuesSupported, "A256GCM") {
		t.Fatalf("UserinfoEncryptionEncValuesSupported = %v, want to contain A256GCM", md.UserinfoEncryptionEncValuesSupported)
	}
}

// TestMetadataMarshalJSONUsesDiscoveryFieldNames confirms server.Metadata
// is directly JSON-marshalable using RFC 8414/OIDC Discovery's own
// snake_case field names, guarding against a renamed/added field silently
// losing its wire name (the risk the old cmd/conformance-as manual-copy
// approach had no protection against at all).
func TestMetadataMarshalJSONUsesDiscoveryFieldNames(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurityWithMessageSigning, true)
	md := h.server.Metadata(context.Background())

	b, err := json.Marshal(md)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	for _, key := range []string{
		"issuer",
		"authorization_endpoint",
		"token_endpoint",
		"pushed_authorization_request_endpoint",
		"jwks_uri",
		"response_types_supported",
		"response_modes_supported",
		"grant_types_supported",
		"subject_types_supported",
		"code_challenge_methods_supported",
		"token_endpoint_auth_methods_supported",
		"token_endpoint_auth_signing_alg_values_supported",
		"request_object_signing_alg_values_supported",
		"id_token_signing_alg_values_supported",
		"authorization_signing_alg_values_supported",
		"require_pushed_authorization_requests",
		"require_signed_request_object",
		"authorization_response_iss_parameter_supported",
	} {
		if _, ok := decoded[key]; !ok {
			t.Fatalf("Marshal(md) missing key %q, got %s", key, b)
		}
	}

	if got, want := decoded["issuer"], testIssuer; got != want {
		t.Fatalf("issuer = %v, want %q", got, want)
	}

	// Fields left unset by this profile (no ID token encryption
	// configured) must be entirely absent, not present as null/empty.
	for _, key := range []string{
		"id_token_encryption_alg_values_supported",
		"id_token_encryption_enc_values_supported",
	} {
		if _, ok := decoded[key]; ok {
			t.Fatalf("Marshal(md) unexpectedly contains key %q, got %s", key, b)
		}
	}
}

func TestMetadataOmitsClientCredentialsGrantWhenDisabled(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true) // ClientCredentialsGrant left false
	md := h.server.Metadata(context.Background())

	if containsString(md.GrantTypesSupported, "client_credentials") {
		t.Fatalf("GrantTypesSupported = %v, want it to omit client_credentials", md.GrantTypesSupported)
	}
}

func TestMetadataIncludesClientCredentialsGrantWhenEnabled(t *testing.T) {
	h := newHarnessWithClientCredentialsGrant(t, storage.SenderConstrainDPoP, true)
	md := h.server.Metadata(context.Background())

	if !containsString(md.GrantTypesSupported, "client_credentials") {
		t.Fatalf("GrantTypesSupported = %v, want it to contain client_credentials", md.GrantTypesSupported)
	}
	// Every other grant type stays advertised alongside it, not replaced.
	if !containsString(md.GrantTypesSupported, "authorization_code") || !containsString(md.GrantTypesSupported, "refresh_token") {
		t.Fatalf("GrantTypesSupported = %v, want to still contain authorization_code and refresh_token", md.GrantTypesSupported)
	}
}
