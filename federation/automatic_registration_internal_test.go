package federation

import (
	"encoding/json"
	"testing"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/storage"
)

const testRPJWKS = `{"keys":[{"kty":"EC","crv":"P-256","kid":"rp-1","alg":"ES256","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl4P0Sr2SFmvDMTFwbjKz8XkNhP4EQhQGE-tfWFdI"}]}`

func validRPMetadataJSON() string {
	return `{
		"redirect_uris": ["https://rp.example.org/cb"],
		"token_endpoint_auth_method": "private_key_jwt",
		"token_endpoint_auth_signing_alg": "ES256",
		"jwks": ` + testRPJWKS + `
	}`
}

func TestRegisteredClientConfigFromMetadata(t *testing.T) {
	cfg, jwks, err := registeredClientConfigFromMetadata("https://rp.example.org", json.RawMessage(validRPMetadataJSON()), AutomaticRegistrationConfig{AllowedScopes: []string{"openid"}})
	if err != nil {
		t.Fatalf("registeredClientConfigFromMetadata: %v", err)
	}
	if cfg.ID != "https://rp.example.org" {
		t.Errorf("ID = %q", cfg.ID)
	}
	if len(cfg.RedirectURIs) != 1 || cfg.RedirectURIs[0] != "https://rp.example.org/cb" {
		t.Errorf("RedirectURIs = %v", cfg.RedirectURIs)
	}
	if cfg.ClientAssertionAlgorithm != fapi.ES256 {
		t.Errorf("ClientAssertionAlgorithm = %v, want ES256", cfg.ClientAssertionAlgorithm)
	}
	if len(jwks.inline) == 0 {
		t.Errorf("jwks.inline is empty")
	}
	if jwks.uri != "" {
		t.Errorf("jwks.uri = %q, want empty", jwks.uri)
	}
	if !cfg.AutomaticFederationRegistration {
		t.Errorf("AutomaticFederationRegistration = false, want true")
	}
}

func TestRegisteredClientConfigFromMetadataAcceptsJWKSURI(t *testing.T) {
	raw := `{"redirect_uris":["https://rp.example.org/cb"],"token_endpoint_auth_method":"private_key_jwt","token_endpoint_auth_signing_alg":"ES256","jwks_uri":"https://rp.example.org/jwks.json"}`
	cfg, jwks, err := registeredClientConfigFromMetadata("https://rp.example.org", json.RawMessage(raw), AutomaticRegistrationConfig{AllowedScopes: []string{"openid"}})
	if err != nil {
		t.Fatalf("registeredClientConfigFromMetadata: %v", err)
	}
	if cfg.ID != "https://rp.example.org" {
		t.Errorf("ID = %q", cfg.ID)
	}
	if jwks.uri != "https://rp.example.org/jwks.json" {
		t.Errorf("jwks.uri = %q", jwks.uri)
	}
	if len(jwks.inline) != 0 {
		t.Errorf("jwks.inline = %q, want empty", jwks.inline)
	}
}

func TestRegisteredClientConfigFromMetadataRejectsBothJWKSAndJWKSURI(t *testing.T) {
	raw := `{"redirect_uris":["https://rp.example.org/cb"],"token_endpoint_auth_method":"private_key_jwt","token_endpoint_auth_signing_alg":"ES256","jwks_uri":"https://rp.example.org/jwks.json","jwks":` + testRPJWKS + `}`
	if _, _, err := registeredClientConfigFromMetadata("https://rp.example.org", json.RawMessage(raw), AutomaticRegistrationConfig{AllowedScopes: []string{"openid"}}); err == nil {
		t.Fatalf("registeredClientConfigFromMetadata(both jwks and jwks_uri) = nil error, want error")
	}
}

func TestRegisteredClientConfigFromMetadataRejectsMissingRedirectURIs(t *testing.T) {
	raw := `{"token_endpoint_auth_method":"private_key_jwt","token_endpoint_auth_signing_alg":"ES256","jwks":` + testRPJWKS + `}`
	if _, _, err := registeredClientConfigFromMetadata("https://rp.example.org", json.RawMessage(raw), AutomaticRegistrationConfig{AllowedScopes: []string{"openid"}}); err == nil {
		t.Fatalf("registeredClientConfigFromMetadata(no redirect_uris) = nil error, want error")
	}
}

func TestRegisteredClientConfigFromMetadataRejectsMissingJWKS(t *testing.T) {
	raw := `{"redirect_uris":["https://rp.example.org/cb"],"token_endpoint_auth_method":"private_key_jwt","token_endpoint_auth_signing_alg":"ES256"}`
	if _, _, err := registeredClientConfigFromMetadata("https://rp.example.org", json.RawMessage(raw), AutomaticRegistrationConfig{AllowedScopes: []string{"openid"}}); err == nil {
		t.Fatalf("registeredClientConfigFromMetadata(no jwks) = nil error, want error")
	}
}

func TestRegisteredClientConfigFromMetadataRejectsUnsupportedAuthMethod(t *testing.T) {
	raw := `{"redirect_uris":["https://rp.example.org/cb"],"token_endpoint_auth_method":"self_signed_tls_client_auth","jwks":` + testRPJWKS + `}`
	if _, _, err := registeredClientConfigFromMetadata("https://rp.example.org", json.RawMessage(raw), AutomaticRegistrationConfig{AllowedScopes: []string{"openid"}}); err == nil {
		t.Fatalf("registeredClientConfigFromMetadata(self_signed_tls_client_auth) = nil error, want error")
	}
}

func TestRegisteredClientConfigFromMetadataRejectsInvalidAuthMethod(t *testing.T) {
	raw := `{"redirect_uris":["https://rp.example.org/cb"],"token_endpoint_auth_method":"client_secret_basic","jwks":` + testRPJWKS + `}`
	if _, _, err := registeredClientConfigFromMetadata("https://rp.example.org", json.RawMessage(raw), AutomaticRegistrationConfig{AllowedScopes: []string{"openid"}}); err == nil {
		t.Fatalf("registeredClientConfigFromMetadata(client_secret_basic) = nil error, want error")
	}
}

func TestRegisteredClientConfigFromMetadataRejectsInvalidAssertionAlgorithm(t *testing.T) {
	raw := `{"redirect_uris":["https://rp.example.org/cb"],"token_endpoint_auth_method":"private_key_jwt","token_endpoint_auth_signing_alg":"none","jwks":` + testRPJWKS + `}`
	if _, _, err := registeredClientConfigFromMetadata("https://rp.example.org", json.RawMessage(raw), AutomaticRegistrationConfig{AllowedScopes: []string{"openid"}}); err == nil {
		t.Fatalf("registeredClientConfigFromMetadata(alg=none) = nil error, want error")
	}
}

func TestRegisteredClientConfigFromMetadataRejectsMalformedJSON(t *testing.T) {
	if _, _, err := registeredClientConfigFromMetadata("https://rp.example.org", json.RawMessage(`not json`), AutomaticRegistrationConfig{AllowedScopes: []string{"openid"}}); err == nil {
		t.Fatalf("registeredClientConfigFromMetadata(malformed json) = nil error, want error")
	}
}

func TestRegisteredClientConfigFromMetadataAcceptsRequestObjectSigningAlg(t *testing.T) {
	raw := `{
		"redirect_uris": ["https://rp.example.org/cb"],
		"token_endpoint_auth_method": "private_key_jwt",
		"token_endpoint_auth_signing_alg": "ES256",
		"request_object_signing_alg": "ES256",
		"jwks": ` + testRPJWKS + `
	}`
	cfg, _, err := registeredClientConfigFromMetadata("https://rp.example.org", json.RawMessage(raw), AutomaticRegistrationConfig{AllowedScopes: []string{"openid"}})
	if err != nil {
		t.Fatalf("registeredClientConfigFromMetadata: %v", err)
	}
	if alg, permitted := cfg.RequestObjectAlgorithm, cfg.RequestObjectAlgorithm != 0; !permitted || alg != fapi.ES256 {
		t.Errorf("RequestObjectAlgorithm = %v, permitted = %v, want ES256/true", alg, permitted)
	}
}

func TestRegisteredClientConfigFromMetadataRejectsInvalidRequestObjectSigningAlg(t *testing.T) {
	raw := `{
		"redirect_uris": ["https://rp.example.org/cb"],
		"token_endpoint_auth_method": "private_key_jwt",
		"token_endpoint_auth_signing_alg": "ES256",
		"request_object_signing_alg": "bogus",
		"jwks": ` + testRPJWKS + `
	}`
	if _, _, err := registeredClientConfigFromMetadata("https://rp.example.org", json.RawMessage(raw), AutomaticRegistrationConfig{AllowedScopes: []string{"openid"}}); err == nil {
		t.Fatalf("registeredClientConfigFromMetadata(bad request_object_signing_alg) = nil error, want error")
	}
}

func TestRegisteredClientConfigFromMetadataMapsMTLSSenderConstrain(t *testing.T) {
	raw := `{
		"redirect_uris": ["https://rp.example.org/cb"],
		"token_endpoint_auth_method": "private_key_jwt",
		"token_endpoint_auth_signing_alg": "ES256",
		"tls_client_certificate_bound_access_tokens": true,
		"jwks": ` + testRPJWKS + `
	}`
	cfg, _, err := registeredClientConfigFromMetadata("https://rp.example.org", json.RawMessage(raw), AutomaticRegistrationConfig{AllowedScopes: []string{"openid"}})
	if err != nil {
		t.Fatalf("registeredClientConfigFromMetadata: %v", err)
	}
	if cfg.SenderConstrain != storage.SenderConstrainMTLS {
		t.Errorf("SenderConstrain = %v, want mtls", cfg.SenderConstrain)
	}
}

func TestRegisteredClientConfigFromMetadataDoesNotGrantClientCredentialsByDefault(t *testing.T) {
	cfg, _, err := registeredClientConfigFromMetadata("https://rp.example.org", json.RawMessage(validRPMetadataJSON()), AutomaticRegistrationConfig{AllowedScopes: []string{"openid"}})
	if err != nil {
		t.Fatalf("registeredClientConfigFromMetadata: %v", err)
	}
	if cfg.AllowsClientCredentialsGrant {
		t.Errorf("AllowsClientCredentialsGrant = true, want false (AutomaticRegistrationConfig.AllowsClientCredentialsGrant not set)")
	}
}

func TestRegisteredClientConfigFromMetadataGrantsClientCredentialsWhenConfigured(t *testing.T) {
	cfg, _, err := registeredClientConfigFromMetadata("https://rp.example.org", json.RawMessage(validRPMetadataJSON()), AutomaticRegistrationConfig{
		AllowedScopes: []string{"openid"}, AllowsClientCredentialsGrant: true,
	})
	if err != nil {
		t.Fatalf("registeredClientConfigFromMetadata: %v", err)
	}
	if !cfg.AllowsClientCredentialsGrant {
		t.Errorf("AllowsClientCredentialsGrant = false, want true (AutomaticRegistrationConfig.AllowsClientCredentialsGrant is set)")
	}
}

// An RP publishing backchannel_authentication_request_signing_alg in its
// own metadata must NOT grant it CIBA when AllowsCIBA is not set — the
// whole point of AllowsCIBA being a config-level switch (mirroring
// AllowedScopes) is that self-published metadata alone can never grant
// this capability.
func TestRegisteredClientConfigFromMetadataIgnoresCIBAMetadataWhenNotAllowed(t *testing.T) {
	raw := `{
		"redirect_uris": ["https://rp.example.org/cb"],
		"token_endpoint_auth_method": "private_key_jwt",
		"token_endpoint_auth_signing_alg": "ES256",
		"backchannel_authentication_request_signing_alg": "ES256",
		"jwks": ` + testRPJWKS + `
	}`
	cfg, _, err := registeredClientConfigFromMetadata("https://rp.example.org", json.RawMessage(raw), AutomaticRegistrationConfig{AllowedScopes: []string{"openid"}})
	if err != nil {
		t.Fatalf("registeredClientConfigFromMetadata: %v", err)
	}
	if cfg.BackchannelAuthenticationRequestAlgorithm != 0 {
		t.Errorf("BackchannelAuthenticationRequestAlgorithm = %v, want unset (AllowsCIBA not set)", cfg.BackchannelAuthenticationRequestAlgorithm)
	}
}

func TestRegisteredClientConfigFromMetadataMapsCIBAMetadataWhenAllowed(t *testing.T) {
	raw := `{
		"redirect_uris": ["https://rp.example.org/cb"],
		"token_endpoint_auth_method": "private_key_jwt",
		"token_endpoint_auth_signing_alg": "ES256",
		"backchannel_authentication_request_signing_alg": "ES256",
		"backchannel_token_delivery_mode": "ping",
		"backchannel_client_notification_endpoint": "https://rp.example.org/notify",
		"jwks": ` + testRPJWKS + `
	}`
	cfg, _, err := registeredClientConfigFromMetadata("https://rp.example.org", json.RawMessage(raw), AutomaticRegistrationConfig{
		AllowedScopes: []string{"openid"}, AllowsCIBA: true,
	})
	if err != nil {
		t.Fatalf("registeredClientConfigFromMetadata: %v", err)
	}
	if cfg.BackchannelAuthenticationRequestAlgorithm != fapi.ES256 {
		t.Errorf("BackchannelAuthenticationRequestAlgorithm = %v, want ES256", cfg.BackchannelAuthenticationRequestAlgorithm)
	}
	if cfg.BackchannelTokenDeliveryMode != storage.BackchannelTokenDeliveryModePing {
		t.Errorf("BackchannelTokenDeliveryMode = %v, want ping", cfg.BackchannelTokenDeliveryMode)
	}
	if cfg.BackchannelClientNotificationEndpoint.String() != "https://rp.example.org/notify" {
		t.Errorf("BackchannelClientNotificationEndpoint = %q, want https://rp.example.org/notify", cfg.BackchannelClientNotificationEndpoint.String())
	}
}

func TestRegisteredClientConfigFromMetadataDefaultsCIBADeliveryModeToPoll(t *testing.T) {
	raw := `{
		"redirect_uris": ["https://rp.example.org/cb"],
		"token_endpoint_auth_method": "private_key_jwt",
		"token_endpoint_auth_signing_alg": "ES256",
		"backchannel_authentication_request_signing_alg": "ES256",
		"jwks": ` + testRPJWKS + `
	}`
	cfg, _, err := registeredClientConfigFromMetadata("https://rp.example.org", json.RawMessage(raw), AutomaticRegistrationConfig{
		AllowedScopes: []string{"openid"}, AllowsCIBA: true,
	})
	if err != nil {
		t.Fatalf("registeredClientConfigFromMetadata: %v", err)
	}
	if cfg.BackchannelTokenDeliveryMode != storage.BackchannelTokenDeliveryModePoll {
		t.Errorf("BackchannelTokenDeliveryMode = %v, want poll (default)", cfg.BackchannelTokenDeliveryMode)
	}
}

func TestRegisteredClientConfigFromMetadataRejectsInvalidCIBASigningAlg(t *testing.T) {
	raw := `{
		"redirect_uris": ["https://rp.example.org/cb"],
		"token_endpoint_auth_method": "private_key_jwt",
		"token_endpoint_auth_signing_alg": "ES256",
		"backchannel_authentication_request_signing_alg": "bogus",
		"jwks": ` + testRPJWKS + `
	}`
	if _, _, err := registeredClientConfigFromMetadata("https://rp.example.org", json.RawMessage(raw), AutomaticRegistrationConfig{
		AllowedScopes: []string{"openid"}, AllowsCIBA: true,
	}); err == nil {
		t.Fatalf("registeredClientConfigFromMetadata(bogus backchannel_authentication_request_signing_alg) = nil error, want error")
	}
}

func TestRegisteredClientConfigFromMetadataRejectsInvalidCIBADeliveryMode(t *testing.T) {
	raw := `{
		"redirect_uris": ["https://rp.example.org/cb"],
		"token_endpoint_auth_method": "private_key_jwt",
		"token_endpoint_auth_signing_alg": "ES256",
		"backchannel_authentication_request_signing_alg": "ES256",
		"backchannel_token_delivery_mode": "push",
		"jwks": ` + testRPJWKS + `
	}`
	if _, _, err := registeredClientConfigFromMetadata("https://rp.example.org", json.RawMessage(raw), AutomaticRegistrationConfig{
		AllowedScopes: []string{"openid"}, AllowsCIBA: true,
	}); err == nil {
		t.Fatalf("registeredClientConfigFromMetadata(backchannel_token_delivery_mode=push) = nil error, want error")
	}
}

func TestRegisteredClientConfigFromMetadataRejectsInvalidCIBANotificationEndpoint(t *testing.T) {
	raw := `{
		"redirect_uris": ["https://rp.example.org/cb"],
		"token_endpoint_auth_method": "private_key_jwt",
		"token_endpoint_auth_signing_alg": "ES256",
		"backchannel_authentication_request_signing_alg": "ES256",
		"backchannel_token_delivery_mode": "ping",
		"backchannel_client_notification_endpoint": "not a url",
		"jwks": ` + testRPJWKS + `
	}`
	if _, _, err := registeredClientConfigFromMetadata("https://rp.example.org", json.RawMessage(raw), AutomaticRegistrationConfig{
		AllowedScopes: []string{"openid"}, AllowsCIBA: true,
	}); err == nil {
		t.Fatalf("registeredClientConfigFromMetadata(malformed backchannel_client_notification_endpoint) = nil error, want error")
	}
}

func TestRegisteredClientConfigFromMetadataMapsIDTokenEncryption(t *testing.T) {
	raw := `{
		"redirect_uris": ["https://rp.example.org/cb"],
		"token_endpoint_auth_method": "private_key_jwt",
		"token_endpoint_auth_signing_alg": "ES256",
		"id_token_encrypted_response_alg": "ECDH-ES+A256KW",
		"id_token_encrypted_response_enc": "A256GCM",
		"jwks": ` + testRPJWKS + `
	}`
	cfg, _, err := registeredClientConfigFromMetadata("https://rp.example.org", json.RawMessage(raw), AutomaticRegistrationConfig{AllowedScopes: []string{"openid"}})
	if err != nil {
		t.Fatalf("registeredClientConfigFromMetadata: %v", err)
	}
	km, ce, enabled := cfg.IDTokenEncryptionKeyManagement, cfg.IDTokenEncryptionContentEncryption, cfg.IDTokenEncryptionKeyManagement != 0
	if !enabled || km == 0 || ce == 0 {
		t.Errorf("IDTokenEncryption = %v/%v/%v, want a non-zero pair", km, ce, enabled)
	}
}

func TestRegisteredClientConfigFromMetadataRejectsUnpairedIDTokenEncryption(t *testing.T) {
	raw := `{
		"redirect_uris": ["https://rp.example.org/cb"],
		"token_endpoint_auth_method": "private_key_jwt",
		"token_endpoint_auth_signing_alg": "ES256",
		"id_token_encrypted_response_alg": "ECDH-ES+A256KW",
		"jwks": ` + testRPJWKS + `
	}`
	if _, _, err := registeredClientConfigFromMetadata("https://rp.example.org", json.RawMessage(raw), AutomaticRegistrationConfig{AllowedScopes: []string{"openid"}}); err == nil {
		t.Fatalf("registeredClientConfigFromMetadata(id_token enc alg without enc) = nil error, want error")
	}
}

func TestRegisteredClientConfigFromMetadataRejectsInvalidIDTokenEncryptionKeyManagement(t *testing.T) {
	raw := `{
		"redirect_uris": ["https://rp.example.org/cb"],
		"token_endpoint_auth_method": "private_key_jwt",
		"token_endpoint_auth_signing_alg": "ES256",
		"id_token_encrypted_response_alg": "bogus",
		"id_token_encrypted_response_enc": "A256GCM",
		"jwks": ` + testRPJWKS + `
	}`
	if _, _, err := registeredClientConfigFromMetadata("https://rp.example.org", json.RawMessage(raw), AutomaticRegistrationConfig{AllowedScopes: []string{"openid"}}); err == nil {
		t.Fatalf("registeredClientConfigFromMetadata(bogus id_token_encrypted_response_alg) = nil error, want error")
	}
}

func TestRegisteredClientConfigFromMetadataRejectsInvalidIDTokenEncryptionContentEncryption(t *testing.T) {
	raw := `{
		"redirect_uris": ["https://rp.example.org/cb"],
		"token_endpoint_auth_method": "private_key_jwt",
		"token_endpoint_auth_signing_alg": "ES256",
		"id_token_encrypted_response_alg": "ECDH-ES+A256KW",
		"id_token_encrypted_response_enc": "bogus",
		"jwks": ` + testRPJWKS + `
	}`
	if _, _, err := registeredClientConfigFromMetadata("https://rp.example.org", json.RawMessage(raw), AutomaticRegistrationConfig{AllowedScopes: []string{"openid"}}); err == nil {
		t.Fatalf("registeredClientConfigFromMetadata(bogus id_token_encrypted_response_enc) = nil error, want error")
	}
}

func TestRegisteredClientConfigFromMetadataMapsUserInfoEncryption(t *testing.T) {
	raw := `{
		"redirect_uris": ["https://rp.example.org/cb"],
		"token_endpoint_auth_method": "private_key_jwt",
		"token_endpoint_auth_signing_alg": "ES256",
		"userinfo_encrypted_response_alg": "ECDH-ES+A256KW",
		"userinfo_encrypted_response_enc": "A256GCM",
		"jwks": ` + testRPJWKS + `
	}`
	cfg, _, err := registeredClientConfigFromMetadata("https://rp.example.org", json.RawMessage(raw), AutomaticRegistrationConfig{AllowedScopes: []string{"openid"}})
	if err != nil {
		t.Fatalf("registeredClientConfigFromMetadata: %v", err)
	}
	km, ce, enabled := cfg.UserInfoEncryptionKeyManagement, cfg.UserInfoEncryptionContentEncryption, cfg.UserInfoEncryptionKeyManagement != 0
	if !enabled || km == 0 || ce == 0 {
		t.Errorf("UserInfoEncryption = %v/%v/%v, want a non-zero pair", km, ce, enabled)
	}
}

func TestRegisteredClientConfigFromMetadataRejectsInvalidUserInfoEncryptionKeyManagement(t *testing.T) {
	raw := `{
		"redirect_uris": ["https://rp.example.org/cb"],
		"token_endpoint_auth_method": "private_key_jwt",
		"token_endpoint_auth_signing_alg": "ES256",
		"userinfo_encrypted_response_alg": "bogus",
		"userinfo_encrypted_response_enc": "A256GCM",
		"jwks": ` + testRPJWKS + `
	}`
	if _, _, err := registeredClientConfigFromMetadata("https://rp.example.org", json.RawMessage(raw), AutomaticRegistrationConfig{AllowedScopes: []string{"openid"}}); err == nil {
		t.Fatalf("registeredClientConfigFromMetadata(bogus userinfo_encrypted_response_alg) = nil error, want error")
	}
}

func TestRegisteredClientConfigFromMetadataRejectsInvalidUserInfoEncryptionContentEncryption(t *testing.T) {
	raw := `{
		"redirect_uris": ["https://rp.example.org/cb"],
		"token_endpoint_auth_method": "private_key_jwt",
		"token_endpoint_auth_signing_alg": "ES256",
		"userinfo_encrypted_response_alg": "ECDH-ES+A256KW",
		"userinfo_encrypted_response_enc": "bogus",
		"jwks": ` + testRPJWKS + `
	}`
	if _, _, err := registeredClientConfigFromMetadata("https://rp.example.org", json.RawMessage(raw), AutomaticRegistrationConfig{AllowedScopes: []string{"openid"}}); err == nil {
		t.Fatalf("registeredClientConfigFromMetadata(bogus userinfo_encrypted_response_enc) = nil error, want error")
	}
}

func TestRegisteredClientConfigFromMetadataRejectsUnpairedUserInfoEncryption(t *testing.T) {
	raw := `{
		"redirect_uris": ["https://rp.example.org/cb"],
		"token_endpoint_auth_method": "private_key_jwt",
		"token_endpoint_auth_signing_alg": "ES256",
		"userinfo_encrypted_response_enc": "A256GCM",
		"jwks": ` + testRPJWKS + `
	}`
	if _, _, err := registeredClientConfigFromMetadata("https://rp.example.org", json.RawMessage(raw), AutomaticRegistrationConfig{AllowedScopes: []string{"openid"}}); err == nil {
		t.Fatalf("registeredClientConfigFromMetadata(userinfo enc without alg) = nil error, want error")
	}
}
