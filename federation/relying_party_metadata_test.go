package federation_test

import (
	"encoding/json"
	"testing"

	"github.com/idfoundry/fapigo/federation"
)

func TestOpenIDRelyingPartyMetadataJSONTags(t *testing.T) {
	meta := federation.OpenIDRelyingPartyMetadata{
		ClientRegistrationTypes:     []string{"automatic"},
		RedirectURIs:                []string{"https://rp.example.org/callback"},
		ResponseTypes:               []string{"code"},
		GrantTypes:                  []string{"authorization_code"},
		ApplicationType:             "web",
		TokenEndpointAuthMethod:     "private_key_jwt",
		TokenEndpointAuthSigningAlg: "ES256",
		JWKS:                        json.RawMessage(`{"keys":[]}`),
		SignedJWKSURI:               "https://rp.example.org/signed_jwks.jose",
		IDTokenSignedResponseAlg:    "ES256",
		RequestObjectSigningAlg:     "ES256",
		OrganizationName:            "Example Org",
		ClientName:                  "Example RP",
		LogoURI:                     "https://rp.example.org/logo.png",
		Contacts:                    []string{"admin@example.org"},
	}

	raw, err := json.Marshal(meta)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}

	wantKeys := []string{
		"client_registration_types", "redirect_uris", "response_types", "grant_types",
		"application_type", "token_endpoint_auth_method", "token_endpoint_auth_signing_alg",
		"jwks", "signed_jwks_uri", "id_token_signed_response_alg", "request_object_signing_alg",
		"organization_name", "client_name", "logo_uri", "contacts",
	}
	for _, k := range wantKeys {
		if _, ok := got[k]; !ok {
			t.Errorf("marshaled JSON missing key %q", k)
		}
	}
	if len(got) != len(wantKeys) {
		t.Errorf("marshaled JSON has %d keys, want %d (extra or missing fields): %v", len(got), len(wantKeys), got)
	}
}

func TestOpenIDRelyingPartyMetadataOmitsEmptyFields(t *testing.T) {
	raw, err := json.Marshal(federation.OpenIDRelyingPartyMetadata{
		ClientRegistrationTypes: []string{"automatic"},
	})
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if len(got) != 1 {
		t.Errorf("marshaled JSON = %v, want exactly one key (client_registration_types)", got)
	}
}

func TestOpenIDRelyingPartyMetadataJWKSAndJWKSURIRoundTrip(t *testing.T) {
	meta := federation.OpenIDRelyingPartyMetadata{JWKSURI: "https://rp.example.org/jwks.json"}
	raw, err := json.Marshal(meta)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if _, ok := got["jwks"]; ok {
		t.Error("jwks present when only JWKSURI was set")
	}
	if got["jwks_uri"] != "https://rp.example.org/jwks.json" {
		t.Errorf("jwks_uri = %v, want the set URI", got["jwks_uri"])
	}
}
