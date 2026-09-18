package metadata

import (
	"encoding/json"
	"testing"
)

// FuzzParseAndValidate exercises ParseAndValidate against arbitrary
// bytes — an authorization-server metadata document is fetched from a
// remote issuer's own discovery endpoint, parsed before any of its
// values are trusted. Unlike a protocol message elsewhere in this
// module, Document's own doc comment notes RFC 8414 §2 explicitly
// allows additional metadata values, so encoding/json's default
// tolerance of unrecognized fields is deliberate here, not an
// oversight — this target exercises that alongside the nested
// MTLSEndpointAliases object and the required-field/issuer-match
// checks. expectedIssuer is fixed to match the seed documents' own
// "issuer" value, so the fuzzer's mutations land on body. Only checks
// for panics/hangs.
func FuzzParseAndValidate(f *testing.F) {
	const issuer = "https://as.example"

	full, err := json.Marshal(Document{
		Issuer: issuer, AuthorizationEndpoint: issuer + "/authorize",
		TokenEndpoint: issuer + "/token", PushedAuthorizationRequestEndpoint: issuer + "/par",
		JWKSURI: issuer + "/jwks", UserinfoEndpoint: issuer + "/userinfo",
		BackchannelAuthenticationEndpoint:  issuer + "/bc-authorize",
		ResponseTypesSupported:             []string{"code"},
		GrantTypesSupported:                []string{"authorization_code"},
		TokenEndpointAuthMethodsSupported:  []string{"private_key_jwt"},
		RequirePushedAuthorizationRequests: true,
		MTLSEndpointAliases: &MTLSEndpointAliases{
			TokenEndpoint: issuer + "/mtls/token",
		},
	})
	if err != nil {
		f.Fatalf("marshal full document: %v", err)
	}

	minimal, err := json.Marshal(Document{Issuer: issuer, TokenEndpoint: issuer + "/token", JWKSURI: issuer + "/jwks"})
	if err != nil {
		f.Fatalf("marshal minimal document: %v", err)
	}

	f.Add(full)
	f.Add(minimal)
	f.Add([]byte(`{"issuer":"https://wrong.example","token_endpoint":"x","jwks_uri":"x"}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`not json`))
	f.Add([]byte(`{"issuer":"https://as.example","token_endpoint":"x","jwks_uri":"x","unknown_field":"ignored"}`))

	f.Fuzz(func(t *testing.T, body []byte) {
		_, _ = ParseAndValidate(body, issuer)
	})
}
