package federation_test

import (
	"context"
	"slices"
	"strings"
	"testing"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/federation"
	"github.com/idfoundry/fapigo/storage"
)

// resolveUnderPolicy registers the fixture RP publishing members (plus
// its jwks) under policy, a Trust Anchor's openid_relying_party
// metadata_policy, with ES256 and PS256 as the OP's default assertion
// algorithms.
func resolveUnderPolicy(t *testing.T, policy string, members map[string]any) (storage.RegisteredClient, error) {
	t.Helper()
	f := setupAutomaticRegistrationFixtureWithPolicy(t, rpMetadataMembers(t, members),
		mustPolicy(t, `{"openid_relying_party":`+policy+`}`))
	cfg := validAutomaticRegistrationConfig()
	cfg.ClientAssertionAlgorithms = []fapi.SignatureAlgorithm{fapi.ES256, fapi.PS256}
	repo, err := federation.NewAutomaticClientRepository(alwaysFailsRepository{}, f.newResolver(t), f.fetcher, cfg, fixedClock{now: f.now})
	if err != nil {
		t.Fatalf("NewAutomaticClientRepository: %v", err)
	}
	return repo.ResolveClient(context.Background(), fapi.ClientID(f.rpID))
}

// TestAutomaticRegistrationHoldsAlgorithmChoicesToPolicy: a superior's
// one_of (or value) on token_endpoint_auth_signing_alg bounds the
// algorithms the RP registers however it declares them — with the
// singular parameter, its RP Metadata Choices plural sibling, or neither
// (the OP's defaults) — since the policy itself checks only the singular
// parameter, and only when it is present.
func TestAutomaticRegistrationHoldsAlgorithmChoicesToPolicy(t *testing.T) {
	base := map[string]any{"redirect_uris": []string{"https://rp.example.org/cb"}, "token_endpoint_auth_method": "private_key_jwt"}
	with := func(extra map[string]any) map[string]any {
		m := map[string]any{}
		for k, v := range base {
			m[k] = v
		}
		for k, v := range extra {
			m[k] = v
		}
		return m
	}
	oneOfPS256 := `{"token_endpoint_auth_signing_alg":{"one_of":["PS256"]}}`
	for _, tc := range []struct {
		name    string
		policy  string
		members map[string]any
		want    []fapi.SignatureAlgorithm // nil: refused
	}{
		{"plural outside one_of", oneOfPS256, with(map[string]any{"token_endpoint_auth_signing_alg_values_supported": []string{"ES256"}}), nil},
		{"plural narrowed to one_of", oneOfPS256, with(map[string]any{"token_endpoint_auth_signing_alg_values_supported": []string{"ES256", "PS256"}}), []fapi.SignatureAlgorithm{fapi.PS256}},
		{"defaults narrowed to one_of", oneOfPS256, base, []fapi.SignatureAlgorithm{fapi.PS256}},
		{"singular within one_of", oneOfPS256, with(map[string]any{"token_endpoint_auth_signing_alg": "PS256"}), []fapi.SignatureAlgorithm{fapi.PS256}},
		{"plural outside value", `{"token_endpoint_auth_signing_alg":{"value":"PS256"}}`, with(map[string]any{"token_endpoint_auth_signing_alg_values_supported": []string{"ES256"}}), nil},
		{"defaults outside one_of", `{"token_endpoint_auth_signing_alg":{"one_of":["RS256"]}}`, base, nil},
		// subset_of on the plural can leave it empty: that declares no
		// algorithm, never "none declared, use the defaults".
		{"plural emptied by subset_of", `{"token_endpoint_auth_signing_alg_values_supported":{"subset_of":["RS256"]}}`, with(map[string]any{"token_endpoint_auth_signing_alg_values_supported": []string{"ES256"}}), nil},
		{"no policy", `{}`, with(map[string]any{"token_endpoint_auth_signing_alg_values_supported": []string{"ES256"}}), []fapi.SignatureAlgorithm{fapi.ES256}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, err := resolveUnderPolicy(t, tc.policy, tc.members)
			if tc.want == nil {
				if err == nil {
					t.Fatalf("ResolveClient registered %v, want the registration refused", client.ClientAssertionAlgorithms())
				}
				return
			}
			if err != nil {
				t.Fatalf("ResolveClient: %v", err)
			}
			if got := client.ClientAssertionAlgorithms(); !slices.Equal(got, tc.want) {
				t.Errorf("ClientAssertionAlgorithms() = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestAutomaticRegistrationHoldsMethodChoicesToPolicy: likewise for
// token_endpoint_auth_method and token_endpoint_auth_methods_supported.
func TestAutomaticRegistrationHoldsMethodChoicesToPolicy(t *testing.T) {
	members := func(extra map[string]any) map[string]any {
		m := map[string]any{
			"redirect_uris":                   []string{"https://rp.example.org/cb"},
			"token_endpoint_auth_signing_alg": "ES256",
			"tls_client_auth_subject_dn":      "CN=rp.example.org",
		}
		for k, v := range extra {
			m[k] = v
		}
		return m
	}
	both := []string{"tls_client_auth", "private_key_jwt"}
	for _, tc := range []struct {
		name    string
		policy  string
		members map[string]any
		want    []storage.ClientAuthMethod // nil: refused
	}{
		{"plural narrowed to one_of", `{"token_endpoint_auth_method":{"one_of":["private_key_jwt"]}}`,
			members(map[string]any{"token_endpoint_auth_methods_supported": both}),
			[]storage.ClientAuthMethod{storage.ClientAuthMethodPrivateKeyJWT}},
		{"plural outside one_of", `{"token_endpoint_auth_method":{"one_of":["private_key_jwt"]}}`,
			members(map[string]any{"token_endpoint_auth_methods_supported": []string{"tls_client_auth"}}), nil},
		{"plural narrowed to value", `{"token_endpoint_auth_method":{"value":"private_key_jwt"}}`,
			members(map[string]any{"token_endpoint_auth_methods_supported": both}),
			[]storage.ClientAuthMethod{storage.ClientAuthMethodPrivateKeyJWT}},
		// §12.1.4: with no policy on the method, every mutually supported
		// one is registered.
		{"no policy", `{}`,
			members(map[string]any{"token_endpoint_auth_methods_supported": both}),
			[]storage.ClientAuthMethod{storage.ClientAuthMethodTLSClientAuth, storage.ClientAuthMethodPrivateKeyJWT}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, err := resolveUnderPolicy(t, tc.policy, tc.members)
			if tc.want == nil {
				if err == nil {
					t.Fatalf("ResolveClient registered %v, want the registration refused", client.ClientAuthMethods())
				}
				return
			}
			if err != nil {
				t.Fatalf("ResolveClient: %v", err)
			}
			if got := client.ClientAuthMethods(); !slices.Equal(got, tc.want) {
				t.Errorf("ClientAuthMethods() = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestAutomaticRegistrationRefusesEmptyStringParameters: an empty
// string is present to a metadata policy, so it meets essential, but
// would read as left out; every string parameter registration reads
// refuses it. (null never gets this far: OpenID Federation 1.0 §5
// prohibits it as a metadata value, so the Entity Configuration is
// refused when parsed.)
func TestAutomaticRegistrationRefusesEmptyStringParameters(t *testing.T) {
	base := map[string]any{
		"redirect_uris":                   []string{"https://rp.example.org/cb"},
		"token_endpoint_auth_method":      "private_key_jwt",
		"token_endpoint_auth_signing_alg": "ES256",
	}
	with := func(name string, value any) map[string]any {
		m := map[string]any{name: value}
		for k, v := range base {
			if k != name {
				m[k] = v
			}
		}
		return m
	}
	for _, name := range []string{"subject_type", "client_name", "logo_uri", "request_object_signing_alg", "token_endpoint_auth_signing_alg", "backchannel_token_delivery_mode"} {
		t.Run(name, func(t *testing.T) {
			_, err := resolveUnderPolicy(t, `{"`+name+`":{"essential":true}}`, with(name, ""))
			if err == nil || !strings.Contains(err.Error(), name+" must not be empty") {
				t.Errorf("ResolveClient(%s \"\") = %v, want an empty-value error", name, err)
			}
		})
	}
}
