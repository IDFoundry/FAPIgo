package federation_test

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"maps"
	"net/url"
	"strings"
	"testing"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/federation"
	intfed "github.com/idfoundry/fapigo/internal/federation"
	"github.com/idfoundry/fapigo/storage"
)

// subjectTypesConfig is validAutomaticRegistrationConfig for an OP
// issuing types, defaulting to def.
func subjectTypesConfig(def fapi.SubjectType, types ...fapi.SubjectType) federation.AutomaticRegistrationConfig {
	cfg := validAutomaticRegistrationConfig()
	cfg.SubjectTypes = types
	cfg.DefaultSubjectType = def
	return cfg
}

// resolveWith registers the fixture RP under cfg, returning the client
// and the failure OnResolutionFailure saw, if any.
func resolveWith(t *testing.T, f *automaticRegistrationFixture, cfg federation.AutomaticRegistrationConfig) (storage.RegisteredClient, error) {
	t.Helper()
	var failure error
	cfg.OnResolutionFailure = func(_ context.Context, _ fapi.ClientID, err error) { failure = err }
	repo, err := federation.NewAutomaticClientRepository(alwaysFailsRepository{}, f.newResolver(t), f.fetcher, cfg, fixedClock{now: f.now})
	if err != nil {
		t.Fatalf("NewAutomaticClientRepository: %v", err)
	}
	client, err := repo.ResolveClient(context.Background(), fapi.ClientID(f.rpID))
	if err != nil && failure == nil {
		t.Fatalf("ResolveClient failed (%v) without reporting why", err)
	}
	return client, failure
}

// TestAutomaticRegistrationSubjectType: an automatically registered
// client gets the subject_type its metadata names, or the OP's default,
// recorded on the client; one the OP doesn't issue, or an unknown
// value, fails the registration.
func TestAutomaticRegistrationSubjectType(t *testing.T) {
	both := []fapi.SubjectType{fapi.SubjectTypePublic, fapi.SubjectTypePairwise}
	tests := []struct {
		name     string
		metadata map[string]any
		cfg      federation.AutomaticRegistrationConfig
		want     fapi.SubjectType
		wantErr  string
	}{
		{"absent, public-only OP (zero config)", nil, validAutomaticRegistrationConfig(), fapi.SubjectTypePublic, ""},
		{"absent, pairwise default", nil, subjectTypesConfig(fapi.SubjectTypePairwise, both...), fapi.SubjectTypePairwise, ""},
		{"absent, public default", nil, subjectTypesConfig(fapi.SubjectTypePublic, both...), fapi.SubjectTypePublic, ""},
		{"pairwise asked", map[string]any{"subject_type": "pairwise"}, subjectTypesConfig(fapi.SubjectTypePublic, both...), fapi.SubjectTypePairwise, ""},
		{"public asked", map[string]any{"subject_type": "public"}, subjectTypesConfig(fapi.SubjectTypePairwise, both...), fapi.SubjectTypePublic, ""},
		{"pairwise from a public-only OP", map[string]any{"subject_type": "pairwise"}, validAutomaticRegistrationConfig(), 0, "subject_type pairwise is not one this OP issues"},
		{"public from a pairwise-only OP", map[string]any{"subject_type": "public"}, subjectTypesConfig(fapi.SubjectTypePairwise, fapi.SubjectTypePairwise), 0, "subject_type public is not one this OP issues"},
		{"unknown value", map[string]any{"subject_type": "Pairwise"}, subjectTypesConfig(fapi.SubjectTypePublic, both...), 0, "subject_type:"},
		{"not a string", map[string]any{"subject_type": 1}, subjectTypesConfig(fapi.SubjectTypePublic, both...), 0, "parse"},
		{"sector_identifier_uri with pairwise", map[string]any{"subject_type": "pairwise", "sector_identifier_uri": "https://rp.example/sector.json"}, subjectTypesConfig(fapi.SubjectTypePublic, both...), 0, "sector_identifier_uri"},
		{"sector_identifier_uri with public", map[string]any{"sector_identifier_uri": "https://rp.example/sector.json"}, subjectTypesConfig(fapi.SubjectTypePublic, both...), fapi.SubjectTypePublic, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := setupAutomaticRegistrationFixture(t, rpMetadataWith(t, tc.metadata))
			client, failure := resolveWith(t, f, tc.cfg)
			if tc.wantErr != "" {
				if failure == nil || !strings.Contains(failure.Error(), tc.wantErr) {
					t.Fatalf("registration failure = %v, want one mentioning %q", failure, tc.wantErr)
				}
				return
			}
			if failure != nil {
				t.Fatalf("registration failed: %v", failure)
			}
			if got := client.SubjectType(); got != tc.want {
				t.Errorf("SubjectType() = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestAutomaticRegistrationPolicyForcesPairwise: a superior's
// metadata_policy setting subject_type is what the client gets, whatever
// its own metadata says.
func TestAutomaticRegistrationPolicyForcesPairwise(t *testing.T) {
	policy := intfed.MetadataPolicy{"openid_relying_party": {
		"subject_type": {"value": json.RawMessage(`"pairwise"`)},
	}}
	f := setupAutomaticRegistrationFixtureWithPolicy(t, rpMetadataWith(t, map[string]any{"subject_type": "public"}), policy)
	client, failure := resolveWith(t, f, subjectTypesConfig(fapi.SubjectTypePublic, fapi.SubjectTypePublic, fapi.SubjectTypePairwise))
	if failure != nil {
		t.Fatalf("registration failed: %v", failure)
	}
	if got := client.SubjectType(); got != fapi.SubjectTypePairwise {
		t.Errorf("SubjectType() = %v, want pairwise (forced by the superior's policy)", got)
	}
}

// TestAutomaticRegistrationPairwiseSector: a pairwise client's sector is
// its Entity Identifier's host, and its redirect URIs must all be https
// on that host; redirect URIs elsewhere fail the registration. A public
// client needs no sector.
func TestAutomaticRegistrationPairwiseSector(t *testing.T) {
	both := []fapi.SubjectType{fapi.SubjectTypePublic, fapi.SubjectTypePairwise}
	t.Run("one host", func(t *testing.T) {
		f := setupAutomaticRegistrationFixture(t, rpMetadataWith(t, map[string]any{"subject_type": "pairwise"}))
		client, failure := resolveWith(t, f, subjectTypesConfig(fapi.SubjectTypePublic, both...))
		if failure != nil {
			t.Fatalf("registration failed: %v", failure)
		}
		if want := hostOf(t, f.rpID); client.Sector() != want {
			t.Errorf("Sector() = %q, want %q", client.Sector(), want)
		}
	})
	t.Run("several hosts, pairwise", func(t *testing.T) {
		f := setupAutomaticRegistrationFixture(t, multiHostMetadata(t, "pairwise"))
		_, failure := resolveWith(t, f, subjectTypesConfig(fapi.SubjectTypePublic, both...))
		if failure == nil || !strings.Contains(failure.Error(), "Entity Identifier's host") {
			t.Fatalf("registration failure = %v, want a pairwise client with a redirect URI off its own host refused", failure)
		}
	})
	t.Run("several hosts, public", func(t *testing.T) {
		f := setupAutomaticRegistrationFixture(t, multiHostMetadata(t, "public"))
		client, failure := resolveWith(t, f, subjectTypesConfig(fapi.SubjectTypePublic, both...))
		if failure != nil {
			t.Fatalf("registration failed: %v", failure)
		}
		if client.Sector() != "" {
			t.Errorf("Sector() = %q, want none", client.Sector())
		}
	})
}

// TestAutomaticRegistrationSubjectTypeIsStableAcrossRegistrations: the
// same metadata registered again (a new repository, as after the cache
// expires) gives the same subject type and sector, so the client's end
// users keep their sub values.
func TestAutomaticRegistrationSubjectTypeIsStableAcrossRegistrations(t *testing.T) {
	f := setupAutomaticRegistrationFixture(t, rpMetadataBuilder(t))
	cfg := subjectTypesConfig(fapi.SubjectTypePairwise, fapi.SubjectTypePublic, fapi.SubjectTypePairwise)
	first, failure := resolveWith(t, f, cfg)
	if failure != nil {
		t.Fatalf("first registration failed: %v", failure)
	}
	second, failure := resolveWith(t, f, cfg)
	if failure != nil {
		t.Fatalf("second registration failed: %v", failure)
	}
	if first.SubjectType() != second.SubjectType() || first.Sector() != second.Sector() {
		t.Errorf("registrations differ: (%v, %q) then (%v, %q)", first.SubjectType(), first.Sector(), second.SubjectType(), second.Sector())
	}
}

func TestNewAutomaticClientRepositoryRejectsInvalidSubjectTypes(t *testing.T) {
	f := setupAutomaticRegistrationFixture(t, rpMetadataBuilder(t))
	for name, cfg := range map[string]federation.AutomaticRegistrationConfig{
		"invalid type":               subjectTypesConfig(0, fapi.SubjectType(9)),
		"listed twice":               subjectTypesConfig(0, fapi.SubjectTypePublic, fapi.SubjectTypePublic),
		"default not listed":         subjectTypesConfig(fapi.SubjectTypePairwise, fapi.SubjectTypePublic),
		"pairwise default, no types": subjectTypesConfig(fapi.SubjectTypePairwise),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := federation.NewAutomaticClientRepository(alwaysFailsRepository{}, f.newResolver(t), f.fetcher, cfg, fixedClock{now: f.now}); err == nil {
				t.Fatal("NewAutomaticClientRepository accepted it")
			}
		})
	}
}

// multiHostMetadata is rpMetadataBuilder's metadata with redirect URIs
// on two hosts and the given subject_type.
func multiHostMetadata(t *testing.T, subjectType string) func(rpID string, rpOIDCKey *ecdsa.PrivateKey) json.RawMessage {
	return func(rpID string, rpOIDCKey *ecdsa.PrivateKey) json.RawMessage {
		return rpMetadataWith(t, map[string]any{
			"redirect_uris": []string{rpID + "/cb", "https://other.example/cb"},
			"subject_type":  subjectType,
		})(rpID, rpOIDCKey)
	}
}

func hostOf(t *testing.T, rawURL string) string {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse %q: %v", rawURL, err)
	}
	return strings.ToLower(u.Hostname())
}

// TestAutomaticRegistrationPairwiseRefusesAnotherRPsHost: a Relying
// Party can't take another Relying Party's sector, and with it that
// Relying Party's pairwise sub values, by naming that Relying Party's
// host in its own redirect_uris, whether or not it then uses CIBA, which
// delivers tokens without the redirect that would otherwise prove it.
func TestAutomaticRegistrationPairwiseRefusesAnotherRPsHost(t *testing.T) {
	for name, extra := range map[string]map[string]any{
		"code flow": {},
		"CIBA": {
			"backchannel_authentication_request_signing_alg": "ES256",
			"backchannel_token_delivery_mode":                "poll",
		},
	} {
		t.Run(name, func(t *testing.T) {
			fields := map[string]any{
				"subject_type":  "pairwise",
				"redirect_uris": []string{"https://victim-rp.example/cb"},
			}
			maps.Copy(fields, extra)
			f := setupAutomaticRegistrationFixture(t, rpMetadataWith(t, fields))
			cfg := subjectTypesConfig(fapi.SubjectTypePairwise, fapi.SubjectTypePublic, fapi.SubjectTypePairwise)
			cfg.AllowsCIBA = true
			_, failure := resolveWith(t, f, cfg)
			if failure == nil || !strings.Contains(failure.Error(), "Entity Identifier's host") {
				t.Fatalf("registration failure = %v, want the victim's host refused", failure)
			}
		})
	}
}

// TestAutomaticRegistrationPairwiseCIBAUsesEntityHost: a pairwise
// Relying Party permitted CIBA gets its Entity Identifier's host as its
// sector, though a CIBA client derives none from its redirect URIs.
func TestAutomaticRegistrationPairwiseCIBAUsesEntityHost(t *testing.T) {
	f := setupAutomaticRegistrationFixture(t, rpMetadataWith(t, map[string]any{
		"subject_type": "pairwise",
		"backchannel_authentication_request_signing_alg": "ES256",
		"backchannel_token_delivery_mode":                "poll",
	}))
	cfg := subjectTypesConfig(fapi.SubjectTypePairwise, fapi.SubjectTypePublic, fapi.SubjectTypePairwise)
	cfg.AllowsCIBA = true
	client, failure := resolveWith(t, f, cfg)
	if failure != nil {
		t.Fatalf("registration failed: %v", failure)
	}
	if _, ok := client.BackchannelAuthenticationRequestAlgorithm(); !ok {
		t.Fatal("CIBA not permitted")
	}
	if want := hostOf(t, f.rpID); client.Sector() != want {
		t.Errorf("Sector() = %q, want the Entity Identifier's host %q", client.Sector(), want)
	}
}
