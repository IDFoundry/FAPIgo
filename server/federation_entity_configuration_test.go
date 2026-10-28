package server_test

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	intfed "github.com/idfoundry/fapigo/internal/federation"
	"github.com/idfoundry/fapigo/server"
)

// TestEntityConfigurationAdvertisesAutomaticRegistration covers OpenID
// Federation 1.0 §12.1, "An OP that supports Automatic Registration
// MUST include the automatic keyword in its
// client_registration_types_supported metadata parameter": the Entity
// Configuration carries it whether or not the caller's openid_provider
// metadata did, keeps any other listed type, and round-trips through
// the library's own Parse.
func TestEntityConfigurationAdvertisesAutomaticRegistration(t *testing.T) {
	f := setupAutomaticRegistrationFixture(t, "")
	cfg, deps := automaticRegistrationTestConfig(t, f, func(cfg *server.Config, deps *server.Dependencies) {
		cfg.Federation = server.FederationConfig{EntityID: testIssuer, Lifetime: time.Hour, Algorithm: fapi.ES256}
		deps.Keys.(*fakeKeyManager).federationKey = generateKey(t)
	})
	srv, err := server.New(cfg, deps)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for name, tc := range map[string]struct {
		op   string
		want []string
	}{
		"absent":           {`{"issuer":"` + testIssuer + `"}`, []string{"automatic"}},
		"explicit only":    {`{"client_registration_types_supported":["explicit"]}`, []string{"explicit", "automatic"}},
		"already included": {`{"client_registration_types_supported":["automatic"]}`, []string{"automatic"}},
	} {
		t.Run(name, func(t *testing.T) {
			statement, err := srv.EntityConfiguration(context.Background(), map[string]json.RawMessage{"openid_provider": json.RawMessage(tc.op)})
			if err != nil {
				t.Fatalf("EntityConfiguration: %v", err)
			}
			if _, err := intfed.Parse(statement); err != nil {
				t.Fatalf("intfed.Parse: %v", err)
			}
			var op struct {
				Types []string `json:"client_registration_types_supported"`
			}
			if err := json.Unmarshal(jwtPayloadMetadata(t, statement)["openid_provider"], &op); err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(op.Types, tc.want) {
				t.Errorf("client_registration_types_supported = %q, want %q", op.Types, tc.want)
			}
		})
	}
}

// TestEntityConfigurationRefusesForeignIssuer covers §5.1.3: "The
// issuer parameter value in the openid_provider metadata MUST match the
// Federation Entity Identifier".
func TestEntityConfigurationRefusesForeignIssuer(t *testing.T) {
	deps := validDependencies()
	deps.Keys = &fakeKeyManager{key: generateKey(t), keyID: "as-fed-kid", federationKey: generateKey(t)}
	srv, err := server.New(federationConfiguredConfig(t), deps)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := srv.EntityConfiguration(context.Background(), map[string]json.RawMessage{
		"openid_provider": json.RawMessage(`{"issuer":"https://someone-else.example.org"}`),
	}); err == nil {
		t.Fatal("EntityConfiguration(foreign issuer) = nil error, want it refused")
	}
}

// TestNewRejectsFederationEntityIDNotIssuer covers OpenID Federation
// 1.0 §5.1.3: an OP's Entity Identifier is its issuer, so a
// configuration where they differ, even by a trailing slash, is refused.
func TestNewRejectsFederationEntityIDNotIssuer(t *testing.T) {
	for _, entityID := range []string{testIssuer + "/", "https://as.example.org", testIssuer + "/federation"} {
		cfg := federationConfiguredConfig(t)
		cfg.Federation.EntityID = entityID
		deps := validDependencies()
		deps.Keys = &fakeKeyManager{key: generateKey(t), keyID: "as-fed-kid", federationKey: generateKey(t)}
		if _, err := server.New(cfg, deps); err == nil || !strings.Contains(err.Error(), "must equal issuer") {
			t.Errorf("New(entity ID %q, issuer %q) = %v, want it refused", entityID, testIssuer, err)
		}
	}
}
