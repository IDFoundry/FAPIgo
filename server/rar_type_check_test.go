package server_test

import (
	"context"
	"strings"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/clientassertion"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
)

// TestRefusalNamesAMistypedRegistration covers the refusal's cause, for
// the logs: a client registered for a type Config.RAR doesn't know —
// "paymnet" — is refused "payment", and the cause names the typo.
func TestRefusalNamesAMistypedRegistration(t *testing.T) {
	policy := newCountingPolicy()
	h := newHarnessWithRARTypes(t, server.ProfileFAPISecurity, newTestRARRegistry(t), policy, policy, []string{"paymnet"})
	_, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
		HTTP: server.FormRequest{Parameters: plainFormParameters(t, h.clientAssertion(t), map[string]string{"authorization_details": paymentDetails})},
	})
	if code := serverErrorCode(t, err); code != server.ErrorInvalidAuthorizationDetails {
		t.Fatalf("error code %q, want %q", code, server.ErrorInvalidAuthorizationDetails)
	}
	if !strings.Contains(err.Error(), `"paymnet"`) || !strings.Contains(err.Error(), "Config.RAR") {
		t.Errorf("cause = %v, want it to name the registration's unknown type", err)
	}
}

func TestCheckClientRegistration(t *testing.T) {
	for name, tc := range map[string]struct {
		types   []string
		unknown string
	}{
		"registered types": {[]string{"payment"}, ""},
		"no types":         {nil, ""},
		"a typo":           {[]string{"payment", "paymnet"}, "paymnet"},
	} {
		t.Run(name, func(t *testing.T) {
			policy := newCountingPolicy()
			h := newHarnessWithRARTypes(t, server.ProfileFAPISecurity, newTestRARRegistry(t), policy, policy, tc.types)
			client, err := storage.NewRegisteredClient(storage.RegisteredClientConfig{
				ID: testClientID, ClientAssertionAlgorithm: fapi.ES256, AllowedScopes: []string{"accounts"}, RedirectURIs: []fapi.RegisteredRedirectURI{testRedirectURI},
				AuthorizationDetailsTypes: tc.types,
			})
			if err != nil {
				t.Fatal(err)
			}
			err = h.server.CheckClientRegistration(client)
			switch {
			case tc.unknown == "" && err != nil:
				t.Errorf("CheckClientRegistration = %v, want nil", err)
			case tc.unknown != "" && (err == nil || !strings.Contains(err.Error(), tc.unknown) || strings.Contains(err.Error(), `"payment"`)):
				t.Errorf("CheckClientRegistration = %v, want it to name %q alone", err, tc.unknown)
			}
		})
	}
}

// TestAutomaticRegistrationAuthorizationDetailsTypes covers the server's
// AutomaticRegistrationConfig.AuthorizationDetailsTypes reaching the
// automatically-registered client, and New refusing a type Config.RAR
// doesn't register.
func TestAutomaticRegistrationAuthorizationDetailsTypes(t *testing.T) {
	f := setupAutomaticRegistrationFixture(t, testRedirectURI)
	assertion, err := clientassertion.CreateAssertion(clientassertion.AssertionRequest{
		Signer: f.rpOIDCKey, Algorithm: fapi.ES256, KeyID: "rp-oidc",
		ClientID: f.rpID, Audience: testIssuer, Now: f.now, Lifetime: 30 * time.Second,
	})
	if err != nil {
		t.Fatalf("CreateAssertion: %v", err)
	}
	params := append(clientCredentialsFormParams(assertion, "accounts"), formParam("authorization_details", paymentDetails))
	rar := func(types []string) func(*server.Config, *server.Dependencies) {
		return func(cfg *server.Config, deps *server.Dependencies) {
			cfg.ClientCredentialsGrant = true
			cfg.AutomaticRegistration.AllowsClientCredentialsGrant = true
			cfg.RAR = newTestRARRegistry(t)
			cfg.AutomaticRegistration.AuthorizationDetailsTypes = types
			deps.ClientCredentialsRARPolicy = server.AllowRequestedAuthorizationDetails{}
		}
	}
	request := func(srv *server.Server) error {
		_, err := srv.RequestClientCredentialsToken(context.Background(), server.ClientCredentialsTokenRequest{
			HTTP: server.FormRequest{Parameters: params}, DPoPProofs: []string{createDPoPProof(t, generateKey(t), f.now)},
		})
		return err
	}

	if err := request(newAutomaticRegistrationTestServer(t, f, rar([]string{"payment"}))); err != nil {
		t.Errorf("RequestClientCredentialsToken(payment, registered) = %v, want nil", err)
	}
	err = request(newAutomaticRegistrationTestServer(t, f, rar(nil)))
	if code := serverErrorCode(t, err); code != server.ErrorInvalidAuthorizationDetails {
		t.Errorf("RequestClientCredentialsToken(no types) error code %q, want %q", code, server.ErrorInvalidAuthorizationDetails)
	}

	cfg := validConfig(t)
	cfg.AutomaticRegistration = validAutomaticRegistrationServerConfig(f)
	deps := validDependencies()
	deps.FederationHTTP, deps.Clock = f.fetcher, fixedClock{now: f.now}
	rar([]string{"paymnet"})(&cfg, &deps)
	if _, err := server.New(cfg, deps); err == nil || !strings.Contains(err.Error(), "paymnet") {
		t.Errorf("New(an unregistered automatic-registration type) = %v, want an error naming it", err)
	}
}
