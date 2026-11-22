package server_test

import (
	"context"
	"reflect"
	"slices"
	"sync"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/federation"
	intfed "github.com/idfoundry/fapigo/internal/federation"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
	"github.com/idfoundry/fapigo/storage/memstore"
)

// TestNewCopiesConfigSlices is TestNewCopiesResources for every slice in
// Config: editing an element of one in place after New, as code deriving
// another tenant's Config from this one by value does, changes nothing
// the Server advertises or enforces. Each case edits one slice of the
// Config already passed to New; the Server must then show what a control
// built from an identical, unedited Config shows. The edited Server is
// first used after the edit, since the registration a federation Relying
// Party's first request caches would hide one made later.
func TestNewCopiesConfigSlices(t *testing.T) {
	f := setupAutomaticRegistrationFixture(t, testRedirectURI)
	otherTrustAnchorJWKS := fedJWKS(t, "ta", generateKey(t))
	for name, edit := range map[string]func(*server.Config){
		"Algorithms.ClientAssertion": func(c *server.Config) { c.Algorithms.ClientAssertion[0] = fapi.PS256 },
		"Algorithms.RequestObject":   func(c *server.Config) { c.Algorithms.RequestObject[0] = fapi.PS256 },
		"Algorithms.IDTokenEncryptionKeyManagement": func(c *server.Config) {
			c.Algorithms.IDTokenEncryptionKeyManagement[0] = fapi.ECDHESA256KW
		},
		"Algorithms.IDTokenEncryptionContentEncryption": func(c *server.Config) {
			c.Algorithms.IDTokenEncryptionContentEncryption[0] = fapi.A256CBCHS512
		},
		"Algorithms.UserInfoEncryptionKeyManagement": func(c *server.Config) {
			c.Algorithms.UserInfoEncryptionKeyManagement[0] = fapi.ECDHESA256KW
		},
		"Algorithms.UserInfoEncryptionContentEncryption": func(c *server.Config) {
			c.Algorithms.UserInfoEncryptionContentEncryption[0] = fapi.A256CBCHS512
		},
		"Algorithms.BackchannelAuthenticationRequest": func(c *server.Config) {
			c.Algorithms.BackchannelAuthenticationRequest[0] = fapi.PS256
		},
		"Algorithms.ClientAttestation":    func(c *server.Config) { c.Algorithms.ClientAttestation[0] = fapi.PS256 },
		"Algorithms.ClientAttestationPoP": func(c *server.Config) { c.Algorithms.ClientAttestationPoP[0] = fapi.PS256 },
		"AdditionalGrantTypes":            func(c *server.Config) { c.AdditionalGrantTypes[0] = "password" },
		"Resources":                       func(c *server.Config) { c.Resources[0] = resourceC },
		"Federation.AuthorityHints": func(c *server.Config) {
			c.Federation.AuthorityHints[0] = "https://other-ta.example.org"
		},
		"AutomaticRegistration.TrustAnchors JWKS": func(c *server.Config) {
			copy(c.AutomaticRegistration.TrustAnchors[0].JWKS, otherTrustAnchorJWKS)
		},
		"AutomaticRegistration.AllowedScopes": func(c *server.Config) { c.AutomaticRegistration.AllowedScopes[1] = "payments" },
		"AutomaticRegistration.AuthorizationDetailsTypes": func(c *server.Config) {
			c.AutomaticRegistration.AuthorizationDetailsTypes[0] = "account_information"
		},
		"AutomaticRegistration.AllowedResources": func(c *server.Config) { c.AutomaticRegistration.AllowedResources[0] = resourceC },
		"AutomaticRegistration.AllowedClientAuthMethods": func(c *server.Config) {
			c.AutomaticRegistration.AllowedClientAuthMethods[0] = storage.ClientAuthMethodTLSClientAuth
		},
		"AutomaticRegistration.SubjectTypes": func(c *server.Config) {
			c.AutomaticRegistration.SubjectTypes[0] = fapi.SubjectTypePairwise
		},
	} {
		t.Run(name, func(t *testing.T) {
			cfg, deps := everySliceConfig(t, f)
			srv, err := server.New(cfg, deps)
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			controlCfg, controlDeps := everySliceConfig(t, f)
			control, err := server.New(controlCfg, controlDeps)
			if err != nil {
				t.Fatalf("New(control): %v", err)
			}
			edit(&cfg)
			if got, want := viewOfServer(t, srv, f), viewOfServer(t, control, f); !reflect.DeepEqual(got, want) {
				t.Errorf("after the Config passed to New was edited, the server shows\n%+v\nwant what the unedited control shows\n%+v", got, want)
			}
		})
	}
}

// TestNewConfigEditedWhileServingNoRace edits every slice of the Config
// passed to New, storing back the values already there, until the
// Server has served requests that read the configuration: under -race,
// this fails if the Server still shares any of them with the caller.
// The edits go on until then, since the race detector can miss a race
// with a goroutine that has already exited.
func TestNewConfigEditedWhileServingNoRace(t *testing.T) {
	f := setupAutomaticRegistrationFixture(t, testRedirectURI)
	cfg, deps := everySliceConfig(t, f)
	srv, err := server.New(cfg, deps)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	stop := make(chan struct{})
	var wg sync.WaitGroup
	defer wg.Wait()
	defer close(stop)
	wg.Go(func() {
		for {
			select {
			case <-stop:
				return
			default:
				rewriteEverySlice(&cfg)
			}
		}
	})
	for range 3 {
		viewOfServer(t, srv, f)
	}
}

// everySliceConfig is automaticRegistrationTestConfig with a value in
// every slice Config has: CIBA, attestation-based client authentication,
// ID token and UserInfo encryption, an additional grant type, resource
// indicators, federation self-issuance and automatic registration's
// lists. Each call builds slices of its own, the Trust Anchor's JWKS
// included.
func everySliceConfig(t *testing.T, f *automaticRegistrationFixture) (server.Config, server.Dependencies) {
	t.Helper()
	backchannel, err := fapi.ParseEndpointURL(testBackchannelAuthenticationEndpoint)
	if err != nil {
		t.Fatalf("ParseEndpointURL: %v", err)
	}
	federationKey := generateKey(t)
	return automaticRegistrationTestConfig(t, f, func(cfg *server.Config, deps *server.Dependencies) {
		cfg.Endpoints.BackchannelAuthentication = backchannel
		cfg.Algorithms.BackchannelAuthenticationRequest = server.AlgorithmSet{fapi.ES256}
		cfg.Limits.BackchannelAuthenticationRequestLifetime = 2 * time.Minute
		cfg.Limits.MaxBackchannelAuthenticationRequestLifetime = time.Minute
		cfg.Limits.BackchannelAuthenticationPollInterval = time.Second
		deps.Backchannel = memstore.NewBackchannelAuthenticationStore()
		deps.BackchannelNotifier = server.NoBackchannelNotifications{}

		cfg.AttestationBasedClientAuthentication = true
		cfg.Algorithms.ClientAttestation = server.AlgorithmSet{fapi.ES256}
		cfg.Algorithms.ClientAttestationPoP = server.AlgorithmSet{fapi.ES256}
		cfg.Limits.MaxClientAttestationLifetime = time.Hour
		cfg.Limits.MaxClientAttestationPoPAge = time.Minute
		deps.AttesterTrust = server.RegisteredAttesterKeys{Keys: keys.StaticAttesterKeys{}}

		cfg.Algorithms.IDTokenEncryptionKeyManagement = server.KeyManagementAlgorithmSet{fapi.RSAOAEP256}
		cfg.Algorithms.IDTokenEncryptionContentEncryption = server.ContentEncryptionAlgorithmSet{fapi.A256GCM}
		cfg.Algorithms.UserInfo = fapi.ES256
		cfg.Algorithms.UserInfoEncryptionKeyManagement = server.KeyManagementAlgorithmSet{fapi.RSAOAEP256}
		cfg.Algorithms.UserInfoEncryptionContentEncryption = server.ContentEncryptionAlgorithmSet{fapi.A256GCM}
		deps.ClientEncryptionKeys = fakeClientEncryptionKeySource{}

		cfg.AdditionalGrantTypes = []string{preAuthorizedCodeGrant}
		cfg.Resources = []string{resourceA, resourceB}

		cfg.Federation = server.FederationConfig{
			EntityID: testIssuer, AuthorityHints: []string{"https://ta.example.org"},
			Lifetime: time.Hour, Algorithm: fapi.ES256,
		}
		deps.Keys.(*fakeKeyManager).federationKey = federationKey

		cfg.RAR = newTestRARRegistry(t)
		deps.AuthorizationCodeRARPolicy = server.AllowRequestedAuthorizationDetails{}
		cfg.AutomaticRegistration.TrustAnchors = []federation.TrustAnchor{{EntityID: f.taID, JWKS: slices.Clone(f.taJWKS)}}
		cfg.AutomaticRegistration.AuthorizationDetailsTypes = []string{"payment"}
		cfg.AutomaticRegistration.AllowedResources = []string{resourceA, resourceB}
		cfg.AutomaticRegistration.AllowedClientAuthMethods = []storage.ClientAuthMethod{storage.ClientAuthMethodPrivateKeyJWT}
		cfg.AutomaticRegistration.SubjectTypes = []fapi.SubjectType{fapi.SubjectTypePublic}
	})
}

// rewriteEverySlice stores every element of each slice everySliceConfig
// sets back in place: writes to their backing arrays that change
// nothing.
func rewriteEverySlice(cfg *server.Config) {
	rewrite(cfg.Algorithms.ClientAssertion)
	rewrite(cfg.Algorithms.RequestObject)
	rewrite(cfg.Algorithms.IDTokenEncryptionKeyManagement)
	rewrite(cfg.Algorithms.IDTokenEncryptionContentEncryption)
	rewrite(cfg.Algorithms.UserInfoEncryptionKeyManagement)
	rewrite(cfg.Algorithms.UserInfoEncryptionContentEncryption)
	rewrite(cfg.Algorithms.BackchannelAuthenticationRequest)
	rewrite(cfg.Algorithms.ClientAttestation)
	rewrite(cfg.Algorithms.ClientAttestationPoP)
	rewrite(cfg.AdditionalGrantTypes)
	rewrite(cfg.Resources)
	rewrite(cfg.Federation.AuthorityHints)
	rewrite(cfg.AutomaticRegistration.TrustAnchors)
	rewrite(cfg.AutomaticRegistration.TrustAnchors[0].JWKS)
	rewrite(cfg.AutomaticRegistration.AllowedScopes)
	rewrite(cfg.AutomaticRegistration.AuthorizationDetailsTypes)
	rewrite(cfg.AutomaticRegistration.AllowedResources)
	rewrite(cfg.AutomaticRegistration.AllowedClientAuthMethods)
	rewrite(cfg.AutomaticRegistration.SubjectTypes)
}

// rewrite stores each element of s back where it is.
func rewrite[S ~[]E, E any](s S) {
	for i, e := range s {
		s[i] = e
	}
}

// serverView is what a Server shows of the slices in its Config.
type serverView struct {
	Metadata server.Metadata
	// AuthorityHints is the authority_hints of its Entity Configuration.
	AuthorityHints []string
	// AutomaticSubjectTypes is AutomaticRegistrationSubjectTypes.
	AutomaticSubjectTypes []string
	// FederatedPush is how it answers f's Relying Party pushing an
	// authorization request: "pushed", or the error code.
	FederatedPush string
}

// viewOfServer is what srv shows, f's Relying Party pushing an
// authorization request for resourceA and payment details with
// everySliceConfig's scope.
func viewOfServer(t *testing.T, srv *server.Server, f *automaticRegistrationFixture) serverView {
	t.Helper()
	ctx := context.Background()
	statement, err := srv.EntityConfiguration(ctx, nil)
	if err != nil {
		t.Fatalf("EntityConfiguration: %v", err)
	}
	parsed, err := intfed.Parse(statement)
	if err != nil {
		t.Fatalf("intfed.Parse: %v", err)
	}
	view := serverView{
		Metadata:              srv.Metadata(ctx),
		AuthorityHints:        parsed.ClaimedAuthorityHints(),
		AutomaticSubjectTypes: srv.AutomaticRegistrationSubjectTypes(),
		FederatedPush:         "pushed",
	}
	_, err = srv.PushAuthorizationRequest(ctx, server.PushAuthorizationRequest{
		HTTP: server.FormRequest{Parameters: plainFormParameters(t, federatedAssertion(t, f), map[string]string{
			"resource": resourceA, "authorization_details": paymentDetails,
		})},
	})
	if err != nil {
		view.FederatedPush = string(serverErrorCode(t, err))
	}
	return view
}
