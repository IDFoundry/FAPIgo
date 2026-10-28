package server_test

import (
	"context"
	"crypto/rand"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/clientassertion"
	"github.com/idfoundry/fapigo/internal/requestobject"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/keys/ephemeral"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage/memstore"
)

// TestRecommendedPresetsProduceAWorkingServer is the real end-to-end
// check that RecommendedLimits/RecommendedAlgorithms aren't just
// individually-plausible values: combined with each other and with the
// real memstore/ephemeral reference implementations (not hand-rolled
// test fakes), server.New must actually accept the result.
func TestRecommendedPresetsProduceAWorkingServer(t *testing.T) {
	issuer, err := fapi.ParseIssuerURL(testIssuer)
	if err != nil {
		t.Fatalf("ParseIssuerURL: %v", err)
	}

	cfg := server.Config{
		Subjects:   server.PublicSubjects(),
		Issuer:     issuer,
		Endpoints:  testEndpoints(t),
		Profile:    server.ProfileFAPISecurity,
		Algorithms: server.RecommendedAlgorithms(),
		Limits:     server.RecommendedLimits(),
		Assurance:  server.AssuranceDevelopment,
	}

	keyManager, err := ephemeral.NewKeyManager(map[keys.SigningPurpose]fapi.SignatureAlgorithm{
		keys.AccessTokenSigning: fapi.ES256,
		keys.IDTokenSigning:     fapi.ES256,
	})
	if err != nil {
		t.Fatalf("ephemeral.NewKeyManager: %v", err)
	}
	clientKeys, err := ephemeral.NewClientKeySource(nil, nil)
	if err != nil {
		t.Fatalf("ephemeral.NewClientKeySource: %v", err)
	}

	deps := server.Dependencies{
		Clients:                memstore.NewClientRepository(nil),
		Transactions:           memstore.NewTransactionStore(),
		Grants:                 memstore.NewGrantStore(),
		Replay:                 memstore.NewReplayStore(),
		ClientKeys:             clientKeys,
		Keys:                   keyManager,
		AccessTokens:           server.JWTAccessTokens{Keys: keyManager, Algorithm: fapi.ES256},
		Revocation:             memstore.NewRevocationStore(),
		ClientCertificateTrust: server.NoClientCertificateChainTrust{},
		Clock:                  server.SystemClock{},
		Random:                 rand.Reader,
	}

	srv, err := server.New(cfg, deps)
	if err != nil {
		t.Fatalf("New(RecommendedLimits, RecommendedAlgorithms): %v", err)
	}

	md := srv.Metadata(context.Background())
	assertContains(t, md.TokenEndpointAuthSigningAlgValuesSupported, "ES256", "PS256")
	assertContains(t, md.RequestObjectSigningAlgValuesSupported, "ES256", "PS256")
	assertContains(t, md.IDTokenSigningAlgValuesSupported, "ES256")
}

// TestRecommendedAlgorithmsWorksUnderMessageSigning confirms
// RecommendedAlgorithms' unconditionally-set JARM field satisfies
// New's stricter validation under ProfileFAPISecurityWithMessageSigning
// too, not just the baseline profile.
func TestRecommendedAlgorithmsWorksUnderMessageSigning(t *testing.T) {
	issuer, err := fapi.ParseIssuerURL(testIssuer)
	if err != nil {
		t.Fatalf("ParseIssuerURL: %v", err)
	}

	cfg := server.Config{
		Subjects:   server.PublicSubjects(),
		Issuer:     issuer,
		Endpoints:  testEndpoints(t),
		Profile:    server.ProfileFAPISecurityWithMessageSigning,
		Algorithms: server.RecommendedAlgorithms(),
		Limits:     server.RecommendedLimits(),
		Assurance:  server.AssuranceDevelopment,
	}

	keyManager, err := ephemeral.NewKeyManager(map[keys.SigningPurpose]fapi.SignatureAlgorithm{
		keys.AccessTokenSigning: fapi.ES256,
		keys.IDTokenSigning:     fapi.ES256,
		keys.JARMSigning:        fapi.ES256,
	})
	if err != nil {
		t.Fatalf("ephemeral.NewKeyManager: %v", err)
	}
	clientKeys, err := ephemeral.NewClientKeySource(nil, nil)
	if err != nil {
		t.Fatalf("ephemeral.NewClientKeySource: %v", err)
	}

	deps := server.Dependencies{
		Clients:                memstore.NewClientRepository(nil),
		Transactions:           memstore.NewTransactionStore(),
		Grants:                 memstore.NewGrantStore(),
		Replay:                 memstore.NewReplayStore(),
		ClientKeys:             clientKeys,
		Keys:                   keyManager,
		AccessTokens:           server.JWTAccessTokens{Keys: keyManager, Algorithm: fapi.ES256},
		Revocation:             memstore.NewRevocationStore(),
		ClientCertificateTrust: server.NoClientCertificateChainTrust{},
		Clock:                  server.SystemClock{},
		Random:                 rand.Reader,
	}

	if _, err := server.New(cfg, deps); err != nil {
		t.Fatalf("New under ProfileFAPISecurityWithMessageSigning: %v", err)
	}
}

func TestRecommendedAlgorithmSetIsExactlyWhatThisModuleSupports(t *testing.T) {
	set := server.RecommendedAlgorithmSet()
	if len(set) != 3 || !set.Contains(fapi.ES256) || !set.Contains(fapi.PS256) || !set.Contains(fapi.EdDSA) {
		t.Fatalf("RecommendedAlgorithmSet() = %v, want exactly {ES256, PS256, EdDSA}", set)
	}
}

func assertContains(t *testing.T, got []string, want ...string) {
	t.Helper()
	for _, w := range want {
		found := false
		for _, g := range got {
			if g == w {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("%v does not contain %q", got, w)
		}
	}
}

// TestRecommendedLimitsAcceptMessageSigningRequestObjectWindows checks
// that a server on RecommendedLimits accepts request objects signed with
// a window of a few minutes, as Message Signing clients commonly do (the
// OIDF conformance suite uses exp - nbf = 300s; Message Signing §5.3.1
// allows up to 60 minutes), while still refusing one past its own limit.
func TestRecommendedLimitsAcceptMessageSigningRequestObjectWindows(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurityWithMessageSigning, true)
	cfg := h.cfg
	cfg.Limits = server.RecommendedLimits()
	srv, err := server.New(cfg, h.deps)
	if err != nil {
		t.Fatalf("server.New with RecommendedLimits: %v", err)
	}
	h.server = srv

	cases := []struct {
		lifetime time.Duration
		wantErr  bool
	}{
		{lifetime: 300 * time.Second, wantErr: false},
		{lifetime: 10 * time.Minute, wantErr: false},
		{lifetime: 11 * time.Minute, wantErr: true},
	}
	for _, c := range cases {
		obj, err := requestobject.Create(requestobject.CreateParams{
			Signer: h.key, Algorithm: fapi.ES256,
			ClientID: testClientID.String(), Audience: testIssuer,
			Now: h.now, Lifetime: c.lifetime, Parameters: standardAuthParams(t),
		})
		if err != nil {
			t.Fatalf("requestobject.Create: %v", err)
		}
		_, err = h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
			HTTP: server.FormRequest{Parameters: []server.FormParameter{
				formParam("client_assertion", h.clientAssertion(t)),
				formParam("client_assertion_type", clientassertion.AssertionType),
				formParam("request", obj),
			}},
		})
		if (err != nil) != c.wantErr {
			t.Errorf("request object with exp - nbf = %v: err = %v, want error %v", c.lifetime, err, c.wantErr)
		}
	}
}
