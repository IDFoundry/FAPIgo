package server_test

import (
	"context"
	"crypto/rand"
	"testing"

	fapi "github.com/idfoundry/fapigo"
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
		Clients:      memstore.NewClientRepository(nil),
		Transactions: memstore.NewTransactionStore(),
		Grants:       memstore.NewGrantStore(),
		Replay:       memstore.NewReplayStore(),
		ClientKeys:   clientKeys,
		Keys:         keyManager,
		Clock:        server.SystemClock{},
		Random:       rand.Reader,
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
		Clients:      memstore.NewClientRepository(nil),
		Transactions: memstore.NewTransactionStore(),
		Grants:       memstore.NewGrantStore(),
		Replay:       memstore.NewReplayStore(),
		ClientKeys:   clientKeys,
		Keys:         keyManager,
		Clock:        server.SystemClock{},
		Random:       rand.Reader,
	}

	if _, err := server.New(cfg, deps); err != nil {
		t.Fatalf("New under ProfileFAPISecurityWithMessageSigning: %v", err)
	}
}

func TestRecommendedAlgorithmSetIsExactlyWhatThisModuleSupports(t *testing.T) {
	set := server.RecommendedAlgorithmSet()
	if len(set) != 2 || !set.Contains(fapi.ES256) || !set.Contains(fapi.PS256) {
		t.Fatalf("RecommendedAlgorithmSet() = %v, want exactly {ES256, PS256}", set)
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
