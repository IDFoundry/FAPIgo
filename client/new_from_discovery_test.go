package client_test

import (
	"testing"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/client"
)

// TestNewFromDiscoverySucceedsWhenAlgorithmsMatch covers the base case:
// a Config whose declared algorithms are all among what discovered
// advertises constructs successfully, exactly like plain New.
func TestNewFromDiscoverySucceedsWhenAlgorithmsMatch(t *testing.T) {
	discovered := discoverForAlgorithmTests(t)
	cfg := validConfig(t)
	cfg.Algorithms.IDToken = fapi.ES256

	if _, err := client.NewFromDiscovery(discovered, cfg, validDependencies(t)); err != nil {
		t.Fatalf("NewFromDiscovery(matching algorithms): %v", err)
	}
}

// TestNewFromDiscoveryRejectsUnsupportedAlgorithm covers the entire
// point of this constructor: a declared algorithm the issuer never
// advertised is caught here, even though plain New has no way to know
// and would accept the identical Config.
func TestNewFromDiscoveryRejectsUnsupportedAlgorithm(t *testing.T) {
	discovered := discoverForAlgorithmTests(t)
	cfg := validConfig(t)
	cfg.Algorithms.IDToken = fapi.PS256 // discoverForAlgorithmTests only ever advertises ES256

	if _, err := client.NewFromDiscovery(discovered, cfg, validDependencies(t)); err == nil {
		t.Fatal("NewFromDiscovery(unadvertised id_token algorithm) = nil error, want error")
	}
	if _, err := client.New(cfg, validDependencies(t)); err != nil {
		t.Fatalf("New(same config): %v, want success — proves NewFromDiscovery's check is the delta, not a New-side rejection", err)
	}
}

// TestNewFromDiscoveryLeavesConfigEndpointsAlone covers the other half
// of NewFromDiscovery's contract: it never reads or overwrites
// cfg.Endpoints with discovered.Endpoints — a Config already pointing
// at a completely different set of endpoints than the ones just
// discovered (as would be the case after a caller already applied its
// own MTLSEndpoints.ApplyForSenderConstrain/ApplyForClientAuth
// override) still constructs successfully, using exactly the Config it
// was given.
func TestNewFromDiscoveryLeavesConfigEndpointsAlone(t *testing.T) {
	discovered := discoverForAlgorithmTests(t)
	cfg := validConfig(t) // endpoints at testIssuer, unrelated to discovered's own httptest server
	cfg.Algorithms.IDToken = fapi.ES256

	if _, err := client.NewFromDiscovery(discovered, cfg, validDependencies(t)); err != nil {
		t.Fatalf("NewFromDiscovery(config endpoints independent of discovered): %v", err)
	}
}
