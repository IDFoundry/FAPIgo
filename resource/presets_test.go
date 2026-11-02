package resource_test

import (
	"testing"

	"github.com/idfoundry/fapigo/resource"
	"github.com/idfoundry/fapigo/server"
)

// TestRecommendedLimitsMatchServer: a resource server built from
// resource.RecommendedLimits accepts the DPoP proofs and clock offsets
// its authorization server, built from server.RecommendedLimits, does.
func TestRecommendedLimitsMatchServer(t *testing.T) {
	got := resource.RecommendedLimits()
	srv := server.RecommendedLimits()
	want := resource.Limits{
		MaxDPoPProofAge:   srv.MaxDPoPProofAge,
		MaxClockSkew:      srv.MaxClockSkew,
		DPoPNonceLifetime: srv.DPoPNonceLifetime,
	}
	if got != want {
		t.Fatalf("resource.RecommendedLimits() = %+v, want the server preset's %+v", got, want)
	}
}

// TestRecommendedLimitsAcceptedInProduction: the preset satisfies every
// bound NewVerifier enforces under AssuranceProduction, with nonces on.
func TestRecommendedLimitsAcceptedInProduction(t *testing.T) {
	cfg, deps := productionSetup(t)
	cfg.Limits = resource.RecommendedLimits()
	if _, err := resource.NewVerifier(cfg, deps); err != nil {
		t.Fatalf("NewVerifier(RecommendedLimits, AssuranceProduction): %v", err)
	}
}
