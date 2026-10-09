package fapihttp_test

import (
	"testing"

	"github.com/idfoundry/fapigo/fapihttp"
)

// TestRecommendedPresetsAreAccepted: the presets set every limit New
// and NewClient require, and grant no loopback exception, so a
// transport built from them counts as hardened.
func TestRecommendedPresetsAreAccepted(t *testing.T) {
	transportCfg := fapihttp.RecommendedTransportConfig()
	if transportCfg.AllowsLoopback() {
		t.Fatal("RecommendedTransportConfig grants a loopback exception")
	}
	transport, err := fapihttp.NewClient(transportCfg)
	if err != nil {
		t.Fatalf("NewClient(RecommendedTransportConfig()): %v", err)
	}
	cfg := fapihttp.RecommendedConfig()
	if cfg.AllowsLoopback() {
		t.Fatal("RecommendedConfig grants a loopback exception")
	}
	fetcher, err := fapihttp.New(transport, cfg)
	if err != nil {
		t.Fatalf("New(transport, RecommendedConfig()): %v", err)
	}
	if fetcher.AllowsLoopback() {
		t.Fatal("a fetcher built from the presets allows loopback")
	}
}
