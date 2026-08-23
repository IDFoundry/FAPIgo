package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestMetadataAdvertisesEdDSAForDPoP guards against exactly the mistake
// Phase 3 of EdDSA support fixed: dpopSigningAlgValuesSupported is a
// fixed list (see wireMetadata's own doc comment for why — DPoP proof
// verification checks against this module's whole closed algorithm
// set, not a configured subset), so adding a new SignatureAlgorithm
// without updating this list would silently under-advertise what the
// server actually accepts.
func TestMetadataAdvertisesEdDSAForDPoP(t *testing.T) {
	h := newSmokeHarness(t, AccessTokenFormatJWT)
	metadataURL := strings.TrimSuffix(h.authorize, "/authorize") + "/.well-known/openid-configuration"

	res, err := h.httpClient.Get(metadataURL)
	if err != nil {
		t.Fatalf("GET metadata: %v", err)
	}
	defer res.Body.Close()

	var doc struct {
		DPoPSigningAlgValuesSupported []string `json:"dpop_signing_alg_values_supported"`
	}
	if err := json.NewDecoder(res.Body).Decode(&doc); err != nil {
		t.Fatalf("decode metadata: %v", err)
	}

	for _, want := range []string{"ES256", "PS256", "EdDSA"} {
		found := false
		for _, got := range doc.DPoPSigningAlgValuesSupported {
			if got == want {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("dpop_signing_alg_values_supported = %v, want to contain %q", doc.DPoPSigningAlgValuesSupported, want)
		}
	}
}
