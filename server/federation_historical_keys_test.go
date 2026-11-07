package server_test

import (
	"context"
	"strings"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/federation"
	intfed "github.com/idfoundry/fapigo/internal/federation"
	"github.com/idfoundry/fapigo/server"
)

func TestServerHistoricalKeys(t *testing.T) {
	federationKey := generateKey(t)
	deps := validDependencies()
	deps.Keys = &fakeKeyManager{key: generateKey(t), keyID: "as-kid", federationKey: federationKey}
	srv, err := server.New(federationConfiguredConfig(t), deps)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	retired := generateKey(t)
	now := time.Now()
	token, err := srv.HistoricalKeys(context.Background(), []federation.HistoricalKeyParams{{
		KeyID: "retired-fed-kid", Algorithm: fapi.ES256, PublicKey: &retired.PublicKey, ExpiresAt: now.Add(-time.Hour),
		Revoked: &federation.KeyRevocation{RevokedAt: now.Add(-time.Minute), Reason: federation.KeyRevocationReasonSuperseded},
	}})
	if err != nil {
		t.Fatalf("HistoricalKeys: %v", err)
	}

	resp, err := intfed.ParseHistoricalKeysResponse(token)
	if err != nil {
		t.Fatalf("ParseHistoricalKeysResponse: %v", err)
	}
	if resp.KeyID() != "fed-as-kid" {
		t.Errorf("kid = %q, want the federation signing key's", resp.KeyID())
	}
	claims, err := resp.Verify(&federationKey.PublicKey, intfed.HistoricalKeysVerifyPolicy{
		ExpectedIssuer: testIssuer, Algorithm: fapi.ES256, Now: time.Now(), MaxClockSkew: time.Minute,
	})
	if err != nil {
		t.Fatalf("Verify(against the federation key): %v", err)
	}
	if len(claims.Keys) != 1 || claims.Keys[0].KeyID != "retired-fed-kid" || claims.Keys[0].Revoked == nil {
		t.Errorf("Keys = %+v", claims.Keys)
	}
}

func TestServerHistoricalKeysRequiresFederationConfig(t *testing.T) {
	srv, err := server.New(validConfig(t), validDependencies())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := srv.HistoricalKeys(context.Background(), nil); err == nil {
		t.Fatalf("HistoricalKeys(federation not configured) = nil error, want error")
	}
}

// TestServerHistoricalKeysRefusesPublishedFederationKeys covers both
// keys a rotating key manager still publishes in the Entity
// Configuration's jwks: neither is historical yet.
func TestServerHistoricalKeysRefusesPublishedFederationKeys(t *testing.T) {
	outgoing, newest := generateKey(t), generateKey(t)
	deps := validDependencies()
	deps.Keys = &rotatingKeyManager{
		outgoing: &fakeKeyManager{key: generateKey(t), keyID: "old", federationKey: outgoing},
		newest:   &fakeKeyManager{key: generateKey(t), keyID: "new", federationKey: newest},
	}
	srv, err := server.New(federationConfiguredConfig(t), deps)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for name, k := range map[string]federation.HistoricalKeyParams{
		"outgoing": {KeyID: "renamed-old", Algorithm: fapi.ES256, PublicKey: &outgoing.PublicKey, ExpiresAt: time.Now()},
		"newest":   {KeyID: "renamed-new", Algorithm: fapi.ES256, PublicKey: &newest.PublicKey, ExpiresAt: time.Now()},
	} {
		if _, err := srv.HistoricalKeys(context.Background(), []federation.HistoricalKeyParams{k}); err == nil || !strings.Contains(err.Error(), "kid \"renamed-") {
			t.Errorf("HistoricalKeys(%s federation key) = %v, want refused", name, err)
		}
	}
}
