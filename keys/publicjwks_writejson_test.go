package keys_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/keys/ephemeral"
)

func TestPublicKeySetWriteJSON(t *testing.T) {
	signer, err := ephemeral.GenerateSigner(fapi.ES256)
	if err != nil {
		t.Fatal(err)
	}
	manager, err := keys.NewKeyManagerFromSigners(
		[]keys.SignerSpec{
			{Purpose: keys.IDTokenSigning, Algorithm: fapi.ES256, Signer: signer, KeyID: "kid-1"},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	set, err := keys.PublicJWKS(context.Background(), []keys.SigningKeyUse{{Manager: manager, Purpose: keys.IDTokenSigning, Algorithm: fapi.ES256}}, nil)
	if err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	set.WriteJSON(rec)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", got)
	}
	if got := rec.Header().Get("Cache-Control"); got != "" {
		t.Errorf("Cache-Control = %q, want none: a JWKS is meant to be cached", got)
	}
	var body struct {
		Keys []struct {
			KeyID string `json:"kid"`
			Kty   string `json:"kty"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("body isn't a JWK Set: %v", err)
	}
	if len(body.Keys) != 1 || body.Keys[0].KeyID != "kid-1" || body.Keys[0].Kty != "EC" {
		t.Errorf("body = %s, want the one EC key kid-1", rec.Body)
	}
}

func TestPublicKeySetWriteJSONUnencodable(t *testing.T) {
	rec := httptest.NewRecorder()
	keys.PublicKeySet{Keys: []keys.PublicJWK{{}}}.WriteJSON(rec)
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500 for a key set that can't be encoded", rec.Code)
	}
}
