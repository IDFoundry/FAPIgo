package client_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/client"
)

// TestRevokeTokenAttestationRequest covers the request an attested
// client sends: the token with a refresh_token hint, the attestation
// headers (checked by the fixture), and no DPoP proof.
func TestRevokeTokenAttestationRequest(t *testing.T) {
	c, as := newTestClientWithAttestationAuth(t)
	if err := c.RevokeToken(context.Background(), fapi.NewSecret("rt-1")); err != nil {
		t.Fatalf("RevokeToken: %v", err)
	}
	if as.lastRevokeForm.Get("token") != "rt-1" || as.lastRevokeForm.Get("token_type_hint") != "refresh_token" {
		t.Errorf("form = %v, want token rt-1 with the refresh_token hint", as.lastRevokeForm)
	}
	if as.lastRevokeHeaders.Get("DPoP") != "" {
		t.Error("revocation request carried a DPoP proof")
	}
}

func TestRevokeTokenNotSupported(t *testing.T) {
	c, err := client.New(validConfig(t), validDependencies(t))
	if err != nil {
		t.Fatal(err)
	}
	err = c.RevokeToken(context.Background(), fapi.NewSecret("rt-1"))
	var cerr *client.Error
	if !errors.As(err, &cerr) || cerr.Code() != client.ErrorRevocationNotSupported {
		t.Fatalf("RevokeToken without Endpoints.Revocation = %v, want ErrorRevocationNotSupported", err)
	}
}

func TestRevokeTokenRefusesEmptyToken(t *testing.T) {
	c, _ := newTestClientWithAttestationAuth(t)
	var cerr *client.Error
	if err := c.RevokeToken(context.Background(), fapi.Secret{}); !errors.As(err, &cerr) || cerr.Code() != client.ErrorInvalidRequest {
		t.Fatalf("RevokeToken(empty) = %v, want ErrorInvalidRequest", err)
	}
}

// TestRevokeTokenServerError covers an error response: ErrorInvalidResponse
// carrying the server's error.
func TestRevokeTokenServerError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "unsupported_token_type"})
	}))
	t.Cleanup(ts.Close)
	cfg := validConfig(t)
	revokeURL, err := fapi.ParseEndpointURL(ts.URL+"/revoke", fapi.AllowLoopbackHTTP())
	if err != nil {
		t.Fatal(err)
	}
	cfg.Endpoints.Revocation = revokeURL
	deps := validDependencies(t)
	deps.HTTP = ts.Client()
	c, err := client.New(cfg, deps)
	if err != nil {
		t.Fatal(err)
	}
	err = c.RevokeToken(context.Background(), fapi.NewSecret("rt-1"))
	var cerr *client.Error
	if !errors.As(err, &cerr) || cerr.Code() != client.ErrorInvalidResponse {
		t.Fatalf("RevokeToken = %v, want ErrorInvalidResponse", err)
	}
	if resp, ok := cerr.ServerResponse(); !ok || resp.Code != "unsupported_token_type" {
		t.Errorf("ServerResponse() = %+v, %v", resp, ok)
	}
}

// TestMTLSAliasesApplyToRevocation covers a SenderConstrainMTLS client
// using the server's mTLS alias for the revocation endpoint.
func TestMTLSAliasesApplyToRevocation(t *testing.T) {
	plain, _ := fapi.ParseEndpointURL("https://as.example/revoke")
	alias, _ := fapi.ParseEndpointURL("https://mtls.as.example/revoke")
	endpoints := client.Endpoints{Revocation: plain}
	aliases := &client.MTLSEndpoints{Revocation: alias}
	if !aliases.ApplyForSenderConstrain(&endpoints) || endpoints.Revocation.String() != alias.String() {
		t.Errorf("Revocation = %q, want the mTLS alias %q", endpoints.Revocation.String(), alias.String())
	}
}
