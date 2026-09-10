package client_test

import (
	"context"
	"errors"
	"testing"

	"github.com/idfoundry/fapigo/client"
)

// TestRequestClientCredentialsTokenRejectsEmptyScope confirms an empty
// scope is rejected locally, before any network call — the server
// (server.RequestClientCredentialsToken) always requires at least one,
// so this would otherwise fail only after a wasted round trip.
func TestRequestClientCredentialsTokenRejectsEmptyScope(t *testing.T) {
	c, err := client.New(validConfig(t), validDependencies(t))
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}
	_, err = c.RequestClientCredentialsToken(context.Background(), client.ClientCredentialsTokenRequest{})
	if err == nil {
		t.Fatalf("RequestClientCredentialsToken(empty scope) = nil error, want error")
	}
	var cerr *client.Error
	if !errors.As(err, &cerr) {
		t.Fatalf("error is not *client.Error: %v", err)
	}
	if cerr.Code() != client.ErrorInvalidRequest {
		t.Errorf("Code() = %q, want %q", cerr.Code(), client.ErrorInvalidRequest)
	}
}
