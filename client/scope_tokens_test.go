package client_test

import (
	"context"
	"errors"
	"testing"

	"github.com/idfoundry/fapigo/client"
)

// TestScopeElementsMustBeScopeTokens: Scope elements are joined with
// spaces on the wire, so one holding a space would send a scope the
// client's own checks never see — "profile openid" asks for openid
// while nothing then requires the ID token. Every grant refuses such an
// element, and an empty one, before sending anything (RFC 6749 §3.3).
func TestScopeElementsMustBeScopeTokens(t *testing.T) {
	bad := [][]string{{"profile openid"}, {"openid", ""}, {"a\tb"}, {`a"b`}, {`a\b`}, {"é"}}
	wantInvalidRequest := func(t *testing.T, what string, err error) {
		t.Helper()
		var cerr *client.Error
		if !errors.As(err, &cerr) || cerr.Code() != client.ErrorInvalidRequest {
			t.Errorf("%s = %v, want invalid_request", what, err)
		}
	}
	ctx := context.Background()

	c, as, _ := newTestClient(t, false)
	for _, scope := range bad {
		_, err := c.BeginAuthorization(ctx, client.BeginAuthorizationRequest{Scope: scope})
		wantInvalidRequest(t, "BeginAuthorization", err)
	}
	if as.lastPARForm != nil {
		t.Errorf("a PAR request was sent: %v", as.lastPARForm)
	}

	ciba, _, _ := newTestClientWithCIBA(t)
	for _, scope := range bad {
		_, err := ciba.BeginBackchannelAuthentication(ctx, client.BeginBackchannelAuthenticationRequest{Scope: scope, LoginHint: "sam"})
		wantInvalidRequest(t, "BeginBackchannelAuthentication", err)
	}

	cc, err := client.New(validConfig(t), validDependencies(t))
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}
	for _, scope := range bad {
		_, err := cc.RequestClientCredentialsToken(ctx, client.ClientCredentialsTokenRequest{Scope: scope})
		wantInvalidRequest(t, "RequestClientCredentialsToken", err)
	}

	// Each scope as its own element is fine.
	if _, err := c.BeginAuthorization(ctx, client.BeginAuthorizationRequest{Scope: []string{"openid", "profile", "a:b/c"}}); err != nil {
		t.Errorf("BeginAuthorization(separate elements) = %v", err)
	}
}
