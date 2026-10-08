package client_test

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/idfoundry/fapigo/client"
)

// TestCompleteAuthorizationRequiresIDTokenForOpenID covers OIDC Core
// §3.1.3.3 on the client: a request for "openid" gets an ID token, and
// max_age is met only by one proving when the user authenticated. A
// token response without one is refused rather than completed with no
// authenticated subject.
func TestCompleteAuthorizationRequiresIDTokenForOpenID(t *testing.T) {
	for _, tc := range []struct {
		name      string
		scope     []string
		hasMaxAge bool
		omit      bool
		wantErr   bool
	}{
		{name: "openid, no ID token", scope: []string{"openid", "accounts"}, omit: true, wantErr: true},
		{name: "openid and max_age, no ID token", scope: []string{"openid", "accounts"}, hasMaxAge: true, omit: true, wantErr: true},
		{name: "no openid, no ID token", scope: []string{"accounts"}, omit: true},
		{name: "openid, ID token", scope: []string{"openid", "accounts"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, as, _ := newTestClient(t, false)
			as.omitIDToken = tc.omit
			as.idTokenAuthTime = time.Now()
			ctx := context.Background()
			session, err := c.BeginAuthorization(ctx, client.BeginAuthorizationRequest{Scope: tc.scope, HasMaxAge: tc.hasMaxAge, MaxAge: time.Hour})
			if err != nil {
				t.Fatalf("BeginAuthorization: %v", err)
			}
			result, err := c.CompleteAuthorization(ctx, client.AuthorizationCallback{
				RawQuery: as.callbackFor(t, session.Handle().String(), "auth-code-123", ""), Session: session.Handle(),
			})
			if tc.wantErr {
				var cerr *client.Error
				if !errors.As(err, &cerr) || cerr.Code() != client.ErrorInvalidResponse {
					t.Fatalf("CompleteAuthorization = %v, %v; want invalid_response", result, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("CompleteAuthorization: %v", err)
			}
		})
	}
}

// TestPollBackchannelAuthenticationRequiresIDTokenForOpenID is the CIBA
// counterpart: an approval for an "openid" request must carry an ID
// token.
func TestPollBackchannelAuthenticationRequiresIDTokenForOpenID(t *testing.T) {
	for name, tc := range map[string]struct {
		scope   []string
		wantErr bool
	}{
		"openid":    {[]string{"openid", "accounts"}, true},
		"no openid": {[]string{"accounts"}, false},
	} {
		t.Run(name, func(t *testing.T) {
			c, as, _ := newTestClientWithCIBA(t)
			session, err := c.BeginBackchannelAuthentication(context.Background(), client.BeginBackchannelAuthenticationRequest{
				Scope: tc.scope, LoginHint: "user@example.com",
			})
			if err != nil {
				t.Fatalf("BeginBackchannelAuthentication: %v", err)
			}
			// The session survives a restart with its requirement intact.
			sealer, err := client.NewBackchannelSessionSealer(c, [][]byte{bytes.Repeat([]byte{7}, 32)})
			if err != nil {
				t.Fatal(err)
			}
			sealed, err := sealer.Seal(session)
			if err != nil {
				t.Fatal(err)
			}
			restored, _, err := sealer.Open(sealed)
			if err != nil {
				t.Fatal(err)
			}
			as.tokenResponses = []cibaTokenResponse{{status: http.StatusOK, body: map[string]any{
				"access_token": "opaque-access-token", "token_type": "DPoP", "expires_in": 300, "scope": "accounts",
			}}}
			result, err := c.PollBackchannelAuthentication(context.Background(), restored)
			if tc.wantErr {
				var cerr *client.Error
				if !errors.As(err, &cerr) || cerr.Code() != client.ErrorInvalidResponse {
					t.Fatalf("PollBackchannelAuthentication = %v, %v; want invalid_response", result, err)
				}
				return
			}
			if _, ok := result.(client.BackchannelAuthenticationApproved); err != nil || !ok {
				t.Fatalf("PollBackchannelAuthentication = %T, %v; want approved", result, err)
			}
		})
	}
}

// TestBeginAuthorizationRefusesMaxAgeWithoutOpenID covers max_age's
// requirement up front: only an ID token's auth_time can meet it, so a
// request without "openid" is refused before the user reaches the
// authorization server.
func TestBeginAuthorizationRefusesMaxAgeWithoutOpenID(t *testing.T) {
	c, as, _ := newTestClient(t, false)
	_, err := c.BeginAuthorization(context.Background(), client.BeginAuthorizationRequest{Scope: []string{"accounts"}, HasMaxAge: true})
	var cerr *client.Error
	if !errors.As(err, &cerr) || cerr.Code() != client.ErrorInvalidRequest {
		t.Fatalf("BeginAuthorization(max_age, no openid) = %v, want invalid_request", err)
	}
	if as.lastPARForm != nil {
		t.Error("the request was pushed anyway")
	}
	if _, err := c.BeginAuthorization(context.Background(), client.BeginAuthorizationRequest{Scope: []string{"openid"}, HasMaxAge: true}); err != nil {
		t.Fatalf("BeginAuthorization(max_age, openid): %v", err)
	}
}
