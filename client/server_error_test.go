package client_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/client"
	"github.com/idfoundry/fapigo/storage"
)

func serverResponseOf(t *testing.T, err error) (client.ServerErrorResponse, bool) {
	t.Helper()
	var cerr *client.Error
	if !errors.As(err, &cerr) {
		t.Fatalf("error = %v (%T), want *client.Error", err, err)
	}
	return cerr.ServerResponse()
}

func newPARErrorTestClient(t *testing.T, handler http.HandlerFunc) *client.Client {
	t.Helper()
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)
	cfg := validConfig(t)
	parURL, err := fapi.ParseEndpointURL(ts.URL+"/par", fapi.AllowLoopbackHTTP())
	if err != nil {
		t.Fatalf("ParseEndpointURL(par): %v", err)
	}
	cfg.Endpoints.PushedAuthorizationRequest = parURL
	deps := validDependencies(t)
	deps.HTTP = ts.Client()
	c, err := client.New(cfg, deps)
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}
	return c
}

func beginAuthorizationError(t *testing.T, c *client.Client) error {
	t.Helper()
	_, err := c.BeginAuthorization(context.Background(), client.BeginAuthorizationRequest{Scope: []string{"openid"}})
	if err == nil {
		t.Fatal("BeginAuthorization = nil error, want error")
	}
	return err
}

func TestPARErrorExposesServerResponse(t *testing.T) {
	c := newPARErrorTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":             "invalid_client",
			"error_description": "client authentication failed",
			"error_uri":         "https://as.example.com/errors#invalid_client",
		})
	})
	err := beginAuthorizationError(t, c)
	got, ok := serverResponseOf(t, err)
	want := client.ServerErrorResponse{
		Code:        "invalid_client",
		Description: "client authentication failed",
		URI:         "https://as.example.com/errors#invalid_client",
		HTTPStatus:  http.StatusUnauthorized,
	}
	if !ok || got != want {
		t.Fatalf("ServerResponse() = %+v, %v, want %+v", got, ok, want)
	}
	// Error text, Code and PublicDescription are unchanged by the addition.
	if msg := err.Error(); msg != "client: invalid_response: client authentication failed: authorization server error: invalid_client" {
		t.Errorf("Error() = %q", msg)
	}
	var cerr *client.Error
	errors.As(err, &cerr)
	if cerr.Code() != client.ErrorInvalidResponse || cerr.PublicDescription() != "client authentication failed" {
		t.Errorf("Code/PublicDescription = %q/%q", cerr.Code(), cerr.PublicDescription())
	}
}

func TestPARNonOAuthErrorBodyExposesStatusOnly(t *testing.T) {
	c := newPARErrorTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusBadGateway)
		// A proxy's error page that echoes the request it refused.
		_, _ = w.Write([]byte("<html>502 Bad Gateway: client_assertion=eyJSECRET</html>"))
	})
	err := beginAuthorizationError(t, c)
	got, ok := serverResponseOf(t, err)
	if !ok || got != (client.ServerErrorResponse{HTTPStatus: http.StatusBadGateway}) {
		t.Fatalf("ServerResponse() = %+v, %v, want status 502 only", got, ok)
	}
	// The body never reaches Error(): it may echo the request's secrets.
	if msg := err.Error(); strings.Contains(msg, "SECRET") || strings.Contains(msg, "html") || !strings.Contains(msg, "HTTP 502") {
		t.Errorf("Error() = %q, want the status and no body", msg)
	}
}

func TestPARErrorDropsFieldsOutsideRFC6749CharacterSet(t *testing.T) {
	c := newPARErrorTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":             "invalid\nclient",
			"error_description": "call \"support\" now",
			"error_uri":         "https://as.example.com/a b",
		})
	})
	err := beginAuthorizationError(t, c)
	got, ok := serverResponseOf(t, err)
	if !ok || got != (client.ServerErrorResponse{HTTPStatus: http.StatusBadRequest}) {
		t.Fatalf("ServerResponse() = %+v, %v, want every malformed field dropped", got, ok)
	}
	var cerr *client.Error
	errors.As(err, &cerr)
	if cerr.PublicDescription() != "" {
		t.Errorf("PublicDescription() = %q, want the malformed description dropped", cerr.PublicDescription())
	}
	if msg := err.Error(); msg != `client: invalid_response: : authorization server error: "invalid\nclient"` {
		t.Errorf("Error() = %q, want the malformed code quoted", msg)
	}
}

func TestTransportFailureHasNoServerResponse(t *testing.T) {
	deps := validDependencies(t)
	deps.HTTP = &trackingHTTPClient{} // returns no response
	cfg := validConfig(t)
	parURL, _ := fapi.ParseEndpointURL("http://127.0.0.1:1/par", fapi.AllowLoopbackHTTP())
	cfg.Endpoints.PushedAuthorizationRequest = parURL
	c, err := client.New(cfg, deps)
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}
	if got, ok := serverResponseOf(t, beginAuthorizationError(t, c)); ok {
		t.Fatalf("ServerResponse() = %+v, true, want false for a transport failure", got)
	}
}

func TestTokenErrorExposesServerResponse(t *testing.T) {
	c, as, _ := newTestClient(t, false)
	as.rejectTokenRequestPlain = true
	ctx := context.Background()
	session, err := c.BeginAuthorization(ctx, client.BeginAuthorizationRequest{Scope: []string{"openid", "accounts"}})
	if err != nil {
		t.Fatalf("BeginAuthorization: %v", err)
	}
	rawQuery := as.callbackFor(t, session.Handle().String(), "auth-code-123", "")
	_, err = c.CompleteAuthorization(ctx, client.AuthorizationCallback{RawQuery: rawQuery, Session: session.Handle()})
	if err == nil {
		t.Fatal("CompleteAuthorization = nil error, want error")
	}
	got, ok := serverResponseOf(t, err)
	want := client.ServerErrorResponse{Code: "invalid_grant", Description: "test: rejected without a DPoP-nonce challenge", HTTPStatus: http.StatusBadRequest}
	if !ok || got != want {
		t.Fatalf("ServerResponse() = %+v, %v, want %+v", got, ok, want)
	}
}

func TestBackchannelAuthenticationErrorExposesServerResponse(t *testing.T) {
	c, as, _ := newTestClientWithCIBA(t)
	as.rejectBCRequestPlain = true
	_, err := c.BeginBackchannelAuthentication(context.Background(), client.BeginBackchannelAuthenticationRequest{
		Scope: []string{"openid"}, LoginHint: "user@example.com",
	})
	if err == nil {
		t.Fatal("BeginBackchannelAuthentication = nil error, want error")
	}
	got, ok := serverResponseOf(t, err)
	want := client.ServerErrorResponse{Code: "invalid_client", Description: "test: rejected without a DPoP-nonce challenge", HTTPStatus: http.StatusBadRequest}
	if !ok || got != want {
		t.Fatalf("ServerResponse() = %+v, %v, want %+v", got, ok, want)
	}
}

func userInfoError(t *testing.T, mtls bool, handler http.HandlerFunc) (client.ServerErrorResponse, bool) {
	t.Helper()
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)
	var mutate func(*client.Config)
	if mtls {
		mutate = func(cfg *client.Config) { cfg.SenderConstrain = storage.SenderConstrainMTLS }
	}
	c := newUserInfoTestClient(t, ts, nil, mutate, nil)
	_, err := c.FetchUserInfo(context.Background(), userInfoTestTokens())
	if err == nil {
		t.Fatal("FetchUserInfo = nil error, want error")
	}
	return serverResponseOf(t, err)
}

func TestUserInfoErrorFromChallenge(t *testing.T) {
	got, ok := userInfoError(t, false, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Add("WWW-Authenticate", `Bearer error="ignored_for_dpop"`)
		w.Header().Add("WWW-Authenticate", `DPoP algs="ES256", error="invalid_token", error_description="token, expired", error_uri="https://rs.example.com/e"`)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "body_is_ignored"})
	})
	want := client.ServerErrorResponse{Code: "invalid_token", Description: "token, expired", URI: "https://rs.example.com/e", HTTPStatus: http.StatusUnauthorized}
	if !ok || got != want {
		t.Fatalf("ServerResponse() = %+v, %v, want %+v", got, ok, want)
	}
}

func TestUserInfoErrorFromBearerChallengeUnderMTLS(t *testing.T) {
	got, ok := userInfoError(t, true, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("WWW-Authenticate", `Bearer error="insufficient_scope"`)
		w.WriteHeader(http.StatusForbidden)
	})
	if !ok || got != (client.ServerErrorResponse{Code: "insufficient_scope", HTTPStatus: http.StatusForbidden}) {
		t.Fatalf("ServerResponse() = %+v, %v", got, ok)
	}
}

func TestUserInfoErrorFallsBackToJSONBody(t *testing.T) {
	for name, challenge := range map[string]string{
		"no challenge":           "",
		"challenge has no error": `DPoP algs="ES256"`,
		"other scheme only":      `Bearer error="invalid_token"`,
		"malformed challenge":    `DPoP error="unterminated`,
	} {
		t.Run(name, func(t *testing.T) {
			got, ok := userInfoError(t, false, func(w http.ResponseWriter, _ *http.Request) {
				if challenge != "" {
					w.Header().Set("WWW-Authenticate", challenge)
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_request", "error_description": "no data for this user"})
			})
			want := client.ServerErrorResponse{Code: "invalid_request", Description: "no data for this user", HTTPStatus: http.StatusBadRequest}
			if !ok || got != want {
				t.Fatalf("ServerResponse() = %+v, %v, want %+v", got, ok, want)
			}
		})
	}
}

func TestUserInfoNonOAuthErrorExposesStatusOnly(t *testing.T) {
	got, ok := userInfoError(t, false, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("<html>down</html>"))
	})
	if !ok || got != (client.ServerErrorResponse{HTTPStatus: http.StatusServiceUnavailable}) {
		t.Fatalf("ServerResponse() = %+v, %v, want status 503 only", got, ok)
	}
}

func TestUserInfoValidationFailureHasNoServerResponse(t *testing.T) {
	got, ok := userInfoError(t, false, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("hello"))
	})
	if ok {
		t.Fatalf("ServerResponse() = %+v, true, want false for a rejected 200 response", got)
	}
}

func TestCallbackDeniedEnforcesErrorCharacterSet(t *testing.T) {
	cases := map[string]struct {
		code, description string
		wantErr           bool
		wantDescription   string
	}{
		"well-formed":           {"access_denied", "user cancelled", false, "user cancelled"},
		"malformed description": {"access_denied", "café", false, ""},
		"malformed code":        {"access\"denied", "x", true, ""},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			c, as, _ := newTestClient(t, false)
			ctx := context.Background()
			session, err := c.BeginAuthorization(ctx, client.BeginAuthorizationRequest{Scope: []string{"openid", "accounts"}})
			if err != nil {
				t.Fatalf("BeginAuthorization: %v", err)
			}
			q := url.Values{}
			q.Set("state", session.Handle().String())
			q.Set("error", tc.code)
			q.Set("error_description", tc.description)
			q.Set("iss", as.issuer)
			result, err := c.HandleAuthorizationResponse(ctx, client.AuthorizationCallback{RawQuery: q.Encode(), Session: session.Handle()})
			if tc.wantErr {
				if err == nil {
					t.Fatalf("HandleAuthorizationResponse = %#v, want error", result)
				}
				return
			}
			denied, ok := result.(client.CallbackDenied)
			if err != nil || !ok || denied.Code != tc.code || denied.Description != tc.wantDescription {
				t.Fatalf("HandleAuthorizationResponse = %#v, %v", result, err)
			}
		})
	}
}
