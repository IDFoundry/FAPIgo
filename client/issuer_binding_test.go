package client_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/client"
)

// otherIssuer is a second authorization server in a multi-issuer
// application, which runs one Client per issuer.
const otherIssuer = "https://other-as.example"

// formRecorder is otherIssuer's authorization server: it records every
// form posted to its token and revocation endpoints, answering
// invalid_grant and 200.
type formRecorder struct {
	mu     sync.Mutex
	token  []url.Values
	revoke []url.Values
}

func (r *formRecorder) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, req *http.Request) {
		_ = req.ParseForm()
		r.mu.Lock()
		r.token = append(r.token, req.PostForm)
		r.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
	})
	mux.HandleFunc("/revoke", func(w http.ResponseWriter, req *http.Request) {
		_ = req.ParseForm()
		r.mu.Lock()
		r.revoke = append(r.revoke, req.PostForm)
		r.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	})
	return mux
}

func (r *formRecorder) requests() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.token) + len(r.revoke)
}

// newOtherIssuerClient is the application's Client for otherIssuer.
func newOtherIssuerClient(t *testing.T) (*client.Client, *formRecorder) {
	t.Helper()
	recorder := &formRecorder{}
	ts := httptest.NewServer(recorder.handler())
	t.Cleanup(ts.Close)
	cfg := validConfig(t)
	iss, err := fapi.ParseIssuerURL(otherIssuer)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Issuer = iss
	cfg.Endpoints = client.Endpoints{
		Token:      mustLoopbackEndpoint(t, ts.URL+"/token"),
		Revocation: mustLoopbackEndpoint(t, ts.URL+"/revoke"),
	}
	cfg.RedirectURI = ""
	deps := validDependencies(t)
	deps.HTTP = ts.Client()
	c, err := client.New(cfg, deps)
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}
	return c, recorder
}

func mustLoopbackEndpoint(t *testing.T, raw string) fapi.URL {
	t.Helper()
	u, err := fapi.ParseEndpointURL(raw, fapi.AllowLoopbackHTTP())
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// TestExchangeCodeRefusesAnotherClientsResponse: a
// ValidatedAuthorizationResponse is bound to the Client that validated
// it. Exchanged through another issuer's Client, its code, PKCE verifier
// and redirect URI would reach that issuer's token endpoint; it is
// refused before anything is sent. So is the zero value.
func TestExchangeCodeRefusesAnotherClientsResponse(t *testing.T) {
	ctx := context.Background()
	clientA, asA, _ := newTestClient(t, false)
	clientB, recorder := newOtherIssuerClient(t)

	session, err := clientA.BeginAuthorization(ctx, client.BeginAuthorizationRequest{Scope: []string{"openid", "accounts"}})
	if err != nil {
		t.Fatal(err)
	}
	result, err := clientA.HandleAuthorizationResponse(ctx, client.AuthorizationCallback{
		RawQuery: asA.callbackFor(t, session.Handle().String(), "code-for-a", ""),
		Session:  session.Handle(),
	})
	if err != nil {
		t.Fatal(err)
	}
	validated := result.(client.CallbackSuccess).Response

	for name, resp := range map[string]client.ValidatedAuthorizationResponse{
		"another issuer's": validated,
		"zero value":       {},
	} {
		var cerr *client.Error
		if _, err := clientB.ExchangeCode(ctx, resp); !errors.As(err, &cerr) || cerr.Code() != client.ErrorInvalidRequest {
			t.Errorf("ExchangeCode(%s response) = %v, want ErrorInvalidRequest", name, err)
		}
	}
	if n := recorder.requests(); n != 0 {
		t.Fatalf("the other issuer received %d requests: %v", n, recorder.token)
	}
	if _, err := clientA.ExchangeCode(ctx, validated); err != nil {
		t.Fatalf("ExchangeCode on the validating client: %v", err)
	}
}

// TestExchangeCodeRefusesAnotherClientIDsResponse: the binding names the
// client ID too, for an application with two registrations at one issuer.
func TestExchangeCodeRefusesAnotherClientIDsResponse(t *testing.T) {
	ctx := context.Background()
	clientA, asA, _ := newTestClient(t, false)
	other, _, _ := newTestClientWith(t, false, func(cfg *client.Config, _ *client.Dependencies) {
		cfg.ClientID = "another-client"
	})
	session, err := clientA.BeginAuthorization(ctx, client.BeginAuthorizationRequest{Scope: []string{"openid"}})
	if err != nil {
		t.Fatal(err)
	}
	result, err := clientA.HandleAuthorizationResponse(ctx, client.AuthorizationCallback{
		RawQuery: asA.callbackFor(t, session.Handle().String(), "code", ""),
		Session:  session.Handle(),
	})
	if err != nil {
		t.Fatal(err)
	}
	var cerr *client.Error
	if _, err := other.ExchangeCode(ctx, result.(client.CallbackSuccess).Response); !errors.As(err, &cerr) || cerr.Code() != client.ErrorInvalidRequest {
		t.Fatalf("ExchangeCode(another client ID's response) = %v, want ErrorInvalidRequest", err)
	}
}

// TestRevokeTokenThroughAnotherIssuersClient: issuer A's refresh token
// isn't posted to issuer B's revocation endpoint, as RefreshTokens
// doesn't post it to B's token endpoint.
func TestRevokeTokenThroughAnotherIssuersClient(t *testing.T) {
	ctx := context.Background()
	clientA, asA, _ := newTestClient(t, false)
	clientB, recorder := newOtherIssuerClient(t)

	session, err := clientA.BeginAuthorization(ctx, client.BeginAuthorizationRequest{Scope: []string{"openid", "accounts"}})
	if err != nil {
		t.Fatal(err)
	}
	res, err := clientA.CompleteAuthorization(ctx, client.AuthorizationCallback{
		RawQuery: asA.callbackFor(t, session.Handle().String(), "code", ""), Session: session.Handle(),
	})
	if err != nil {
		t.Fatal(err)
	}
	tokensA := res.(client.CompletionSuccess).Tokens
	if !tokensA.HasRefreshToken {
		t.Fatal("the fixture issued no refresh token")
	}
	var cerr *client.Error
	if err := clientB.RevokeToken(ctx, tokensA); !errors.As(err, &cerr) || cerr.Code() != client.ErrorInvalidRequest {
		t.Fatalf("RevokeToken(A's set) via B = %v, want ErrorInvalidRequest", err)
	}
	if n := recorder.requests(); n != 0 {
		t.Fatalf("the other issuer received %d requests: %v", n, recorder.revoke)
	}
}

// TestTokenSetSealerDoesNotRelabelAnIssuerlessSet: an issuer-less set
// (from storage that predates TokenSet.Issuer, perhaps another issuer's)
// can't be sealed by B's sealer, so Open never stamps B's issuer on it
// for RefreshTokens to send its refresh token to B.
func TestTokenSetSealerDoesNotRelabelAnIssuerlessSet(t *testing.T) {
	clientB, recorder := newOtherIssuerClient(t)
	legacy := client.TokenSet{
		AccessToken: fapi.NewSecret("a-access"), TokenType: "DPoP",
		RefreshToken: fapi.NewSecret("a-refresh"), HasRefreshToken: true,
	}
	sealer, err := client.NewTokenSetSealer(clientB, [][]byte{sealKey(1)})
	if err != nil {
		t.Fatal(err)
	}
	var cerr *client.Error
	if _, err := sealer.Seal(legacy, "user-42"); !errors.As(err, &cerr) || cerr.Code() != client.ErrorInvalidRequest {
		t.Fatalf("Seal(issuer-less) = %v, want ErrorInvalidRequest", err)
	}
	if n := recorder.requests(); n != 0 {
		t.Fatalf("the other issuer received %d requests", n)
	}
}

// TestClientCredentialsResourceRefusesAnotherIssuersToken: a
// ClientCredentialsTokenResult records its issuer, and another issuer's
// Client won't present its token.
func TestClientCredentialsResourceRefusesAnotherIssuersToken(t *testing.T) {
	clientB, _ := newOtherIssuerClient(t)
	rc := clientB.ClientCredentialsResource(client.ClientCredentialsTokenResult{AccessToken: fapi.NewSecret("at"), Issuer: testIssuer})
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://rs.example/api", nil)
	if err != nil {
		t.Fatal(err)
	}
	var cerr *client.Error
	if _, err := rc.Do(context.Background(), req); !errors.As(err, &cerr) || cerr.Code() != client.ErrorInvalidRequest {
		t.Fatalf("Do = %v, want ErrorInvalidRequest", err)
	}
}

// TestMisroutedCallbackLeavesTheSession: a callback routed to the Client
// for another issuer, over a shared session store, is refused by its
// "iss" before its session is consumed, so the right Client can still
// complete it.
func TestMisroutedCallbackLeavesTheSession(t *testing.T) {
	ctx := context.Background()
	sessions := newFakeSessionStore()
	share := func(_ *client.Config, deps *client.Dependencies) { deps.Sessions = sessions }
	clientA, asA, _ := newTestClientWith(t, false, share)
	clientB, _, _ := newTestClientWith(t, false, func(cfg *client.Config, deps *client.Dependencies) {
		share(cfg, deps)
		iss, err := fapi.ParseIssuerURL(otherIssuer)
		if err != nil {
			t.Fatal(err)
		}
		cfg.Issuer = iss
	})

	session, err := clientA.BeginAuthorization(ctx, client.BeginAuthorizationRequest{Scope: []string{"openid"}})
	if err != nil {
		t.Fatal(err)
	}
	cb := client.AuthorizationCallback{
		RawQuery: asA.callbackFor(t, session.Handle().String(), "code", ""),
		Session:  session.Handle(),
	}
	if _, err := clientB.HandleAuthorizationResponse(ctx, cb); err == nil {
		t.Fatal("the other issuer's client accepted the callback")
	}
	if _, err := clientA.HandleAuthorizationResponse(ctx, cb); err != nil {
		t.Fatalf("the right client, after the misrouted callback: %v", err)
	}
}

// TestCallbackRefusedByAnotherClientAtTheSameIssuer: a session is bound
// to the client ID that began it, not just its issuer. A plain-mode
// callback routed to another Client for the same issuer, over a shared
// session store, carries nothing naming the client, so it gets as far
// as the session and is refused there, rather than completed with the
// other client's PKCE verifier and nonce.
func TestCallbackRefusedByAnotherClientAtTheSameIssuer(t *testing.T) {
	ctx := context.Background()
	sessions := newFakeSessionStore()
	clientA, asA, _ := newTestClientWith(t, false, func(_ *client.Config, deps *client.Dependencies) { deps.Sessions = sessions })
	clientB, _, _ := newTestClientWith(t, false, func(cfg *client.Config, deps *client.Dependencies) {
		deps.Sessions = sessions
		cfg.ClientID = "other-client-same-issuer"
	})

	session, err := clientA.BeginAuthorization(ctx, client.BeginAuthorizationRequest{Scope: []string{"openid"}})
	if err != nil {
		t.Fatal(err)
	}
	cb := client.AuthorizationCallback{
		RawQuery: asA.callbackFor(t, session.Handle().String(), "code", ""),
		Session:  session.Handle(),
	}
	var cerr *client.Error
	if res, err := clientB.HandleAuthorizationResponse(ctx, cb); !errors.As(err, &cerr) || cerr.Code() != client.ErrorInvalidRequest {
		t.Fatalf("another client's HandleAuthorizationResponse = %T, %v; want ErrorInvalidRequest", res, err)
	}
}

// TestPollBackchannelAuthenticationRefusesAnotherClientsSession: a
// BackchannelAuthenticationSession is bound to the Client that began it.
// Polled through another issuer's Client, its auth_req_id and that
// client's authentication would reach the other issuer's token endpoint;
// it is refused before anything is sent. So is the zero value, and
// sealing it with another Client's sealer.
func TestPollBackchannelAuthenticationRefusesAnotherClientsSession(t *testing.T) {
	ctx := context.Background()
	clientA, asA, _ := newTestClientWithCIBA(t)
	clientB, recorder := newOtherIssuerClient(t)
	session := beginTestBackchannelSession(t, clientA)

	var cerr *client.Error
	if _, err := clientB.PollBackchannelAuthentication(ctx, session); !errors.As(err, &cerr) || cerr.Code() != client.ErrorInvalidRequest {
		t.Fatalf("PollBackchannelAuthentication(A's session) via B = %v, want ErrorInvalidRequest", err)
	}
	if _, err := clientA.PollBackchannelAuthentication(ctx, client.BackchannelAuthenticationSession{}); !errors.As(err, &cerr) || cerr.Code() != client.ErrorInvalidRequest {
		t.Fatalf("PollBackchannelAuthentication(zero session) = %v, want ErrorInvalidRequest", err)
	}
	sealerB, err := client.NewBackchannelSessionSealer(clientB, [][]byte{sealKey(1)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sealerB.Seal(session, "user-1"); !errors.As(err, &cerr) || cerr.Code() != client.ErrorInvalidRequest {
		t.Fatalf("Seal(A's session) with B's sealer = %v, want ErrorInvalidRequest", err)
	}
	if n := recorder.requests(); n != 0 {
		t.Fatalf("the other issuer received %d requests: %v", n, recorder.token)
	}

	// Through A, and through A's sealer, it polls as before.
	sealerA, err := client.NewBackchannelSessionSealer(clientA, [][]byte{sealKey(1)})
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := sealerA.Seal(session, "user-1")
	if err != nil {
		t.Fatalf("Seal with A's sealer: %v", err)
	}
	opened, _, err := sealerA.Open(sealed, "user-1")
	if err != nil {
		t.Fatalf("Open with A's sealer: %v", err)
	}
	asA.tokenResponses = []cibaTokenResponse{{status: http.StatusBadRequest, body: map[string]any{"error": "authorization_pending"}}}
	if _, err := clientA.PollBackchannelAuthentication(ctx, opened); err != nil {
		t.Fatalf("PollBackchannelAuthentication(opened session) via A: %v", err)
	}
}
