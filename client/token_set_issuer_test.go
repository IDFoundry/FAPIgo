package client_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/idfoundry/fapigo/client"
)

// TestTokenSetFromAnotherIssuerIsRefused: a multi-issuer application
// holds token sets from several authorization servers. FetchUserInfo
// and ProtectedResource refuse one another issuer issued, sending
// nothing, as RefreshTokens already did; ProtectedResource uses a set
// built by hand that records no issuer as given.
func TestTokenSetFromAnotherIssuerIsRefused(t *testing.T) {
	var hits atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"sub": userInfoTestSubject})
	}))
	defer ts.Close()
	c := newUserInfoTestClient(t, ts, nil, nil, nil)
	ctx := context.Background()
	wantInvalidRequest := func(what string, err error) {
		t.Helper()
		var cerr *client.Error
		if !errors.As(err, &cerr) || cerr.Code() != client.ErrorInvalidRequest {
			t.Errorf("%s = %v, want invalid_request", what, err)
		}
	}

	other := userInfoTestTokens()
	other.Issuer = "https://other-as.example.com"
	otherIDToken := userInfoTestTokens()
	otherIDToken.IDTokenClaims.Issuer = "https://other-as.example.com"
	for name, tokens := range map[string]client.TokenSet{"other issuer": other, "other ID token issuer": otherIDToken} {
		_, err := c.FetchUserInfo(ctx, tokens)
		wantInvalidRequest("FetchUserInfo("+name+")", err)
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/userinfo", nil)
		_, err = c.ProtectedResource(tokens).Do(ctx, req)
		wantInvalidRequest("ProtectedResource("+name+").Do", err)
	}
	if n := hits.Load(); n != 0 {
		t.Fatalf("%d requests were sent, want none", n)
	}

	if _, err := c.FetchUserInfo(ctx, userInfoTestTokens()); err != nil {
		t.Errorf("FetchUserInfo(this issuer's tokens) = %v", err)
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/userinfo", nil)
	res, err := c.ProtectedResource(client.TokenSet{AccessToken: userInfoTestTokens().AccessToken}).Do(ctx, req)
	if err != nil {
		t.Fatalf("ProtectedResource(no issuer recorded).Do = %v", err)
	}
	_ = res.Body.Close()
}
