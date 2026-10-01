package client_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/client"
	"github.com/idfoundry/fapigo/keys"
)

// refreshClient is an OAuthOnly test client whose token endpoint answers
// every request with body, and the token set it refreshes.
func refreshClient(t *testing.T, body string, deps func(*client.Dependencies)) (*client.Client, client.TokenSet) {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil || r.PostForm.Get("grant_type") != "refresh_token" || r.PostForm.Get("refresh_token") != "rt-1" {
			t.Errorf("token request form = %v, want a refresh_token grant for rt-1", r.PostForm)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(ts.Close)
	cfg, d := validConfig(t), validDependencies(t)
	oauthOnly(&cfg, &d)
	token, err := fapi.ParseEndpointURL(ts.URL+"/token", fapi.AllowLoopbackHTTP())
	if err != nil {
		t.Fatal(err)
	}
	cfg.Endpoints, cfg.RedirectURI, d.Sessions = client.Endpoints{Token: token}, "", nil
	d.HTTP = ts.Client()
	if deps != nil {
		deps(&d)
	}
	c, err := client.New(cfg, d)
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}
	return c, client.TokenSet{RefreshToken: fapi.NewSecret("rt-1"), HasRefreshToken: true}
}

func TestRefreshTokensKeepsTheRefreshTokenWhenNoneIsReturned(t *testing.T) {
	c, tokens := refreshClient(t, `{"access_token":"at-2","token_type":"DPoP","expires_in":300}`, nil)
	got, err := c.RefreshTokens(context.Background(), client.RefreshTokenRequest{Tokens: tokens})
	if err != nil {
		t.Fatalf("RefreshTokens: %v", err)
	}
	if got.AccessToken.Reveal() != "at-2" || !got.HasRefreshToken || got.RefreshToken.Reveal() != "rt-1" {
		t.Errorf("got access %q, refresh %q (%v); want at-2 and the original rt-1", got.AccessToken.Reveal(), got.RefreshToken.Reveal(), got.HasRefreshToken)
	}
}

func TestRefreshTokensRejectsMalformedResponse(t *testing.T) {
	c, tokens := refreshClient(t, `{"access_token":`, nil)
	_, err := c.RefreshTokens(context.Background(), client.RefreshTokenRequest{Tokens: tokens})
	var cerr *client.Error
	if !errors.As(err, &cerr) || cerr.Code() != client.ErrorInvalidResponse {
		t.Fatalf("RefreshTokens(malformed response) = %v, want invalid_response", err)
	}
}

func TestRefreshTokensWithoutSigningKeys(t *testing.T) {
	c, tokens := refreshClient(t, `{}`, func(d *client.Dependencies) {
		d.Keys = newFakeKeyManager(t, keys.DPoPProofSigning) // no client authentication key
	})
	_, err := c.RefreshTokens(context.Background(), client.RefreshTokenRequest{Tokens: tokens})
	var cerr *client.Error
	if !errors.As(err, &cerr) || cerr.Code() != client.ErrorInternal {
		t.Fatalf("RefreshTokens(no client authentication key) = %v, want an internal error", err)
	}
}
