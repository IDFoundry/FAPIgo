package client_test

import (
	"context"
	"errors"
	"fmt"
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
	return c, client.TokenSet{RefreshToken: fapi.NewSecret("rt-1"), HasRefreshToken: true, Issuer: cfg.Issuer.String()}
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

// signFailsKeyManager resolves its keys, so New accepts it, but fails
// to sign — a KMS that's down by the time a request needs it.
type signFailsKeyManager struct{ keys.KeyManager }

func (signFailsKeyManager) Sign(context.Context, keys.SigningRequest) (keys.Signature, error) {
	return keys.Signature{}, fmt.Errorf("signFailsKeyManager: key unavailable")
}

func TestRefreshTokensWithoutSigningKeys(t *testing.T) {
	c, tokens := refreshClient(t, `{}`, func(d *client.Dependencies) {
		d.Keys = signFailsKeyManager{d.Keys}
	})
	_, err := c.RefreshTokens(context.Background(), client.RefreshTokenRequest{Tokens: tokens})
	var cerr *client.Error
	if !errors.As(err, &cerr) || cerr.Code() != client.ErrorInternal {
		t.Fatalf("RefreshTokens(no client authentication key) = %v, want an internal error", err)
	}
}

// originalIDToken gives tokens an ID token for user-1 from this client's
// issuer, as ExchangeCode would have validated it.
func originalIDToken(tokens client.TokenSet, issuer string) client.TokenSet {
	tokens.IDToken, tokens.HasIDToken, tokens.Subject = fapi.NewSecret("original-id-token"), true, "user-1"
	tokens.IDTokenClaims = client.IDTokenClaims{Subject: "user-1", Issuer: issuer}
	return tokens
}

// TestRefreshTokensKeepsTheIDTokenWhenNoneIsReturned covers a refresh
// whose response has no ID token: the result keeps the original's, so a
// later refresh from it still checks a refreshed ID token against it
// (OIDC Core §12.2).
func TestRefreshTokensKeepsTheIDTokenWhenNoneIsReturned(t *testing.T) {
	c, tokens := refreshClient(t, `{"access_token":"at-2","token_type":"DPoP","expires_in":300}`, nil)
	tokens = originalIDToken(tokens, testIssuer)
	got, err := c.RefreshTokens(context.Background(), client.RefreshTokenRequest{Tokens: tokens})
	if err != nil {
		t.Fatalf("RefreshTokens: %v", err)
	}
	if !got.HasIDToken || got.IDToken.Reveal() != "original-id-token" || got.Subject != "user-1" || got.IDTokenClaims.Subject != "user-1" {
		t.Errorf("got ID token %q (%v), subject %q / %q; want the original's kept", got.IDToken.Reveal(), got.HasIDToken, got.Subject, got.IDTokenClaims.Subject)
	}
}

// TestRefreshTokensRefusesAnotherIssuersTokens covers a token set from a
// different issuer: refused before its refresh token is sent anywhere.
func TestRefreshTokensRefusesAnotherIssuersTokens(t *testing.T) {
	c, tokens := refreshClient(t, `{"access_token":"at-2","token_type":"DPoP","expires_in":300}`, nil)
	tokens = originalIDToken(tokens, "https://other-issuer.example.com")
	_, err := c.RefreshTokens(context.Background(), client.RefreshTokenRequest{Tokens: tokens})
	var cerr *client.Error
	if !errors.As(err, &cerr) || cerr.Code() != client.ErrorInvalidRequest {
		t.Fatalf("RefreshTokens(another issuer's tokens) = %v, want invalid_request", err)
	}
}

// TestRefreshTokensChecksTheTokenSetsIssuer: a set from another issuer,
// or one recording no issuer at all, is refused before anything is
// sent; a set without Issuer but with an ID token falls back to its iss.
func TestRefreshTokensChecksTheTokenSetsIssuer(t *testing.T) {
	c, base := refreshClient(t, `{"access_token":"at-2","token_type":"DPoP","expires_in":300}`, nil)
	for name, tc := range map[string]struct {
		mutate  func(*client.TokenSet)
		refused bool
	}{
		"this issuer":    {func(*client.TokenSet) {}, false},
		"another issuer": {func(s *client.TokenSet) { s.Issuer = "https://other.example.com" }, true},
		"no issuer":      {func(s *client.TokenSet) { s.Issuer = "" }, true},
		"legacy, ID token": {func(s *client.TokenSet) {
			s.Issuer = ""
			s.HasIDToken, s.IDTokenClaims.Issuer = true, base.Issuer
		}, false},
		"legacy, foreign ID token": {func(s *client.TokenSet) {
			s.Issuer = ""
			s.HasIDToken, s.IDTokenClaims.Issuer = true, "https://other.example.com"
		}, true},
	} {
		t.Run(name, func(t *testing.T) {
			tokens := base
			tc.mutate(&tokens)
			got, err := c.RefreshTokens(context.Background(), client.RefreshTokenRequest{Tokens: tokens})
			var cerr *client.Error
			if tc.refused {
				if !errors.As(err, &cerr) || cerr.Code() != client.ErrorInvalidRequest {
					t.Fatalf("RefreshTokens = %v, want invalid_request", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("RefreshTokens: %v", err)
			}
			if got.Issuer != base.Issuer {
				t.Errorf("refreshed Issuer = %q, want %q", got.Issuer, base.Issuer)
			}
		})
	}
}
