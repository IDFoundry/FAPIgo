package client_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/client"
)

// assertNamesAlgorithms checks err is invalid_response naming both the
// algorithm the server signed with and the configured one, and the
// Config field to change.
func assertNamesAlgorithms(t *testing.T, err error, want string) {
	t.Helper()
	var cerr *client.Error
	if !errors.As(err, &cerr) || cerr.Code() != client.ErrorInvalidResponse {
		t.Fatalf("err = %v, want invalid_response", err)
	}
	if !strings.Contains(err.Error(), want) {
		t.Errorf("err = %v, want it to say %q", err, want)
	}
}

// TestCompleteAuthorizationNamesIDTokenAlgorithmMismatch: an ID token
// signed with another algorithm than Config.Algorithms.IDToken is
// refused, saying which setting to change rather than that no issuer
// key matched.
func TestCompleteAuthorizationNamesIDTokenAlgorithmMismatch(t *testing.T) {
	c, as, _ := newTestClientWith(t, false, func(cfg *client.Config, _ *client.Dependencies) {
		cfg.Algorithms.IDToken = fapi.PS256
	})
	ctx := context.Background()
	session, err := c.BeginAuthorization(ctx, client.BeginAuthorizationRequest{Scope: []string{"openid", "accounts"}})
	if err != nil {
		t.Fatalf("BeginAuthorization: %v", err)
	}
	_, err = c.CompleteAuthorization(ctx, client.AuthorizationCallback{
		RawQuery: as.callbackFor(t, session.Handle().String(), "auth-code-123", ""), Session: session.Handle(),
	})
	assertNamesAlgorithms(t, err, "ID token is signed with ES256, but Config.Algorithms.IDToken is PS256")
}

// TestCompleteAuthorizationNamesJARMAlgorithmMismatch is the JARM
// counterpart, for Config.Algorithms.JARM.
func TestCompleteAuthorizationNamesJARMAlgorithmMismatch(t *testing.T) {
	c, as, _ := newTestClientWith(t, true, func(cfg *client.Config, _ *client.Dependencies) {
		cfg.Algorithms.JARM = fapi.PS256
	})
	ctx := context.Background()
	session, err := c.BeginAuthorization(ctx, client.BeginAuthorizationRequest{Scope: []string{"openid", "accounts"}})
	if err != nil {
		t.Fatalf("BeginAuthorization: %v", err)
	}
	_, err = c.CompleteAuthorization(ctx, client.AuthorizationCallback{
		RawQuery: as.callbackFor(t, session.Handle().String(), "auth-code-123", ""), Session: session.Handle(),
	})
	assertNamesAlgorithms(t, err, "authorization response is signed with ES256, but Config.Algorithms.JARM is PS256")
}

// TestFetchUserInfoNamesAlgorithmMismatch is the signed UserInfo
// counterpart, for Config.Algorithms.UserInfo; VerifyIssuerJWS says
// the same.
func TestFetchUserInfoNamesAlgorithmMismatch(t *testing.T) {
	userInfoKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate userinfo key: %v", err)
	}
	compact := signUserInfoJWS(t, userInfoKey, map[string]any{"sub": userInfoTestSubject, "iss": testIssuer, "aud": testClientID})
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/jwt")
		_, _ = w.Write([]byte(compact))
	}))
	defer ts.Close()

	c := newUserInfoTestClient(t, ts, &userInfoKey.PublicKey, func(cfg *client.Config) { cfg.Algorithms.UserInfo = fapi.PS256 }, nil)
	_, err = c.FetchUserInfo(context.Background(), userInfoTestTokens())
	assertNamesAlgorithms(t, err, "is signed with ES256, but Config.Algorithms.UserInfo is PS256: set it to the userinfo_signed_response_alg")
	_, err = c.VerifyIssuerJWS(context.Background(), compact)
	assertNamesAlgorithms(t, err, "JWS is signed with ES256, but Config.Algorithms.UserInfo is PS256")
}
