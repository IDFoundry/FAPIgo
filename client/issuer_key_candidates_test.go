package client_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/idfoundry/fapigo/client"
	"github.com/idfoundry/fapigo/internal/jose"
	"github.com/idfoundry/fapigo/keys"
)

// issuerKeyCandidateCap is how many of the keys Dependencies.IssuerKeys
// returns for a JWS the client tries, as that field documents.
const issuerKeyCandidateCap = 8

// orderedIssuerKeys resolves every request to decoys followed by
// genuine, the key that signed what is checked, each with the requested
// algorithm and kid: an issuer whose JWK Set lists that many keys a JWS
// doesn't tell apart. cancel, when set, is called as the keys are
// resolved: a caller giving up while the client verifies.
type orderedIssuerKeys struct {
	genuine crypto.PublicKey
	decoys  []crypto.PublicKey
	cancel  context.CancelFunc
}

func (s *orderedIssuerKeys) ResolveIssuerKeys(_ context.Context, req keys.IssuerKeyRequest) (keys.IssuerKeySet, error) {
	if s.cancel != nil {
		s.cancel()
	}
	var set keys.IssuerKeySet
	for _, pub := range append(slices.Clone(s.decoys), s.genuine) {
		set.Keys = append(set.Keys, keys.IssuerKey{KeyID: req.KeyID, Algorithm: req.Algorithm, PublicKey: pub})
	}
	return set, nil
}

// issuerSignedPath is one way the client verifies something the
// authorization server signed. setup builds a client resolving the
// issuer's keys through issuerKeys, sets issuerKeys.genuine to the key
// its fake server signs with, and returns the call that verifies what it
// signed.
type issuerSignedPath struct {
	name  string
	setup func(t *testing.T, issuerKeys *orderedIssuerKeys) func(context.Context) error
}

func issuerSignedPaths() []issuerSignedPath {
	return []issuerSignedPath{
		{"JARM response", setupJARMCallback},
		{"ID token from an authorization code", setupCodeExchange},
		{"ID token from a CIBA poll", setupCIBAPoll},
		{"ID token from a refresh", setupRefresh},
		{"VerifyIssuerJWS", setupVerifyIssuerJWS},
		{"signed UserInfo response", setupSignedUserInfo},
	}
}

// TestIssuerKeyCandidatesAreCapped: each way the client verifies
// something the authorization server signed tries only the first eight
// keys Dependencies.IssuerKeys returns for it. Signed with the eighth, it
// verifies; signed with the ninth, the key is never tried and the check
// fails, however many keys the issuer lists.
func TestIssuerKeyCandidatesAreCapped(t *testing.T) {
	for _, path := range issuerSignedPaths() {
		t.Run(path.name, func(t *testing.T) {
			if err := runWithDecoys(t, path, issuerKeyCandidateCap-1); err != nil {
				t.Errorf("signed with key %d of %d: %v, want it verified", issuerKeyCandidateCap, issuerKeyCandidateCap, err)
			}
			err := runWithDecoys(t, path, issuerKeyCandidateCap)
			var cerr *client.Error
			if !errors.As(err, &cerr) || cerr.Code() != client.ErrorInvalidResponse || !errors.Is(err, jose.ErrInvalidSignature) {
				t.Errorf("signed with key %d of %d: %v, want an invalid signature", issuerKeyCandidateCap+1, issuerKeyCandidateCap+1, err)
			}
		})
	}
}

// runWithDecoys sets path up with the issuer's signing key alone, then
// puts decoys other keys ahead of it, as an issuer listing that many
// more for the algorithm would, and runs the check.
func runWithDecoys(t *testing.T, path issuerSignedPath, decoys int) error {
	t.Helper()
	issuerKeys := &orderedIssuerKeys{}
	verify := path.setup(t, issuerKeys)
	for range decoys {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("generate decoy key: %v", err)
		}
		issuerKeys.decoys = append(issuerKeys.decoys, &key.PublicKey)
	}
	return verify(context.Background())
}

// TestIssuerKeyCandidatesStopWhenTheContextEnds: once the context has
// ended, the client tries none of the issuer's keys, not even the signing
// key first in line, and fails with the context's error.
func TestIssuerKeyCandidatesStopWhenTheContextEnds(t *testing.T) {
	for _, path := range issuerSignedPaths() {
		t.Run(path.name, func(t *testing.T) {
			issuerKeys := &orderedIssuerKeys{}
			verify := path.setup(t, issuerKeys)
			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)
			issuerKeys.cancel = cancel
			err := verify(ctx)
			var cerr *client.Error
			if !errors.As(err, &cerr) || cerr.Code() != client.ErrorInternal || !errors.Is(err, context.Canceled) {
				t.Fatalf("context ended as the issuer's keys resolved: %v, want an internal error wrapping context.Canceled", err)
			}
		})
	}
}

func setupJARMCallback(t *testing.T, issuerKeys *orderedIssuerKeys) func(context.Context) error {
	c, as, _ := newTestClientWith(t, true, func(_ *client.Config, d *client.Dependencies) { d.IssuerKeys = issuerKeys })
	issuerKeys.genuine = &as.jarmKey.PublicKey
	cb := beginAuthorizationCallback(t, c, as)
	return func(ctx context.Context) error {
		_, err := c.HandleAuthorizationResponse(ctx, cb)
		return err
	}
}

func setupCodeExchange(t *testing.T, issuerKeys *orderedIssuerKeys) func(context.Context) error {
	c, as, _ := newTestClientWith(t, false, func(_ *client.Config, d *client.Dependencies) { d.IssuerKeys = issuerKeys })
	issuerKeys.genuine = &as.idTokenKey.PublicKey
	cb := beginAuthorizationCallback(t, c, as)
	return func(ctx context.Context) error {
		_, err := c.CompleteAuthorization(ctx, cb)
		return err
	}
}

// beginAuthorizationCallback begins an authorization with c and returns
// the callback as's approval of it sends back.
func beginAuthorizationCallback(t *testing.T, c *client.Client, as *fakeAS) client.AuthorizationCallback {
	t.Helper()
	session, err := c.BeginAuthorization(context.Background(), client.BeginAuthorizationRequest{Scope: []string{"openid"}})
	if err != nil {
		t.Fatalf("BeginAuthorization: %v", err)
	}
	return client.AuthorizationCallback{
		RawQuery: as.callbackFor(t, as.lastState, "auth-code-1", ""),
		Session:  session.Handle(),
	}
}

func setupCIBAPoll(t *testing.T, issuerKeys *orderedIssuerKeys) func(context.Context) error {
	c, as, _ := newTestClientWithCIBAWith(t, func(d *client.Dependencies) { d.IssuerKeys = issuerKeys })
	issuerKeys.genuine = &as.idTokenKey.PublicKey
	session := beginTestBackchannelSession(t, c)
	as.tokenResponses = []cibaTokenResponse{{status: http.StatusOK, body: map[string]any{
		"access_token": "at-1", "token_type": "DPoP", "expires_in": 300, "scope": "openid accounts",
		"id_token": newCIBAIDToken(t, as),
	}}}
	return func(ctx context.Context) error {
		_, err := c.PollBackchannelAuthentication(ctx, session)
		return err
	}
}

func setupRefresh(t *testing.T, issuerKeys *orderedIssuerKeys) func(context.Context) error {
	c, as, _ := newTestClientWithCIBAWith(t, func(d *client.Dependencies) { d.IssuerKeys = issuerKeys })
	issuerKeys.genuine = &as.idTokenKey.PublicKey
	tokens := approvedCIBATokens(t, c, as)
	as.tokenResponses = []cibaTokenResponse{{status: http.StatusOK, body: map[string]any{
		"access_token": "at-2", "token_type": "DPoP", "expires_in": 300, "id_token": newCIBAIDToken(t, as),
	}}}
	return func(ctx context.Context) error {
		_, err := c.RefreshTokens(ctx, client.RefreshTokenRequest{Tokens: tokens})
		return err
	}
}

func setupVerifyIssuerJWS(t *testing.T, issuerKeys *orderedIssuerKeys) func(context.Context) error {
	c, signed := signedUserInfoClient(t, issuerKeys)
	return func(ctx context.Context) error {
		_, err := c.VerifyIssuerJWS(ctx, signed)
		return err
	}
}

func setupSignedUserInfo(t *testing.T, issuerKeys *orderedIssuerKeys) func(context.Context) error {
	c, _ := signedUserInfoClient(t, issuerKeys)
	return func(ctx context.Context) error {
		_, err := c.FetchUserInfo(ctx, userInfoTestTokens())
		return err
	}
}

// signedUserInfoClient returns a client whose UserInfo endpoint answers
// with the signed UserInfo response it also returns, signed by a key
// that becomes issuerKeys.genuine.
func signedUserInfoClient(t *testing.T, issuerKeys *orderedIssuerKeys) (*client.Client, string) {
	t.Helper()
	signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate userinfo key: %v", err)
	}
	issuerKeys.genuine = &signer.PublicKey
	signed := signUserInfoJWS(t, signer, map[string]any{"sub": userInfoTestSubject, "iss": testIssuer, "aud": testClientID})
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/jwt")
		_, _ = w.Write([]byte(signed))
	}))
	t.Cleanup(ts.Close)
	c := newUserInfoTestClient(t, ts, nil, nil, func(d *client.Dependencies) { d.IssuerKeys = issuerKeys })
	return c, signed
}
