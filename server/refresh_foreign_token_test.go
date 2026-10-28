package server_test

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/clientassertion"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
)

// TestRefreshAnotherClientsTokenIsUnknown: an authenticated client
// presenting another client's refresh token is told exactly what it's
// told for a token that doesn't exist, live or expired, so the refresh
// grant is no oracle for whether someone else's token is live — as
// revocation already isn't.
func TestRefreshAnotherClientsTokenIsUnknown(t *testing.T) {
	const otherClientID fapi.ClientID = "rp-other"
	h := newHarness(t, server.ProfileFAPISecurity, true)
	issued, _ := exchangeForTokensWithOfflineAccess(t, h)
	otherKey := generateKey(t)
	other, err := storage.NewRegisteredClient(storage.RegisteredClientConfig{
		ID:                       otherClientID,
		RedirectURIs:             []fapi.RegisteredRedirectURI{testRedirectURI},
		ClientAssertionAlgorithm: fapi.ES256,
		AllowedScopes:            []string{"openid", "accounts", "offline_access"},
	})
	if err != nil {
		t.Fatalf("NewRegisteredClient: %v", err)
	}
	h.clients.clients[otherClientID] = other
	h.deps.ClientKeys.(*fakeClientKeySource).keysByClient[otherClientID] = []keys.VerificationKey{{Algorithm: fapi.ES256, PublicKey: &otherKey.PublicKey}}

	unknown := refreshAsDescription(t, h.server, otherClientID, otherKey, h.now, "never-issued")
	if got := refreshAsDescription(t, h.server, otherClientID, otherKey, h.now, issued.RefreshToken.Reveal()); got != unknown {
		t.Errorf("another client's live refresh token = %q, want %q, as for an unknown one", got, unknown)
	}

	later := h.now.Add(time.Hour) // past the harness's RefreshTokenLifetime
	deps := h.deps
	deps.Clock = fixedClock{now: later}
	expired, err := server.New(h.cfg, deps)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	unknown = refreshAsDescription(t, expired, otherClientID, otherKey, later, "never-issued")
	if got := refreshAsDescription(t, expired, otherClientID, otherKey, later, issued.RefreshToken.Reveal()); got != unknown {
		t.Errorf("another client's expired refresh token = %q, want %q, as for an unknown one", got, unknown)
	}
}

// refreshAsDescription presents refreshToken at srv as clientID, signed
// by key, at now, and returns the description of the invalid_grant it
// must be refused with.
func refreshAsDescription(t *testing.T, srv *server.Server, clientID fapi.ClientID, key *ecdsa.PrivateKey, now time.Time, refreshToken string) string {
	t.Helper()
	assertion, err := clientassertion.CreateAssertion(clientassertion.AssertionRequest{
		Signer: key, Algorithm: fapi.ES256, ClientID: clientID.String(), Audience: testIssuer,
		Now: now, Lifetime: 30 * time.Second,
	})
	if err != nil {
		t.Fatalf("CreateAssertion: %v", err)
	}
	_, err = srv.RefreshAccessToken(context.Background(), server.RefreshTokenRequest{
		HTTP:       server.FormRequest{Parameters: refreshFormParams(assertion, refreshToken, "")},
		DPoPProofs: []string{createDPoPProof(t, generateKey(t), now)},
	})
	var srvErr *server.Error
	if !errors.As(err, &srvErr) || srvErr.Code() != server.ErrorInvalidGrant {
		t.Fatalf("RefreshAccessToken = %v, want invalid_grant", err)
	}
	return srvErr.PublicDescription()
}
