package server_test

import (
	"context"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/clientassertion"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
)

const otherClientID = fapi.ClientID("other-client")

// registerOtherClient adds a second private_key_jwt client to h's
// server and returns a client assertion for it.
func registerOtherClient(t *testing.T, h harness) string {
	t.Helper()
	other, err := storage.NewRegisteredClient(storage.RegisteredClientConfig{
		ID: otherClientID, RedirectURIs: []fapi.RegisteredRedirectURI{testRedirectURI},
		ClientAssertionAlgorithm: fapi.ES256, AllowedScopes: []string{"openid", "accounts", "offline_access"},
	})
	if err != nil {
		t.Fatalf("NewRegisteredClient: %v", err)
	}
	h.clients.clients[otherClientID] = other
	h.deps.ClientKeys.(*fakeClientKeySource).keysByClient[otherClientID] = []keys.VerificationKey{{Algorithm: fapi.ES256, PublicKey: &h.key.PublicKey}}
	assertion, err := clientassertion.CreateAssertion(clientassertion.AssertionRequest{
		Signer: h.key, Algorithm: fapi.ES256, ClientID: otherClientID.String(), Audience: testIssuer,
		Now: h.now, Lifetime: 30 * time.Second,
	})
	if err != nil {
		t.Fatalf("CreateAssertion: %v", err)
	}
	return assertion
}

// issueAndReuse redeems a fresh code as testClientID, then presents it
// again as the other client, and reports whether testClientID's refresh
// token still works afterwards.
func issueAndReuse(t *testing.T, h harness) (refreshStillWorks bool) {
	t.Helper()
	ctx := context.Background()
	otherAssertion := registerOtherClient(t, h)
	code := completeSuccessfulAuthorization(t, h, []string{"openid", "accounts", "offline_access"})
	first, err := h.server.ExchangeAuthorizationCode(ctx, server.AuthorizationCodeExchangeRequest{
		HTTP:       server.FormRequest{Parameters: exchangeFormParams(h.clientAssertion(t), code, testRedirectURI, testCodeVerifier)},
		DPoPProofs: []string{createDPoPProof(t, generateKey(t), h.now)},
	})
	if err != nil || !first.HasRefreshToken {
		t.Fatalf("first ExchangeAuthorizationCode = %v (refresh token %v)", err, first.HasRefreshToken)
	}
	if _, err := h.server.ExchangeAuthorizationCode(ctx, server.AuthorizationCodeExchangeRequest{
		HTTP:       server.FormRequest{Parameters: exchangeFormParams(otherAssertion, code, testRedirectURI, testCodeVerifier)},
		DPoPProofs: []string{createDPoPProof(t, generateKey(t), h.now)},
	}); serverErrorCode(t, err) != server.ErrorInvalidGrant {
		t.Fatalf("the other client's reuse = %v, want invalid_grant", err)
	}
	_, err = h.server.RefreshAccessToken(ctx, server.RefreshTokenRequest{
		HTTP:       server.FormRequest{Parameters: refreshFormParams(h.clientAssertion(t), first.RefreshToken.Reveal(), "")},
		DPoPProofs: []string{createDPoPProof(t, generateKey(t), h.now)},
	})
	return err == nil
}

// TestCodeReuseByAnotherClientRevokesNothing covers a leaked, already
// used code presented by a different client: refused, and the client it
// was issued to keeps its tokens. The reuse is audited as such.
func TestCodeReuseByAnotherClientRevokesNothing(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	if !issueAndReuse(t, h) {
		t.Fatal("another client's reuse of the code revoked the original client's refresh token")
	}
	var found bool
	for _, e := range h.audit.all() {
		if e.Type == server.AuditEventExchangeAuthorizationCode && e.ClientID == otherClientID && e.Description == "code reused by another client" {
			found = true
		}
	}
	if !found {
		t.Error("cross-client reuse wasn't audited as such")
	}
}

// TestCodeReuseRevokesWhenTheStoreNamesNoClient covers a store that
// leaves AuthorizationCodeAlreadyRedeemedError.ClientID empty: the
// server can't tell who the code belonged to, so it revokes, as before.
func TestCodeReuseRevokesWhenTheStoreNamesNoClient(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	h.grants.omitReuseClientID = true
	if issueAndReuse(t, h) {
		t.Fatal("a reuse the store attributed to no client didn't revoke the refresh token")
	}
}
