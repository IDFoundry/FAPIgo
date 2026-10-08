package server_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"net/url"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/clientassertion"
	"github.com/idfoundry/fapigo/internal/dpop"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
)

// fixedJTI is a Random source that always yields the same 16 bytes, so
// two assertions or proofs made with it carry the same jti.
func fixedJTI() *bytes.Reader { return bytes.NewReader(bytes.Repeat([]byte{7}, 16)) }

// registerSecondClient adds another client, with its own key, to h.
func registerSecondClient(t *testing.T, h harness) (fapi.ClientID, *ecdsa.PrivateKey) {
	t.Helper()
	const id fapi.ClientID = "client-2"
	client, err := storage.NewRegisteredClient(storage.RegisteredClientConfig{
		ID:                       id,
		RedirectURIs:             []fapi.RegisteredRedirectURI{testRedirectURI},
		ClientAssertionAlgorithm: fapi.ES256,
		RequestObjectAlgorithm:   fapi.ES256,
		AllowedScopes:            []string{"openid", "accounts"},
	})
	if err != nil {
		t.Fatalf("NewRegisteredClient: %v", err)
	}
	key := generateKey(t)
	h.clients.clients[id] = client
	h.deps.ClientKeys.(*fakeClientKeySource).keysByClient[id] = []keys.VerificationKey{{Algorithm: fapi.ES256, PublicKey: &key.PublicKey}}
	return id, key
}

func assertionWithFixedJTI(t *testing.T, h harness, id fapi.ClientID, key *ecdsa.PrivateKey) string {
	t.Helper()
	assertion, err := clientassertion.CreateAssertion(clientassertion.AssertionRequest{
		Signer: key, Algorithm: fapi.ES256, ClientID: id.String(), Audience: testIssuer,
		Now: h.now, Lifetime: 30 * time.Second, Random: fixedJTI(),
	})
	if err != nil {
		t.Fatalf("CreateAssertion: %v", err)
	}
	return assertion
}

// TestReplayRecordsAreScopedToTheClient: a client assertion's jti is
// recorded for the client that sent it, so another client sending the
// same jti first doesn't make this client's assertion fail as a replay.
// The client sending its own jti twice is still refused.
func TestReplayRecordsAreScopedToTheClient(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	ctx := context.Background()
	otherID, otherKey := registerSecondClient(t, h)
	par := func(assertion string) error {
		_, err := h.server.PushAuthorizationRequest(ctx, server.PushAuthorizationRequest{
			HTTP: server.FormRequest{Parameters: plainFormParameters(t, assertion, nil)},
		})
		return err
	}

	if err := par(assertionWithFixedJTI(t, h, otherID, otherKey)); err != nil {
		t.Fatalf("PAR as the other client: %v", err)
	}
	if err := par(assertionWithFixedJTI(t, h, testClientID, h.key)); err != nil {
		t.Fatalf("PAR as this client, with a jti the other client already used: %v", err)
	}
	if err := par(assertionWithFixedJTI(t, h, testClientID, h.key)); serverErrorCode(t, err) != server.ErrorInvalidClient {
		t.Fatalf("PAR replaying this client's own jti: %v, want invalid_client", err)
	}
}

// TestDPoPReplayRecordsAreScopedToTheKey: a DPoP proof's jti is recorded
// for the key that signed it, so a proof from another key with the same
// jti doesn't make this key's proof fail as a replay. The same key
// sending its jti twice is still refused.
func TestDPoPReplayRecordsAreScopedToTheKey(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	ctx := context.Background()
	parURL, err := url.Parse(testPAREndpoint)
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}
	proof := func(key *ecdsa.PrivateKey) string {
		p, err := dpop.CreateProof(dpop.ProofRequest{Signer: key, Algorithm: fapi.ES256, Method: "POST", URL: parURL, Now: h.now, Random: fixedJTI()})
		if err != nil {
			t.Fatalf("dpop.CreateProof: %v", err)
		}
		return p
	}
	par := func(p string) error {
		_, err := h.server.PushAuthorizationRequest(ctx, server.PushAuthorizationRequest{
			HTTP:       server.FormRequest{Parameters: plainFormParameters(t, h.clientAssertion(t), nil)},
			DPoPProofs: []string{p},
		})
		return err
	}

	attackerKey, victimKey := generateKey(t), generateKey(t)
	if err := par(proof(attackerKey)); err != nil {
		t.Fatalf("PAR with the first key's proof: %v", err)
	}
	if err := par(proof(victimKey)); err != nil {
		t.Fatalf("PAR with another key's proof carrying the same jti: %v", err)
	}
	if err := par(proof(victimKey)); serverErrorCode(t, err) != server.ErrorInvalidDPoPProof {
		t.Fatalf("PAR replaying a key's own proof jti: %v, want invalid_dpop_proof", err)
	}
}
