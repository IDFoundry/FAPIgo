package server_test

import (
	"context"
	"crypto/ecdsa"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/clientassertion"
	"github.com/idfoundry/fapigo/internal/requestobject"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage/memstore"
)

// rotatingHarness is newHarness whose client publishes two keys for
// its algorithm mid-rotation — a retired one first, then h.key, which
// signs everything — both under kid (empty for none). The client's
// JWTs carry kid too.
func rotatingHarness(t *testing.T, kid string) harness {
	t.Helper()
	h := newHarness(t, server.ProfileFAPISecurity, true)
	retired := generateKey(t)
	deps := h.deps
	deps.ClientKeys = &fakeClientKeySource{keysByClient: map[fapi.ClientID][]keys.VerificationKey{
		testClientID: {
			{KeyID: kid, Algorithm: fapi.ES256, PublicKey: &retired.PublicKey},
			{KeyID: kid, Algorithm: fapi.ES256, PublicKey: &h.key.PublicKey},
		},
	}}
	srv, err := server.New(h.cfg, deps)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	h.server, h.deps = srv, deps
	return h
}

func signedAssertion(t *testing.T, h harness, signer *ecdsa.PrivateKey, kid string) string {
	t.Helper()
	assertion, err := clientassertion.CreateAssertion(clientassertion.AssertionRequest{
		Signer: signer, Algorithm: fapi.ES256, KeyID: kid,
		ClientID: testClientID.String(), Audience: testIssuer,
		Now: h.now, Lifetime: 30 * time.Second,
	})
	if err != nil {
		t.Fatalf("CreateAssertion: %v", err)
	}
	return assertion
}

func signedRequestObject(t *testing.T, h harness, kid string) string {
	t.Helper()
	obj, err := requestobject.Create(requestobject.CreateParams{
		Signer: h.key, Algorithm: fapi.ES256, KeyID: kid,
		ClientID: testClientID.String(), Audience: testIssuer,
		Now: h.now, Lifetime: 30 * time.Second, Parameters: standardAuthParams(t),
	})
	if err != nil {
		t.Fatalf("requestobject.Create: %v", err)
	}
	return obj
}

func pushSignedWith(h harness, assertion string, extra ...server.FormParameter) error {
	params := append([]server.FormParameter{
		formParam("client_assertion", assertion),
		formParam("client_assertion_type", clientassertion.AssertionType),
	}, extra...)
	_, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
		HTTP: server.FormRequest{Parameters: params},
	})
	return err
}

// TestPushAuthorizationRequestTriesEveryMatchingClientKey: a client
// assertion and request object signed with the second of two keys that
// both match — no kid, or one kid both share — still verify, so a
// client rotating keys that way isn't locked out.
func TestPushAuthorizationRequestTriesEveryMatchingClientKey(t *testing.T) {
	for name, kid := range map[string]string{"no kid": "", "shared kid": "shared"} {
		t.Run(name, func(t *testing.T) {
			h := rotatingHarness(t, kid)
			err := pushSignedWith(h, signedAssertion(t, h, h.key, kid),
				formParam("client_id", testClientID.String()),
				formParam("request", signedRequestObject(t, h, kid)))
			if err != nil {
				t.Fatalf("PushAuthorizationRequest(signed with the second matching key) = %v, want success", err)
			}
		})
	}
}

// TestPushAuthorizationRequestRejectsAssertionNoCandidateVerifies: with
// several candidates, an assertion none of them verifies is refused as
// before.
func TestPushAuthorizationRequestRejectsAssertionNoCandidateVerifies(t *testing.T) {
	h := rotatingHarness(t, "")
	err := pushSignedWith(h, signedAssertion(t, h, generateKey(t), ""), parFormParams(t, h)[2:]...)
	serr, ok := err.(*server.Error)
	if !ok || serr.Code() != server.ErrorInvalidClient {
		t.Fatalf("PushAuthorizationRequest(unknown signing key) = %v, want invalid_client", err)
	}
}

// TestBeginBackchannelAuthenticationTriesEveryMatchingClientKey: a CIBA
// request object signed with the second of two kid-less keys verifies.
func TestBeginBackchannelAuthenticationTriesEveryMatchingClientKey(t *testing.T) {
	retired := generateKey(t)
	h := newHarnessWithBackchannelOptions(t, memstore.NewBackchannelAuthenticationStore(), nil, func(d *server.Dependencies) {
		source := d.ClientKeys.(*fakeClientKeySource)
		source.keysByClient[testClientID] = append([]keys.VerificationKey{{Algorithm: fapi.ES256, PublicKey: &retired.PublicKey}}, source.keysByClient[testClientID]...)
	})
	action, err := h.server.BeginBackchannelAuthentication(context.Background(), server.BeginBackchannelAuthenticationRequest{
		HTTP: server.FormRequest{Parameters: backchannelFormParams(h.clientAssertion(t), h.backchannelRequestObject(t, standardBackchannelParams(t)))},
	})
	if err != nil {
		t.Fatalf("BeginBackchannelAuthentication(signed with the second matching key) = %v, want success", err)
	}
	if _, ok := action.(server.BackchannelInteractionRequired); !ok {
		t.Fatalf("action = %T, want server.BackchannelInteractionRequired", action)
	}
}

// TestClientAttestationTriesEveryMatchingAttesterKey: an attestation
// signed with the second of two kid-less keys registered for its
// attester verifies.
func TestClientAttestationTriesEveryMatchingAttesterKey(t *testing.T) {
	retired, attesterKey, instanceKey := generateKey(t), generateKey(t), generateKey(t)
	h := newHarnessWithAttesterTrust(t, nil, server.RegisteredAttesterKeys{Keys: keys.StaticAttesterKeys{
		testAttesterIssuer: {
			{Algorithm: fapi.ES256, PublicKey: &retired.PublicKey},
			{Algorithm: fapi.ES256, PublicKey: &attesterKey.PublicKey},
		},
	}})
	_, err := h.server.RequestClientCredentialsToken(context.Background(), server.ClientCredentialsTokenRequest{
		HTTP:                  server.FormRequest{Parameters: attestationClientCredentialsFormParams("accounts")},
		ClientAttestations:    []string{createAttestationHeader(t, attesterKey, testClientID.String(), &instanceKey.PublicKey, h.now, time.Hour)},
		ClientAttestationPoPs: []string{createAttestationPoPHeader(t, instanceKey, testClientID.String(), testIssuer, "jti-rotation", h.now)},
		DPoPProofs:            []string{createDPoPProof(t, generateKey(t), h.now)},
	})
	if err != nil {
		t.Fatalf("RequestClientCredentialsToken(attestation signed with the second matching key) = %v, want success", err)
	}
}
