package server_test

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"net/url"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/dpop"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
)

// clientlessTokenRequest is a pre-authorized code token request without
// client authentication, carrying proofs as its DPoP header.
func clientlessTokenRequest(t *testing.T, proofs ...string) server.TokenEndpointRequest {
	t.Helper()
	return extensionTokenRequest(t, preAuthorizedForm(), dpopHeader(proofs...), nil)
}

func wantAuditedDPoPVerification(t *testing.T, h harness, outcome server.AuditOutcome) {
	t.Helper()
	last := lastAudit(t, h)
	if last.Type != server.AuditEventVerifyTokenRequestDPoP || last.Outcome != outcome || last.ClientID != "" {
		t.Errorf("last audit event = %+v, want a VerifyTokenRequestDPoP event with outcome %v and no client ID", last, outcome)
	}
}

func TestVerifyTokenRequestDPoP(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	dpopKey := generateKey(t)
	binding, err := h.server.VerifyTokenRequestDPoP(context.Background(), clientlessTokenRequest(t, dpopProofAt(t, dpopKey, testTokenEndpoint, "", h.now)))
	if err != nil {
		t.Fatalf("VerifyTokenRequestDPoP: %v", err)
	}
	want, err := jwkThumbprintFor(dpopKey)
	if err != nil {
		t.Fatal(err)
	}
	if binding.Thumbprint != want.String() || binding.NextDPoPNonce != "" {
		t.Errorf("binding = %+v, want the DPoP key's thumbprint %s and no nonce", binding, want)
	}
	wantAuditedDPoPVerification(t, h, server.AuditOutcomeSuccess)
}

func TestVerifyTokenRequestDPoPRefusesBadProofs(t *testing.T) {
	dpopKey := generateKey(t)
	for name, proofs := range map[string]func(now time.Time) []string{
		"no proof": func(time.Time) []string { return nil },
		"two proofs": func(now time.Time) []string {
			return []string{dpopProofAt(t, dpopKey, testTokenEndpoint, "", now), dpopProofAt(t, dpopKey, testTokenEndpoint, "", now)}
		},
		"another endpoint": func(now time.Time) []string {
			return []string{dpopProofAt(t, dpopKey, "https://as.example/par", "", now)}
		},
		"another method": func(now time.Time) []string {
			return []string{dpopProofForMethod(t, dpopKey, "GET", now)}
		},
		"stale proof": func(now time.Time) []string {
			return []string{dpopProofAt(t, dpopKey, testTokenEndpoint, "", now.Add(-time.Hour))}
		},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, server.ProfileFAPISecurity, true)
			_, err := h.server.VerifyTokenRequestDPoP(context.Background(), clientlessTokenRequest(t, proofs(h.now)...))
			var serr *server.Error
			if !errors.As(err, &serr) || serr.HTTPStatus() != 400 {
				t.Fatalf("VerifyTokenRequestDPoP = %v, want a 400 refusal", err)
			}
			wantAuditedDPoPVerification(t, h, server.AuditOutcomeFailure)
		})
	}
}

func dpopProofForMethod(t *testing.T, key *ecdsa.PrivateKey, method string, now time.Time) string {
	t.Helper()
	u, err := url.Parse(testTokenEndpoint)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := dpop.CreateProof(dpop.ProofRequest{Signer: key, Algorithm: fapi.ES256, Method: method, URL: u, Now: now})
	if err != nil {
		t.Fatalf("dpop.CreateProof: %v", err)
	}
	return proof
}

func TestVerifyTokenRequestDPoPRefusesReplay(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	proof := dpopProofAt(t, generateKey(t), testTokenEndpoint, "", h.now)
	if _, err := h.server.VerifyTokenRequestDPoP(context.Background(), clientlessTokenRequest(t, proof)); err != nil {
		t.Fatalf("VerifyTokenRequestDPoP: %v", err)
	}
	if _, err := h.server.VerifyTokenRequestDPoP(context.Background(), clientlessTokenRequest(t, proof)); serverErrorCode(t, err) != server.ErrorInvalidDPoPProof {
		t.Fatalf("VerifyTokenRequestDPoP(the same proof again) = %v, want invalid_dpop_proof", err)
	}
}

// TestVerifyTokenRequestDPoPSharesReplayWithAuthorizationCode covers one
// replay record for the token endpoint: a proof the server's own
// authorization code grant accepted is refused without a client, and the
// other way round.
func TestVerifyTokenRequestDPoPSharesReplayWithAuthorizationCode(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	ctx := context.Background()
	exchange := func(proof string) error {
		code := completeSuccessfulAuthorization(t, h, []string{"openid", "accounts"})
		_, err := h.server.ExchangeAuthorizationCode(ctx, server.AuthorizationCodeExchangeRequest{
			HTTP:       server.FormRequest{Parameters: exchangeFormParams(h.clientAssertion(t), code, testRedirectURI, testCodeVerifier)},
			DPoPProofs: []string{proof},
		})
		return err
	}

	proof := createDPoPProof(t, generateKey(t), h.now)
	if err := exchange(proof); err != nil {
		t.Fatalf("ExchangeAuthorizationCode: %v", err)
	}
	if _, err := h.server.VerifyTokenRequestDPoP(ctx, clientlessTokenRequest(t, proof)); serverErrorCode(t, err) != server.ErrorInvalidDPoPProof {
		t.Fatalf("VerifyTokenRequestDPoP(proof the authorization code grant used) = %v, want invalid_dpop_proof", err)
	}

	second := createDPoPProof(t, generateKey(t), h.now)
	if _, err := h.server.VerifyTokenRequestDPoP(ctx, clientlessTokenRequest(t, second)); err != nil {
		t.Fatalf("VerifyTokenRequestDPoP: %v", err)
	}
	if err := exchange(second); serverErrorCode(t, err) != server.ErrorInvalidDPoPProof {
		t.Fatalf("ExchangeAuthorizationCode(proof used without a client) = %v, want invalid_dpop_proof", err)
	}
}

// TestVerifyTokenRequestDPoPSharesReplayWithBinding covers the same for
// an embedder's grant with an authenticated client.
func TestVerifyTokenRequestDPoPSharesReplayWithBinding(t *testing.T) {
	h := newHarnessWithAttestationClientCredentials(t, generateKey(t))
	ctx := context.Background()
	dpopKey := generateKey(t)

	proof := dpopProofAt(t, dpopKey, testTokenEndpoint, "", h.now)
	if _, err := h.server.VerifyTokenRequestBinding(ctx, registeredClient(t, h), clientlessTokenRequest(t, proof)); err != nil {
		t.Fatalf("VerifyTokenRequestBinding: %v", err)
	}
	if _, err := h.server.VerifyTokenRequestDPoP(ctx, clientlessTokenRequest(t, proof)); serverErrorCode(t, err) != server.ErrorInvalidDPoPProof {
		t.Fatalf("VerifyTokenRequestDPoP(proof VerifyTokenRequestBinding accepted) = %v, want invalid_dpop_proof", err)
	}

	second := dpopProofAt(t, dpopKey, testTokenEndpoint, "", h.now)
	if _, err := h.server.VerifyTokenRequestDPoP(ctx, clientlessTokenRequest(t, second)); err != nil {
		t.Fatalf("VerifyTokenRequestDPoP: %v", err)
	}
	if _, err := h.server.VerifyTokenRequestBinding(ctx, registeredClient(t, h), clientlessTokenRequest(t, second)); serverErrorCode(t, err) != server.ErrorInvalidDPoPProof {
		t.Fatalf("VerifyTokenRequestBinding(proof VerifyTokenRequestDPoP accepted) = %v, want invalid_dpop_proof", err)
	}
}

func TestVerifyTokenRequestDPoPNonces(t *testing.T) {
	h, _ := newHarnessWithNonces(t)
	dpopKey := generateKey(t)

	_, err := h.server.VerifyTokenRequestDPoP(context.Background(), clientlessTokenRequest(t, dpopProofAt(t, dpopKey, testTokenEndpoint, "", h.now)))
	var challenge *server.Error
	if !errors.As(err, &challenge) || challenge.Code() != server.ErrorUseDPoPNonce || challenge.Nonce() == "" {
		t.Fatalf("VerifyTokenRequestDPoP(no nonce) = %v, want use_dpop_nonce carrying a nonce", err)
	}

	binding, err := h.server.VerifyTokenRequestDPoP(context.Background(), clientlessTokenRequest(t, dpopProofAt(t, dpopKey, testTokenEndpoint, challenge.Nonce(), h.now)))
	if err != nil {
		t.Fatalf("VerifyTokenRequestDPoP(with the nonce): %v", err)
	}
	if binding.NextDPoPNonce == "" {
		t.Error("NextDPoPNonce is empty, want the nonce to use next")
	}
}

func TestVerifyTokenRequestDPoPAtTheMTLSAlias(t *testing.T) {
	const alias = "https://mtls.as.example/token"
	h := newAttestationHarness(t, time.Now(), generateKey(t), server.RegisteredAttesterKeys{}, func(cfg *server.Config, _ *storage.RegisteredClientConfig) {
		u, err := fapi.ParseEndpointURL(alias)
		if err != nil {
			t.Fatal(err)
		}
		cfg.MTLSEndpoints.Token = u
	})
	if _, err := h.server.VerifyTokenRequestDPoP(context.Background(), clientlessTokenRequest(t, dpopProofAt(t, generateKey(t), alias, "", h.now))); err != nil {
		t.Fatalf("VerifyTokenRequestDPoP(proof for the mTLS alias): %v", err)
	}
}
