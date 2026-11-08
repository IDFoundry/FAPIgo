package server_test

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"net/url"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/clientassertion"
	"github.com/idfoundry/fapigo/internal/dpop"
	"github.com/idfoundry/fapigo/internal/jose"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage/memstore"
)

func dpopThumbprint(t *testing.T, key *ecdsa.PrivateKey) string {
	t.Helper()
	jwk, err := jose.NewJWK(key.Public(), fapi.ES256)
	if err != nil {
		t.Fatalf("NewJWK: %v", err)
	}
	tp, err := jwk.Thumbprint()
	if err != nil {
		t.Fatalf("Thumbprint: %v", err)
	}
	return tp.String()
}

func approveBackchannel(t *testing.T, h harness, handle server.BackchannelAuthenticationHandle) {
	t.Helper()
	subject, err := server.NewSubjectID("user-1")
	if err != nil {
		t.Fatalf("NewSubjectID: %v", err)
	}
	authenticated, err := server.NewAuthenticatedSubject(subject)
	if err != nil {
		t.Fatalf("NewAuthenticatedSubject: %v", err)
	}
	authCtx, err := server.NewAuthenticationContext(h.now, "acr-1", []string{"pwd"})
	if err != nil {
		t.Fatalf("NewAuthenticationContext: %v", err)
	}
	if err := h.server.CompleteBackchannelAuthentication(context.Background(), server.CompleteBackchannelAuthenticationRequest{
		Handle: handle,
		Result: server.Authorize(authenticated, authCtx, server.GrantedAuthorization{Scope: []string{"openid", "accounts"}}),
	}); err != nil {
		t.Fatalf("CompleteBackchannelAuthentication: %v", err)
	}
}

func exchangeBackchannelWithKey(t *testing.T, h harness, authReqID string, key *ecdsa.PrivateKey) error {
	t.Helper()
	_, err := h.server.ExchangeBackchannelAuthentication(context.Background(), server.BackchannelTokenExchangeRequest{
		HTTP: server.FormRequest{Parameters: []server.FormParameter{
			formParam("client_assertion", h.clientAssertion(t)),
			formParam("client_assertion_type", clientassertion.AssertionType),
			formParam("grant_type", server.CIBAGrantType),
			formParam("auth_req_id", authReqID),
		}},
		DPoPProofs: []string{createDPoPProof(t, key, h.now)},
	})
	return err
}

// TestBackchannelAuthenticationHonoursDPoPJKT: an explicit dpop_jkt in
// the backchannel authentication request binds it to that key, as at
// PAR, so the token exchange accepts only a proof from that key.
func TestBackchannelAuthenticationHonoursDPoPJKT(t *testing.T) {
	bound := generateKey(t)
	for name, tc := range map[string]struct {
		exchangeKey *ecdsa.PrivateKey
		wantErr     server.ErrorCode
	}{
		"the declared key": {bound, ""},
		"another key":      {generateKey(t), server.ErrorInvalidGrant},
	} {
		t.Run(name, func(t *testing.T) {
			h, _ := newHarnessWithBackchannel(t)
			params := standardBackchannelParams(t)
			params["dpop_jkt"] = jsonRaw(t, dpopThumbprint(t, bound))
			required := beginBackchannel(t, h, params)
			approveBackchannel(t, h, required.Handle)
			err := exchangeBackchannelWithKey(t, h, required.AuthReqID.String(), tc.exchangeKey)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("exchange with the declared key: %v", err)
				}
				return
			}
			if serverErrorCode(t, err) != tc.wantErr {
				t.Fatalf("exchange with another key: %v, want %s", err, tc.wantErr)
			}
		})
	}
}

// TestBackchannelAuthenticationRefusesBadDPoPJKT: a dpop_jkt that isn't
// a string, or doesn't match a DPoP proof sent with the request, is
// invalid_request.
func TestBackchannelAuthenticationRefusesBadDPoPJKT(t *testing.T) {
	endpoint, err := url.Parse(testBackchannelAuthenticationEndpoint)
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}
	for name, tc := range map[string]struct {
		dpopJKT   func(t *testing.T) json.RawMessage
		withProof bool
	}{
		"not a string":               {func(t *testing.T) json.RawMessage { return jsonRaw(t, 42) }, false},
		"another key than the proof": {func(t *testing.T) json.RawMessage { return jsonRaw(t, dpopThumbprint(t, generateKey(t))) }, true},
	} {
		t.Run(name, func(t *testing.T) {
			h, _ := newHarnessWithBackchannel(t)
			params := standardBackchannelParams(t)
			params["dpop_jkt"] = tc.dpopJKT(t)
			req := server.BeginBackchannelAuthenticationRequest{
				HTTP: server.FormRequest{Parameters: backchannelFormParams(h.clientAssertion(t), h.backchannelRequestObject(t, params))},
			}
			if tc.withProof {
				proof, err := dpop.CreateProof(dpop.ProofRequest{Signer: generateKey(t), Algorithm: fapi.ES256, Method: "POST", URL: endpoint, Now: h.now})
				if err != nil {
					t.Fatalf("CreateProof: %v", err)
				}
				req.DPoPProofs = []string{proof}
			}
			action, err := h.server.BeginBackchannelAuthentication(context.Background(), req)
			if err != nil {
				t.Fatalf("BeginBackchannelAuthentication: %v", err)
			}
			localErr, ok := action.(server.BackchannelAuthenticationLocalError)
			if !ok {
				t.Fatalf("action = %T, want BackchannelAuthenticationLocalError", action)
			}
			if localErr.Error.Code() != server.ErrorInvalidRequest {
				t.Fatalf("Code = %q, want invalid_request", localErr.Error.Code())
			}
		})
	}
}

// TestBackchannelAuthenticationChallengesDPoPNonce guards the nonce
// check on a DPoP proof sent to the backchannel authentication endpoint
// when Dependencies.Nonces is set: a proof without a nonce is refused
// with use_dpop_nonce carrying a fresh nonce, and a retry whose proof
// carries that nonce is accepted.
func TestBackchannelAuthenticationChallengesDPoPNonce(t *testing.T) {
	endpoint, err := url.Parse(testBackchannelAuthenticationEndpoint)
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}
	h := newHarnessWithBackchannelOptions(t, memstore.NewBackchannelAuthenticationStore(),
		func(cfg *server.Config) { cfg.Limits.DPoPNonceLifetime = time.Minute },
		func(deps *server.Dependencies) { deps.Nonces = memstore.NewNonceStore() },
	)
	dpopKey := generateKey(t)
	begin := func(nonce string) server.BackchannelAuthenticationAction {
		t.Helper()
		proof, err := dpop.CreateProof(dpop.ProofRequest{Signer: dpopKey, Algorithm: fapi.ES256, Method: "POST", URL: endpoint, Now: h.now, Nonce: nonce})
		if err != nil {
			t.Fatalf("CreateProof: %v", err)
		}
		action, err := h.server.BeginBackchannelAuthentication(context.Background(), server.BeginBackchannelAuthenticationRequest{
			HTTP:       server.FormRequest{Parameters: backchannelFormParams(h.clientAssertion(t), h.backchannelRequestObject(t, standardBackchannelParams(t)))},
			DPoPProofs: []string{proof},
		})
		if err != nil {
			t.Fatalf("BeginBackchannelAuthentication: %v", err)
		}
		return action
	}

	action := begin("")
	localErr, ok := action.(server.BackchannelAuthenticationLocalError)
	if !ok {
		t.Fatalf("proof without a nonce: action = %T, want BackchannelAuthenticationLocalError", action)
	}
	if localErr.Error.Code() != server.ErrorUseDPoPNonce {
		t.Fatalf("Code = %q, want %q", localErr.Error.Code(), server.ErrorUseDPoPNonce)
	}
	issued := localErr.Error.Nonce()
	if issued == "" {
		t.Fatalf("use_dpop_nonce challenge carries no nonce")
	}

	action = begin(issued)
	if _, ok := action.(server.BackchannelInteractionRequired); !ok {
		t.Fatalf("proof with the issued nonce: action = %T, want BackchannelInteractionRequired", action)
	}
}
