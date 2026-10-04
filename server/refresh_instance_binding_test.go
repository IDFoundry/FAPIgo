package server_test

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
	"github.com/idfoundry/fapigo/storage/memstore"
)

// attestedInstance is one installation of a wallet app: the attester's
// key is shared by every installation, the instance key is its own.
type attestedInstance struct {
	t           *testing.T
	h           harness
	attesterKey *ecdsa.PrivateKey
	instanceKey *ecdsa.PrivateKey
	pops        int
}

// headers returns a fresh attestation and PoP for this instance.
func (i *attestedInstance) headers() (attestations, pops []string) {
	i.pops++
	jti := fmt.Sprintf("jti-%p-%d", i.instanceKey, i.pops)
	return []string{createAttestationHeader(i.t, i.attesterKey, testClientID.String(), &i.instanceKey.PublicKey, i.h.now, time.Hour)},
		[]string{createAttestationPoPHeader(i.t, i.instanceKey, testClientID.String(), testIssuer, jti, i.h.now)}
}

// newInstanceBindingHarness registers testClientID for attestation
// with the authorization code grant and offline_access.
func newInstanceBindingHarness(t *testing.T, attesterKey *ecdsa.PrivateKey) harness {
	t.Helper()
	return newAttestationHarness(t, time.Now(), attesterKey, server.RegisteredAttesterKeys{}, func(_ *server.Config, c *storage.RegisteredClientConfig) {
		c.AllowedScopes = []string{"openid", "accounts", "offline_access"}
	})
}

// issueRefreshToken runs PAR, authorization and code exchange, each
// authenticated by i's attestation, and returns the refresh token.
func (i *attestedInstance) issueRefreshToken() string {
	t := i.t
	t.Helper()
	ctx := context.Background()
	attestations, pops := i.headers()
	push, err := i.h.server.PushAuthorizationRequest(ctx, server.PushAuthorizationRequest{
		HTTP: server.FormRequest{Parameters: []server.FormParameter{
			formParam("client_id", testClientID.String()),
			formParam("response_type", "code"),
			formParam("redirect_uri", testRedirectURI),
			formParam("scope", "openid accounts offline_access"),
			formParam("code_challenge", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"),
			formParam("code_challenge_method", "S256"),
			formParam("state", "opaque-state"),
		}},
		ClientAttestations: attestations, ClientAttestationPoPs: pops,
	})
	if err != nil {
		t.Fatalf("PushAuthorizationRequest: %v", err)
	}
	action, err := i.h.server.BeginAuthorization(ctx, server.BeginAuthorizationRequest{RequestURI: push.RequestURI.String(), ClientID: testClientID})
	if err != nil {
		t.Fatalf("BeginAuthorization: %v", err)
	}
	required, ok := action.(server.InteractionRequired)
	if !ok {
		t.Fatalf("BeginAuthorization = %T, want InteractionRequired", action)
	}
	subjectID, _ := server.NewSubjectID("user-1")
	subject, _ := server.NewAuthenticatedSubject(subjectID)
	authCtx, _ := server.NewAuthenticationContext(i.h.now, "", nil)
	completed, err := i.h.server.CompleteAuthorization(ctx, server.CompleteAuthorizationRequest{
		Handle: required.Handle,
		Result: server.Authorize(subject, authCtx, server.GrantedAuthorization{Scope: []string{"openid", "accounts", "offline_access"}}),
	})
	if err != nil {
		t.Fatalf("CompleteAuthorization: %v", err)
	}
	redirect, ok := completed.(server.AuthorizationRedirect)
	if !ok {
		t.Fatalf("CompleteAuthorization = %T, want AuthorizationRedirect", completed)
	}
	dest := redirect.Destination().URL()
	attestations, pops = i.headers()
	tokens, err := i.h.server.ExchangeAuthorizationCode(ctx, server.AuthorizationCodeExchangeRequest{
		HTTP: server.FormRequest{Parameters: []server.FormParameter{
			formParam("client_id", testClientID.String()),
			formParam("grant_type", "authorization_code"),
			formParam("code", dest.Query().Get("code")),
			formParam("redirect_uri", testRedirectURI),
			formParam("code_verifier", testCodeVerifier),
		}},
		DPoPProofs:         []string{createDPoPProof(t, generateKey(t), i.h.now)},
		ClientAttestations: attestations, ClientAttestationPoPs: pops,
	})
	if err != nil {
		t.Fatalf("ExchangeAuthorizationCode: %v", err)
	}
	if !tokens.HasRefreshToken {
		t.Fatal("no refresh token for offline_access")
	}
	return tokens.RefreshToken.Reveal()
}

// refresh redeems refreshToken authenticated by i's attestation.
func (i *attestedInstance) refresh(refreshToken string) (server.TokenResult, error) {
	attestations, pops := i.headers()
	return i.h.server.RefreshAccessToken(context.Background(), server.RefreshTokenRequest{
		HTTP: server.FormRequest{Parameters: []server.FormParameter{
			formParam("client_id", testClientID.String()),
			formParam("grant_type", "refresh_token"),
			formParam("refresh_token", refreshToken),
		}},
		DPoPProofs:         []string{createDPoPProof(i.t, generateKey(i.t), i.h.now)},
		ClientAttestations: attestations, ClientAttestationPoPs: pops,
	})
}

// TestRefreshTokenBoundToClientInstanceKey covers
// draft-ietf-oauth-attestation-based-client-auth-07 §10.3: a refresh
// token issued to a client authenticated by Client Attestation is
// redeemed only with an attestation for the same Client Instance Key.
// Every installation of a wallet app shares the client_id and a valid
// attestation, so client_id alone doesn't tell them apart.
func TestRefreshTokenBoundToClientInstanceKey(t *testing.T) {
	attesterKey := generateKey(t)
	h := newInstanceBindingHarness(t, attesterKey)
	issuing := &attestedInstance{t: t, h: h, attesterKey: attesterKey, instanceKey: generateKey(t)}
	other := &attestedInstance{t: t, h: h, attesterKey: attesterKey, instanceKey: generateKey(t)}

	refreshToken := issuing.issueRefreshToken()

	_, err := other.refresh(refreshToken)
	var serverErr *server.Error
	if !errors.As(err, &serverErr) || serverErr.Code() != server.ErrorInvalidGrant {
		t.Fatalf("refresh by another instance: err = %v, want invalid_grant", err)
	}

	// The owning instance can still use it, as often as it likes.
	for n := range 2 {
		result, err := issuing.refresh(refreshToken)
		if err != nil {
			t.Fatalf("refresh %d by the issuing instance: %v", n+1, err)
		}
		if result.AccessToken.Reveal() == "" {
			t.Fatalf("refresh %d: no access token", n+1)
		}
	}
}

// TestCIBARefreshTokenBoundToClientInstanceKey is
// TestRefreshTokenBoundToClientInstanceKey for a refresh token issued
// by the CIBA token endpoint.
func TestCIBARefreshTokenBoundToClientInstanceKey(t *testing.T) {
	attesterKey := generateKey(t)
	h := newHarnessWithBackchannelOptions(t, memstore.NewBackchannelAuthenticationStore(), func(cfg *server.Config) {
		cfg.AttestationBasedClientAuthentication = true
		cfg.Algorithms.ClientAttestation = server.AlgorithmSet{fapi.ES256}
		cfg.Algorithms.ClientAttestationPoP = server.AlgorithmSet{fapi.ES256}
		cfg.Limits.MaxClientAttestationLifetime = time.Hour
		cfg.Limits.MaxClientAttestationPoPAge = time.Minute
	}, func(deps *server.Dependencies) {
		client, err := storage.NewRegisteredClient(storage.RegisteredClientConfig{
			ID:                         testClientID,
			RedirectURIs:               []fapi.RegisteredRedirectURI{testRedirectURI},
			ClientAuthMethod:           storage.ClientAuthMethodAttestation,
			ExpectedAttesterIssuer:     testAttesterIssuer,
			ClientAttestationAlgorithm: fapi.ES256,
			AllowedScopes:              []string{"openid", "accounts", "offline_access"},
			BackchannelAuthenticationRequestAlgorithm: fapi.ES256,
		})
		if err != nil {
			t.Fatalf("NewRegisteredClient: %v", err)
		}
		deps.Clients = &fakeClientRepository{clients: map[fapi.ClientID]storage.RegisteredClient{testClientID: client}}
		// The fake key source serves one key for every purpose: the
		// attester's, which also signs the CIBA request object below.
		deps.ClientKeys = &fakeClientKeySource{keysByClient: registeredAttesterKeys(attesterKey)}
		deps.AttesterTrust = server.RegisteredAttesterKeys{}
	})
	h.key = attesterKey
	issuing := &attestedInstance{t: t, h: h, attesterKey: attesterKey, instanceKey: generateKey(t)}
	other := &attestedInstance{t: t, h: h, attesterKey: attesterKey, instanceKey: generateKey(t)}
	ctx := context.Background()

	params := standardBackchannelParams(t)
	params["scope"] = jsonRaw(t, "openid accounts offline_access")
	attestations, pops := issuing.headers()
	action, err := h.server.BeginBackchannelAuthentication(ctx, server.BeginBackchannelAuthenticationRequest{
		HTTP: server.FormRequest{Parameters: []server.FormParameter{
			formParam("client_id", testClientID.String()),
			formParam("request", h.backchannelRequestObject(t, params)),
		}},
		ClientAttestations: attestations, ClientAttestationPoPs: pops,
	})
	if err != nil {
		t.Fatalf("BeginBackchannelAuthentication: %v", err)
	}
	required, ok := action.(server.BackchannelInteractionRequired)
	if !ok {
		t.Fatalf("BeginBackchannelAuthentication = %T, want BackchannelInteractionRequired", action)
	}
	subjectID, _ := server.NewSubjectID("user-1")
	subject, _ := server.NewAuthenticatedSubject(subjectID)
	authCtx, _ := server.NewAuthenticationContext(h.now, "", nil)
	if err := h.server.CompleteBackchannelAuthentication(ctx, server.CompleteBackchannelAuthenticationRequest{
		Handle: required.Handle,
		Result: server.Authorize(subject, authCtx, server.GrantedAuthorization{Scope: []string{"openid", "accounts", "offline_access"}}),
	}); err != nil {
		t.Fatalf("CompleteBackchannelAuthentication: %v", err)
	}
	attestations, pops = issuing.headers()
	tokens, err := h.server.ExchangeBackchannelAuthentication(ctx, server.BackchannelTokenExchangeRequest{
		HTTP: server.FormRequest{Parameters: []server.FormParameter{
			formParam("client_id", testClientID.String()),
			formParam("grant_type", server.CIBAGrantType),
			formParam("auth_req_id", required.AuthReqID.String()),
		}},
		DPoPProofs:         []string{createDPoPProof(t, generateKey(t), h.now)},
		ClientAttestations: attestations, ClientAttestationPoPs: pops,
	})
	if err != nil {
		t.Fatalf("ExchangeBackchannelAuthentication: %v", err)
	}
	if !tokens.HasRefreshToken {
		t.Fatal("no refresh token for offline_access")
	}

	_, err = other.refresh(tokens.RefreshToken.Reveal())
	var serverErr *server.Error
	if !errors.As(err, &serverErr) || serverErr.Code() != server.ErrorInvalidGrant {
		t.Fatalf("refresh by another instance: err = %v, want invalid_grant", err)
	}
	if _, err := issuing.refresh(tokens.RefreshToken.Reveal()); err != nil {
		t.Fatalf("refresh by the issuing instance: %v", err)
	}
}

// TestRefreshTokenIssuedBeforeInstanceBindingStillRedeems covers a
// refresh token issued to an attestation client before refresh tokens
// recorded the Client Instance Key: there is no key to compare, so it
// stays redeemable rather than failing every existing installation on
// upgrade.
func TestRefreshTokenIssuedBeforeInstanceBindingStillRedeems(t *testing.T) {
	attesterKey := generateKey(t)
	h := newInstanceBindingHarness(t, attesterKey)
	issuing := &attestedInstance{t: t, h: h, attesterKey: attesterKey, instanceKey: generateKey(t)}
	refreshToken := issuing.issueRefreshToken()

	h.grants.mu.Lock()
	for hash, stored := range h.grants.refreshByHash {
		var record map[string]json.RawMessage
		if err := json.Unmarshal(stored.Grant, &record); err != nil {
			t.Fatalf("decode stored grant: %v", err)
		}
		if _, ok := record["client_instance_jkt"]; !ok {
			t.Fatalf("stored grant has no client_instance_jkt: %s", stored.Grant)
		}
		delete(record, "client_instance_jkt")
		stored.Grant, _ = json.Marshal(record)
		h.grants.refreshByHash[hash] = stored
	}
	h.grants.mu.Unlock()

	if _, err := issuing.refresh(refreshToken); err != nil {
		t.Fatalf("refresh of a grant without an instance key: %v", err)
	}
}
