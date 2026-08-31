package server_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"net/url"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/clientassertion"
	"github.com/idfoundry/fapigo/internal/dpop"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
	"github.com/idfoundry/fapigo/storage/memstore"
)

// --- Config/Dependencies validation ---------------------------------

func TestNewAcceptsZeroNonceLifetimeWhenNoncesUnset(t *testing.T) {
	cfg := validConfig(t)
	cfg.Limits.DPoPNonceLifetime = 0
	if _, err := server.New(cfg, validDependencies()); err != nil {
		t.Fatalf("New: %v", err)
	}
}

func TestNewRejectsInvalidNonceConfig(t *testing.T) {
	nonces := memstore.NewNonceStore()

	t.Run("zero nonce lifetime with nonces set", func(t *testing.T) {
		cfg := validConfig(t)
		cfg.Limits.DPoPNonceLifetime = 0
		deps := validDependencies()
		deps.Nonces = nonces
		if _, err := server.New(cfg, deps); err == nil {
			t.Fatalf("New(zero nonce lifetime, nonces set) = nil error, want error")
		}
	})

	t.Run("nonces and lifetime both set", func(t *testing.T) {
		cfg := validConfig(t)
		cfg.Limits.DPoPNonceLifetime = time.Minute
		deps := validDependencies()
		deps.Nonces = nonces
		if _, err := server.New(cfg, deps); err != nil {
			t.Fatalf("New: %v", err)
		}
	})
}

// --- harness wiring ------------------------------------------------

// newHarnessWithNonces mirrors newHarnessWithIdentityClaims's shape
// (identity_claims_test.go), but wires a memstore.NonceStore and
// Limits.DPoPNonceLifetime so token/PAR nonce-challenge tests don't have
// to duplicate every other piece of a valid harness.
func newHarnessWithNonces(t *testing.T) (harness, *memstore.NonceStore) {
	t.Helper()
	now := time.Now()
	key := generateKey(t)
	serverKey := generateKey(t)

	client, err := storage.NewRegisteredClient(storage.RegisteredClientConfig{
		ID:                       testClientID,
		RedirectURIs:             []fapi.RegisteredRedirectURI{testRedirectURI},
		ClientAssertionAlgorithm: fapi.ES256,
		AllowedScopes:            []string{"openid", "accounts", "offline_access"},
	})
	if err != nil {
		t.Fatalf("NewRegisteredClient: %v", err)
	}
	issuer, err := fapi.ParseIssuerURL(testIssuer)
	if err != nil {
		t.Fatalf("ParseIssuerURL: %v", err)
	}

	cfg := server.Config{
		Issuer:    issuer,
		Endpoints: testEndpoints(t),
		Profile:   server.ProfileFAPISecurity,
		Algorithms: server.AlgorithmPolicy{
			ClientAssertion: server.AlgorithmSet{fapi.ES256},
			RequestObject:   server.AlgorithmSet{fapi.ES256},
			JARM:            fapi.ES256,
			IDToken:         fapi.ES256,
		},
		Limits: server.Limits{
			PushedRequestLifetime:      90 * time.Second,
			MaxClientAssertionLifetime: time.Minute,
			MaxRequestObjectLifetime:   time.Minute,
			InteractionLifetime:        5 * time.Minute,
			AuthorizationCodeLifetime:  time.Minute,
			JARMResponseLifetime:       time.Minute,
			AccessTokenLifetime:        5 * time.Minute,
			IDTokenLifetime:            5 * time.Minute,
			RefreshTokenLifetime:       5 * time.Minute,
			MaxDPoPProofAge:            time.Minute,
			MaxClockSkew:               5 * time.Second,
			DPoPNonceLifetime:          time.Minute,
		},
		Assurance: server.AssuranceDevelopment,
	}
	serverKeyManager := &fakeKeyManager{key: serverKey, keyID: "as-key-1"}
	nonces := memstore.NewNonceStore()
	deps := server.Dependencies{
		Clients:      &fakeClientRepository{clients: map[fapi.ClientID]storage.RegisteredClient{testClientID: client}},
		Transactions: &fakeTransactionStore{},
		Grants:       &fakeGrantStore{},
		Replay:       &fakeReplayStore{},
		ClientKeys: &fakeClientKeySource{keysByClient: map[fapi.ClientID][]keys.VerificationKey{
			testClientID: {{Algorithm: fapi.ES256, PublicKey: &key.PublicKey}},
		}},
		Keys:         serverKeyManager,
		AccessTokens: server.JWTAccessTokens{Keys: serverKeyManager, Algorithm: fapi.ES256},
		Revocation:   server.NoRevocation{},
		Clock:        fixedClock{now: now},
		Random:       rand.Reader,
		Nonces:       nonces,
	}
	srv, err := server.New(cfg, deps)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	return harness{server: srv, key: key, serverKey: serverKey, now: now}, nonces
}

// exchangeWithDPoPNonce runs a full ExchangeAuthorizationCode attempt
// (a fresh authorization code each call, since codes are single-use)
// with a DPoP proof carrying nonce ("" for none).
func exchangeWithDPoPNonce(t *testing.T, h harness, dpopKey *ecdsa.PrivateKey, nonce string) (server.TokenResult, error) {
	t.Helper()
	code := completeSuccessfulAuthorization(t, h, []string{"openid", "accounts"})
	tokenURL, err := url.Parse(testTokenEndpoint)
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}
	proof, err := dpop.CreateProof(dpop.ProofRequest{
		Signer: dpopKey, Algorithm: fapi.ES256, Method: "POST", URL: tokenURL, Now: h.now, Nonce: nonce,
	})
	if err != nil {
		t.Fatalf("dpop.CreateProof: %v", err)
	}
	return h.server.ExchangeAuthorizationCode(context.Background(), server.AuthorizationCodeExchangeRequest{
		HTTP:       server.FormRequest{Parameters: exchangeFormParams(h.clientAssertion(t), code, testRedirectURI, testCodeVerifier)},
		DPoPProofs: []string{proof},
	})
}

// --- Token endpoint (ExchangeAuthorizationCode / RefreshAccessToken) ---

func TestExchangeAuthorizationCodeNonceDisabledByDefault(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	code := completeSuccessfulAuthorization(t, h, []string{"openid", "accounts"})
	dpopKey := generateKey(t)

	result, err := h.server.ExchangeAuthorizationCode(context.Background(), server.AuthorizationCodeExchangeRequest{
		HTTP:       server.FormRequest{Parameters: exchangeFormParams(h.clientAssertion(t), code, testRedirectURI, testCodeVerifier)},
		DPoPProofs: []string{createDPoPProof(t, dpopKey, h.now)},
	})
	if err != nil {
		t.Fatalf("ExchangeAuthorizationCode: %v", err)
	}
	if result.NextDPoPNonce != "" {
		t.Errorf("NextDPoPNonce = %q, want empty when nonces disabled", result.NextDPoPNonce)
	}
}

func TestExchangeAuthorizationCodeChallengesMissingNonce(t *testing.T) {
	h, _ := newHarnessWithNonces(t)
	dpopKey := generateKey(t)

	_, err := exchangeWithDPoPNonce(t, h, dpopKey, "")
	if err == nil {
		t.Fatalf("ExchangeAuthorizationCode(no nonce) = nil error, want error")
	}
	serr, ok := err.(*server.Error)
	if !ok {
		t.Fatalf("error type = %T, want *server.Error", err)
	}
	if serr.Code() != server.ErrorUseDPoPNonce {
		t.Errorf("Code() = %v, want %v", serr.Code(), server.ErrorUseDPoPNonce)
	}
	if serr.Nonce() == "" {
		t.Errorf("Nonce() is empty, want a freshly issued nonce")
	}
}

func TestExchangeAuthorizationCodeChallengesUnknownNonce(t *testing.T) {
	h, _ := newHarnessWithNonces(t)
	dpopKey := generateKey(t)

	_, err := exchangeWithDPoPNonce(t, h, dpopKey, "never-issued")
	serr, ok := err.(*server.Error)
	if !ok {
		t.Fatalf("error type = %T, want *server.Error", err)
	}
	if serr.Code() != server.ErrorUseDPoPNonce {
		t.Errorf("Code() = %v, want %v", serr.Code(), server.ErrorUseDPoPNonce)
	}
}

func TestExchangeAuthorizationCodeChallengesExpiredNonce(t *testing.T) {
	h, nonces := newHarnessWithNonces(t)
	if err := nonces.Issue(context.Background(), storage.NonceIssuance{
		Nonce: "stale-nonce", ExpiresAt: h.now.Add(-time.Minute),
	}); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	dpopKey := generateKey(t)

	_, err := exchangeWithDPoPNonce(t, h, dpopKey, "stale-nonce")
	serr, ok := err.(*server.Error)
	if !ok {
		t.Fatalf("error type = %T, want *server.Error", err)
	}
	if serr.Code() != server.ErrorUseDPoPNonce {
		t.Errorf("Code() = %v, want %v", serr.Code(), server.ErrorUseDPoPNonce)
	}
}

func TestExchangeAuthorizationCodeAcceptsValidNonceAndIssuesNext(t *testing.T) {
	h, _ := newHarnessWithNonces(t)
	dpopKey := generateKey(t)

	_, err := exchangeWithDPoPNonce(t, h, dpopKey, "")
	serr, ok := err.(*server.Error)
	if !ok {
		t.Fatalf("error type = %T, want *server.Error", err)
	}
	issued := serr.Nonce()

	result, err := exchangeWithDPoPNonce(t, h, dpopKey, issued)
	if err != nil {
		t.Fatalf("ExchangeAuthorizationCode(valid nonce): %v", err)
	}
	if result.NextDPoPNonce == "" {
		t.Fatalf("NextDPoPNonce is empty, want a freshly issued nonce")
	}
	if result.NextDPoPNonce == issued {
		t.Fatalf("NextDPoPNonce = %q, want different from the just-consumed nonce %q", result.NextDPoPNonce, issued)
	}

	// The consumed nonce is single-use: presenting it again must fail
	// (with a fresh authorization code, since the previous one is
	// already spent by the successful exchange above).
	if _, err := exchangeWithDPoPNonce(t, h, dpopKey, issued); err == nil {
		t.Fatalf("ExchangeAuthorizationCode(reused nonce) = nil error, want error")
	}
}

// TestExchangeAuthorizationCodeNonceCheckedBeforeCodeRedemption confirms
// a challenged attempt never actually redeems the authorization code —
// the same code must still work once retried with a valid nonce,
// exactly the shape a real client's single retry produces (RFC 9449
// §8: the same request, replayed with a fresh proof carrying the
// nonce).
func TestExchangeAuthorizationCodeNonceCheckedBeforeCodeRedemption(t *testing.T) {
	h, _ := newHarnessWithNonces(t)
	dpopKey := generateKey(t)
	code := completeSuccessfulAuthorization(t, h, []string{"openid", "accounts"})
	tokenURL, err := url.Parse(testTokenEndpoint)
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}
	proofWithoutNonce, err := dpop.CreateProof(dpop.ProofRequest{
		Signer: dpopKey, Algorithm: fapi.ES256, Method: "POST", URL: tokenURL, Now: h.now,
	})
	if err != nil {
		t.Fatalf("dpop.CreateProof: %v", err)
	}

	_, err = h.server.ExchangeAuthorizationCode(context.Background(), server.AuthorizationCodeExchangeRequest{
		HTTP:       server.FormRequest{Parameters: exchangeFormParams(h.clientAssertion(t), code, testRedirectURI, testCodeVerifier)},
		DPoPProofs: []string{proofWithoutNonce},
	})
	serr, ok := err.(*server.Error)
	if !ok {
		t.Fatalf("error type = %T, want *server.Error", err)
	}
	if serr.Code() != server.ErrorUseDPoPNonce {
		t.Fatalf("Code() = %v, want %v", serr.Code(), server.ErrorUseDPoPNonce)
	}

	// The retry reuses the same authorization code — proving the first,
	// challenged attempt never redeemed it — but needs a fresh client
	// assertion and DPoP proof, exactly like a real client's retry
	// (client/exchange_code.go's sendTokenRequest rebuilds the whole
	// form for the same reason: a client assertion is exactly as
	// single-use as a DPoP proof).
	proofWithNonce, err := dpop.CreateProof(dpop.ProofRequest{
		Signer: dpopKey, Algorithm: fapi.ES256, Method: "POST", URL: tokenURL, Now: h.now, Nonce: serr.Nonce(),
	})
	if err != nil {
		t.Fatalf("dpop.CreateProof: %v", err)
	}
	if _, err := h.server.ExchangeAuthorizationCode(context.Background(), server.AuthorizationCodeExchangeRequest{
		HTTP:       server.FormRequest{Parameters: exchangeFormParams(h.clientAssertion(t), code, testRedirectURI, testCodeVerifier)},
		DPoPProofs: []string{proofWithNonce},
	}); err != nil {
		t.Fatalf("retry with the same authorization code and a valid nonce: %v", err)
	}
}

func TestRefreshAccessTokenReissuesNonceOnSuccess(t *testing.T) {
	h, _ := newHarnessWithNonces(t)
	dpopKey := generateKey(t)

	code := completeSuccessfulAuthorization(t, h, []string{"openid", "accounts", "offline_access"})
	tokenURL, err := url.Parse(testTokenEndpoint)
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}
	firstProof, err := dpop.CreateProof(dpop.ProofRequest{
		Signer: dpopKey, Algorithm: fapi.ES256, Method: "POST", URL: tokenURL, Now: h.now,
	})
	if err != nil {
		t.Fatalf("dpop.CreateProof: %v", err)
	}
	_, err = h.server.ExchangeAuthorizationCode(context.Background(), server.AuthorizationCodeExchangeRequest{
		HTTP:       server.FormRequest{Parameters: exchangeFormParams(h.clientAssertion(t), code, testRedirectURI, testCodeVerifier)},
		DPoPProofs: []string{firstProof},
	})
	serr, ok := err.(*server.Error)
	if !ok {
		t.Fatalf("expected the first, nonce-less exchange to be challenged; error type = %T", err)
	}

	code = completeSuccessfulAuthorization(t, h, []string{"openid", "accounts", "offline_access"})
	proof, err := dpop.CreateProof(dpop.ProofRequest{
		Signer: dpopKey, Algorithm: fapi.ES256, Method: "POST", URL: tokenURL, Now: h.now, Nonce: serr.Nonce(),
	})
	if err != nil {
		t.Fatalf("dpop.CreateProof: %v", err)
	}
	result, err := h.server.ExchangeAuthorizationCode(context.Background(), server.AuthorizationCodeExchangeRequest{
		HTTP:       server.FormRequest{Parameters: exchangeFormParams(h.clientAssertion(t), code, testRedirectURI, testCodeVerifier)},
		DPoPProofs: []string{proof},
	})
	if err != nil {
		t.Fatalf("ExchangeAuthorizationCode: %v", err)
	}
	if !result.HasRefreshToken {
		t.Fatalf("expected a refresh token since scope included offline_access")
	}

	refreshProof, err := dpop.CreateProof(dpop.ProofRequest{
		Signer: dpopKey, Algorithm: fapi.ES256, Method: "POST", URL: tokenURL, Now: h.now, Nonce: result.NextDPoPNonce,
	})
	if err != nil {
		t.Fatalf("dpop.CreateProof: %v", err)
	}
	refreshed, err := h.server.RefreshAccessToken(context.Background(), server.RefreshTokenRequest{
		HTTP: server.FormRequest{Parameters: []server.FormParameter{
			formParam("client_assertion", h.clientAssertion(t)),
			formParam("client_assertion_type", clientassertion.AssertionType),
			formParam("grant_type", "refresh_token"),
			formParam("refresh_token", result.RefreshToken.Reveal()),
		}},
		DPoPProofs: []string{refreshProof},
	})
	if err != nil {
		t.Fatalf("RefreshAccessToken: %v", err)
	}
	if refreshed.NextDPoPNonce == "" {
		t.Fatalf("NextDPoPNonce is empty, want a freshly issued nonce")
	}
}

// --- PAR ---------------------------------------------------------------

func parFormParams(t *testing.T, h harness) []server.FormParameter {
	t.Helper()
	return []server.FormParameter{
		formParam("client_assertion", h.clientAssertion(t)),
		formParam("client_assertion_type", clientassertion.AssertionType),
		formParam("response_type", "code"),
		formParam("redirect_uri", testRedirectURI),
		formParam("scope", "openid accounts"),
		formParam("code_challenge", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"),
		formParam("code_challenge_method", "S256"),
		formParam("state", "opaque-state"),
	}
}

// TestPushAuthorizationRequestWithoutDPoPUnaffectedByNonceChallenge is
// the key regression case: PAR's own DPoP proof stays entirely
// optional even with nonce-challenge enabled — a client that never
// sends one there is unaffected.
func TestPushAuthorizationRequestWithoutDPoPUnaffectedByNonceChallenge(t *testing.T) {
	h, _ := newHarnessWithNonces(t)
	result, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
		HTTP: server.FormRequest{Parameters: parFormParams(t, h)},
	})
	if err != nil {
		t.Fatalf("PushAuthorizationRequest (no DPoP proof) = %v, want success even with nonce-challenge enabled", err)
	}
	if result.NextDPoPNonce == "" {
		t.Fatalf("NextDPoPNonce is empty, want a freshly issued nonce even without a proof presented")
	}
}

func TestPushAuthorizationRequestChallengesMissingNonceWhenDPoPPresented(t *testing.T) {
	h, _ := newHarnessWithNonces(t)
	dpopKey := generateKey(t)
	parURL, err := url.Parse(testPAREndpoint)
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}
	proof, err := dpop.CreateProof(dpop.ProofRequest{
		Signer: dpopKey, Algorithm: fapi.ES256, Method: "POST", URL: parURL, Now: h.now,
	})
	if err != nil {
		t.Fatalf("dpop.CreateProof: %v", err)
	}

	_, err = h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
		HTTP: server.FormRequest{Parameters: parFormParams(t, h)}, DPoPProofs: []string{proof},
	})
	serr, ok := err.(*server.Error)
	if !ok {
		t.Fatalf("error type = %T, want *server.Error", err)
	}
	if serr.Code() != server.ErrorUseDPoPNonce {
		t.Errorf("Code() = %v, want %v", serr.Code(), server.ErrorUseDPoPNonce)
	}
	if serr.Nonce() == "" {
		t.Errorf("Nonce() is empty, want a freshly issued nonce")
	}
}

func TestPushAuthorizationRequestAcceptsValidNonceAndIssuesNext(t *testing.T) {
	h, _ := newHarnessWithNonces(t)
	dpopKey := generateKey(t)
	parURL, err := url.Parse(testPAREndpoint)
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}
	firstProof, err := dpop.CreateProof(dpop.ProofRequest{
		Signer: dpopKey, Algorithm: fapi.ES256, Method: "POST", URL: parURL, Now: h.now,
	})
	if err != nil {
		t.Fatalf("dpop.CreateProof: %v", err)
	}
	_, err = h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
		HTTP: server.FormRequest{Parameters: parFormParams(t, h)}, DPoPProofs: []string{firstProof},
	})
	serr, ok := err.(*server.Error)
	if !ok {
		t.Fatalf("error type = %T, want *server.Error", err)
	}
	issued := serr.Nonce()

	retryProof, err := dpop.CreateProof(dpop.ProofRequest{
		Signer: dpopKey, Algorithm: fapi.ES256, Method: "POST", URL: parURL, Now: h.now, Nonce: issued,
	})
	if err != nil {
		t.Fatalf("dpop.CreateProof: %v", err)
	}
	result, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
		HTTP: server.FormRequest{Parameters: parFormParams(t, h)}, DPoPProofs: []string{retryProof},
	})
	if err != nil {
		t.Fatalf("PushAuthorizationRequest(valid nonce): %v", err)
	}
	if result.NextDPoPNonce == "" || result.NextDPoPNonce == issued {
		t.Fatalf("NextDPoPNonce = %q, want a fresh value different from %q", result.NextDPoPNonce, issued)
	}
}

// TestNonceIssuedAtPARIsValidAtTokenEndpoint confirms one shared nonce
// store covers everything this server verifies (Dependencies.Nonces's
// own doc comment) — a nonce issued from a PAR challenge must also be
// accepted at the token endpoint.
func TestNonceIssuedAtPARIsValidAtTokenEndpoint(t *testing.T) {
	h, _ := newHarnessWithNonces(t)
	dpopKey := generateKey(t)
	parURL, err := url.Parse(testPAREndpoint)
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}
	parProof, err := dpop.CreateProof(dpop.ProofRequest{
		Signer: dpopKey, Algorithm: fapi.ES256, Method: "POST", URL: parURL, Now: h.now,
	})
	if err != nil {
		t.Fatalf("dpop.CreateProof: %v", err)
	}
	_, err = h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
		HTTP: server.FormRequest{Parameters: parFormParams(t, h)}, DPoPProofs: []string{parProof},
	})
	serr, ok := err.(*server.Error)
	if !ok {
		t.Fatalf("expected the first, nonce-less PAR call to be challenged; error type = %T", err)
	}

	if _, err := exchangeWithDPoPNonce(t, h, dpopKey, serr.Nonce()); err != nil {
		t.Fatalf("ExchangeAuthorizationCode(nonce issued by PAR): %v", err)
	}
}
