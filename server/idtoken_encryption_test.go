package server_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/jwe"
	"github.com/idfoundry/fapigo/internal/token"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
)

// fakeClientEncryptionKeys is a keys.ClientEncryptionKeySource backed by
// a fixed map, mirroring fakeClientKeySource's shape for the
// verification side.
type fakeClientEncryptionKeys struct {
	keysByClient map[fapi.ClientID][]keys.ClientEncryptionKey
	err          error
}

func (f *fakeClientEncryptionKeys) ResolveEncryptionKeys(_ context.Context, req keys.ClientEncryptionKeyRequest) (keys.ClientEncryptionKeySet, error) {
	if f.err != nil {
		return keys.ClientEncryptionKeySet{}, f.err
	}
	return keys.ClientEncryptionKeySet{Keys: f.keysByClient[req.ClientID]}, nil
}

// newHarnessWithIDTokenEncryption mirrors newHarness but registers the
// client for encrypted ID tokens (storage.RegisteredClient's own
// IDTokenEncryptionKeyManagement/ContentEncryption) and lets a test
// control the server-wide allow-list and ClientEncryptionKeys
// dependency independently — for exercising encryptIDToken's own
// checks, which the common-case newHarness callers never touch.
func newHarnessWithIDTokenEncryption(t *testing.T, serverKeyManagement server.KeyManagementAlgorithmSet, serverContentEncryption server.ContentEncryptionAlgorithmSet, clientEncryptionKeys keys.ClientEncryptionKeySource) harness {
	t.Helper()
	now := time.Now()
	key := generateKey(t)
	serverKey := generateKey(t)

	client, err := storage.NewRegisteredClient(storage.RegisteredClientConfig{
		ID:                                 testClientID,
		RedirectURIs:                       []fapi.RegisteredRedirectURI{testRedirectURI},
		ClientAssertionAlgorithm:           fapi.ES256,
		AllowedScopes:                      []string{"openid", "accounts", "offline_access"},
		IDTokenEncryptionKeyManagement:     fapi.RSAOAEP256,
		IDTokenEncryptionContentEncryption: fapi.A256GCM,
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
			ClientAssertion:                    server.AlgorithmSet{fapi.ES256},
			RequestObject:                      server.AlgorithmSet{fapi.ES256},
			JARM:                               fapi.ES256,
			IDToken:                            fapi.ES256,
			IDTokenEncryptionKeyManagement:     serverKeyManagement,
			IDTokenEncryptionContentEncryption: serverContentEncryption,
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
		},
		Assurance: server.AssuranceDevelopment,
	}
	serverKeyManager := &fakeKeyManager{key: serverKey, keyID: "as-key-1"}
	deps := server.Dependencies{
		Clients:      &fakeClientRepository{clients: map[fapi.ClientID]storage.RegisteredClient{testClientID: client}},
		Transactions: &fakeTransactionStore{},
		Grants:       &fakeGrantStore{},
		Replay:       &fakeReplayStore{},
		ClientKeys: &fakeClientKeySource{keysByClient: map[fapi.ClientID][]keys.VerificationKey{
			testClientID: {{Algorithm: fapi.ES256, PublicKey: &key.PublicKey}},
		}},
		ClientEncryptionKeys: clientEncryptionKeys,
		Keys:                 serverKeyManager,
		AccessTokens:         server.JWTAccessTokens{Keys: serverKeyManager, Algorithm: fapi.ES256},
		Revocation:           &fakeRevocationSink{},
		Audit:                &fakeAuditSink{},
		Clock:                fixedClock{now: now},
		Random:               rand.Reader,
	}
	srv, err := server.New(cfg, deps)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	return harness{server: srv, key: key, serverKey: serverKey, now: now}
}

// TestExchangeAuthorizationCodeIssuesEncryptedIDToken confirms that,
// once a client is registered for encrypted ID tokens and the server
// allows the algorithm pair, ExchangeAuthorizationCode's ID token comes
// back as a JWE (not a bare signed JWT), decrypts to a nested JWT
// (cty="JWT", OIDC Core §10.2), and the nested JWT verifies and carries
// the expected claims — sign-then-encrypt end to end.
func TestExchangeAuthorizationCodeIssuesEncryptedIDToken(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	encKeys := &fakeClientEncryptionKeys{keysByClient: map[fapi.ClientID][]keys.ClientEncryptionKey{
		testClientID: {{KeyID: "enc-key-1", Algorithm: fapi.RSAOAEP256, PublicKey: &rsaKey.PublicKey}},
	}}
	h := newHarnessWithIDTokenEncryption(t,
		server.KeyManagementAlgorithmSet{fapi.RSAOAEP256},
		server.ContentEncryptionAlgorithmSet{fapi.A256GCM},
		encKeys,
	)
	code := completeSuccessfulAuthorization(t, h, []string{"openid", "accounts"})

	result, err := h.server.ExchangeAuthorizationCode(context.Background(), server.AuthorizationCodeExchangeRequest{
		HTTP:      server.FormRequest{Parameters: exchangeFormParams(h.clientAssertion(t), code, testRedirectURI, testCodeVerifier)},
		DPoPProof: createDPoPProof(t, generateKey(t), h.now),
	})
	if err != nil {
		t.Fatalf("ExchangeAuthorizationCode: %v", err)
	}
	if !result.HasIDToken || result.IDToken.Reveal() == "" {
		t.Fatalf("expected an ID token since scope included openid")
	}

	decrypted, err := jwe.Decrypt(context.Background(), jwe.DecryptRequest{
		Algorithm: fapi.RSAOAEP256, Encryption: fapi.A256GCM,
		RecipientKey: rsaKey,
		Compact:      result.IDToken.Reveal(),
	})
	if err != nil {
		t.Fatalf("jwe.Decrypt: %v", err)
	}
	if decrypted.Header.ContentType != "JWT" {
		t.Fatalf("ContentType = %q, want %q", decrypted.Header.ContentType, "JWT")
	}
	if decrypted.Header.KeyID != "enc-key-1" {
		t.Fatalf("KeyID = %q, want %q", decrypted.Header.KeyID, "enc-key-1")
	}

	parsedIDT, err := token.ParseIDToken(string(decrypted.Plaintext))
	if err != nil {
		t.Fatalf("ParseIDToken: %v", err)
	}
	validatedIDT, err := parsedIDT.Validate(&h.serverKey.PublicKey, token.IDTokenValidatePolicy{
		ExpectedIssuer: testIssuer, ExpectedAudience: testClientID.String(),
		Algorithm: fapi.ES256, Now: h.now, MaxLifetime: 10 * time.Minute,
	})
	if err != nil {
		t.Fatalf("Validate ID token: %v", err)
	}
	if validatedIDT.Subject != "user-1" {
		t.Fatalf("id token Subject = %q, want %q", validatedIDT.Subject, "user-1")
	}
}

// TestRefreshAccessTokenIssuesEncryptedIDToken confirms the refresh
// grant's ID token issuance (server/refresh.go), a second call site
// sharing issueIDToken with ExchangeAuthorizationCode, also encrypts —
// this is a distinct code path, not exercised by the exchange-side
// test above.
func TestRefreshAccessTokenIssuesEncryptedIDToken(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	encKeys := &fakeClientEncryptionKeys{keysByClient: map[fapi.ClientID][]keys.ClientEncryptionKey{
		testClientID: {{KeyID: "enc-key-1", Algorithm: fapi.RSAOAEP256, PublicKey: &rsaKey.PublicKey}},
	}}
	h := newHarnessWithIDTokenEncryption(t,
		server.KeyManagementAlgorithmSet{fapi.RSAOAEP256},
		server.ContentEncryptionAlgorithmSet{fapi.A256GCM},
		encKeys,
	)
	first, dpopKey := exchangeForTokensWithOfflineAccess(t, h)

	result, err := h.server.RefreshAccessToken(context.Background(), server.RefreshTokenRequest{
		HTTP:      server.FormRequest{Parameters: refreshFormParams(h.clientAssertion(t), first.RefreshToken.Reveal(), "")},
		DPoPProof: createDPoPProof(t, dpopKey, h.now),
	})
	if err != nil {
		t.Fatalf("RefreshAccessToken: %v", err)
	}
	if !result.HasIDToken || result.IDToken.Reveal() == "" {
		t.Fatalf("expected an ID token since scope included openid")
	}

	decrypted, err := jwe.Decrypt(context.Background(), jwe.DecryptRequest{
		Algorithm: fapi.RSAOAEP256, Encryption: fapi.A256GCM,
		RecipientKey: rsaKey,
		Compact:      result.IDToken.Reveal(),
	})
	if err != nil {
		t.Fatalf("jwe.Decrypt: %v", err)
	}
	if decrypted.Header.ContentType != "JWT" {
		t.Fatalf("ContentType = %q, want %q", decrypted.Header.ContentType, "JWT")
	}
}

// TestExchangeAuthorizationCodeRejectsIDTokenEncryptionNotPermittedByServer
// covers the downgrade-relevant misconfiguration case: a client
// registered for encrypted ID tokens, but the operator's server-wide
// allow-list doesn't include the algorithm — encryptIDToken must fail
// the exchange rather than silently falling back to a bare signed JWT
// (see storage.RegisteredClientConfig's own doc comment: the two are
// cross-checked at issuance time, not at registration).
func TestExchangeAuthorizationCodeRejectsIDTokenEncryptionNotPermittedByServer(t *testing.T) {
	h := newHarnessWithIDTokenEncryption(t, nil, nil, nil)
	code := completeSuccessfulAuthorization(t, h, []string{"openid", "accounts"})

	_, err := h.server.ExchangeAuthorizationCode(context.Background(), server.AuthorizationCodeExchangeRequest{
		HTTP:      server.FormRequest{Parameters: exchangeFormParams(h.clientAssertion(t), code, testRedirectURI, testCodeVerifier)},
		DPoPProof: createDPoPProof(t, generateKey(t), h.now),
	})
	if err == nil {
		t.Fatalf("ExchangeAuthorizationCode(server disallows configured encryption) = nil error, want error")
	}
	if code := serverErrorCode(t, err); code != server.ErrorServerError {
		t.Fatalf("error code = %q, want %q", code, server.ErrorServerError)
	}
}

// TestExchangeAuthorizationCodeRejectsIDTokenEncryptionKeyResolutionFailure
// covers the ClientEncryptionKeySource returning no matching key —
// e.g. a client mid-rotation with no key registered yet for the
// algorithm it declared.
func TestExchangeAuthorizationCodeRejectsIDTokenEncryptionKeyResolutionFailure(t *testing.T) {
	encKeys := &fakeClientEncryptionKeys{keysByClient: map[fapi.ClientID][]keys.ClientEncryptionKey{}}
	h := newHarnessWithIDTokenEncryption(t,
		server.KeyManagementAlgorithmSet{fapi.RSAOAEP256},
		server.ContentEncryptionAlgorithmSet{fapi.A256GCM},
		encKeys,
	)
	code := completeSuccessfulAuthorization(t, h, []string{"openid", "accounts"})

	_, err := h.server.ExchangeAuthorizationCode(context.Background(), server.AuthorizationCodeExchangeRequest{
		HTTP:      server.FormRequest{Parameters: exchangeFormParams(h.clientAssertion(t), code, testRedirectURI, testCodeVerifier)},
		DPoPProof: createDPoPProof(t, generateKey(t), h.now),
	})
	if err == nil {
		t.Fatalf("ExchangeAuthorizationCode(no matching encryption key) = nil error, want error")
	}
	if code := serverErrorCode(t, err); code != server.ErrorServerError {
		t.Fatalf("error code = %q, want %q", code, server.ErrorServerError)
	}
}
