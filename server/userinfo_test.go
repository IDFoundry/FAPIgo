package server_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/jose"
	"github.com/idfoundry/fapigo/internal/jwe"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
)

// newHarnessWithUserInfo mirrors newHarnessWithIDTokenEncryption but for
// UserInfo signing/encryption — server.Algorithms.UserInfo is always set
// to ES256 (so SignUserInfoResponse's own configured-check passes); the
// UserInfo encryption allow-list and the client's own
// UserInfoEncryptionKeyManagement/ContentEncryption registration are
// each independently controlled by a test, mirroring how the ID token
// encryption harness lets server-wide policy and client registration
// vary independently. Returns the exact storage.RegisteredClient
// registered against the server, since (unlike newHarness's plain
// client) its UserInfoEncryption fields matter to the tests below.
func newHarnessWithUserInfo(t *testing.T, serverKeyManagement server.KeyManagementAlgorithmSet, serverContentEncryption server.ContentEncryptionAlgorithmSet, clientKeyManagement fapi.KeyManagementAlgorithm, clientContentEncryption fapi.ContentEncryptionAlgorithm, clientEncryptionKeys keys.ClientEncryptionKeySource) (harness, storage.RegisteredClient) {
	t.Helper()
	now := time.Now()
	key := generateKey(t)
	serverKey := generateKey(t)

	client, err := storage.NewRegisteredClient(storage.RegisteredClientConfig{
		ID:                                  testClientID,
		RedirectURIs:                        []fapi.RegisteredRedirectURI{testRedirectURI},
		ClientAssertionAlgorithm:            fapi.ES256,
		AllowedScopes:                       []string{"openid", "accounts", "offline_access"},
		UserInfoEncryptionKeyManagement:     clientKeyManagement,
		UserInfoEncryptionContentEncryption: clientContentEncryption,
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
			ClientAssertion:                     server.AlgorithmSet{fapi.ES256},
			RequestObject:                       server.AlgorithmSet{fapi.ES256},
			JARM:                                fapi.ES256,
			IDToken:                             fapi.ES256,
			UserInfo:                            fapi.ES256,
			UserInfoEncryptionKeyManagement:     serverKeyManagement,
			UserInfoEncryptionContentEncryption: serverContentEncryption,
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
	return harness{server: srv, key: key, serverKey: serverKey, now: now}, client
}

func testUserInfoClaims(t *testing.T) map[string]json.RawMessage {
	t.Helper()
	sub, err := json.Marshal("user-1")
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	email, err := json.Marshal("user-1@example.com")
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	return map[string]json.RawMessage{"sub": sub, "email": email}
}

// TestSignUserInfoResponseProducesVerifiableJWS confirms the plain
// (unencrypted) case: a JWS signed under the configured algorithm,
// verifiable against the server's own signing key, carrying exactly the
// claims passed in.
func TestSignUserInfoResponseProducesVerifiableJWS(t *testing.T) {
	h, client := newHarnessWithUserInfo(t, nil, nil, 0, 0, nil)

	signed, srvErr := h.server.SignUserInfoResponse(context.Background(), client, testUserInfoClaims(t))
	if srvErr != nil {
		t.Fatalf("SignUserInfoResponse: %v", srvErr)
	}

	compact, err := jose.ParseCompact(signed)
	if err != nil {
		t.Fatalf("ParseCompact: %v", err)
	}
	if err := compact.Verify(&h.serverKey.PublicKey, fapi.ES256); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	var claims map[string]string
	if err := json.Unmarshal(compact.Payload, &claims); err != nil {
		t.Fatalf("Unmarshal payload: %v", err)
	}
	if claims["sub"] != "user-1" || claims["email"] != "user-1@example.com" {
		t.Fatalf("claims = %v, want sub=user-1 email=user-1@example.com", claims)
	}
}

// TestSignUserInfoResponseEncryptsWhenClientRegistered confirms that
// once a client is registered for encrypted UserInfo responses and the
// server allows the algorithm pair, the result is a JWE that decrypts
// to a nested, verifiable JWT (cty="JWT", OIDC Core §5.3.2) — the same
// sign-then-encrypt shape ID token issuance already has.
func TestSignUserInfoResponseEncryptsWhenClientRegistered(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	encKeys := &fakeClientEncryptionKeys{keysByClient: map[fapi.ClientID][]keys.ClientEncryptionKey{
		testClientID: {{KeyID: "enc-key-1", Algorithm: fapi.RSAOAEP256, PublicKey: &rsaKey.PublicKey}},
	}}
	h, client := newHarnessWithUserInfo(t,
		server.KeyManagementAlgorithmSet{fapi.RSAOAEP256},
		server.ContentEncryptionAlgorithmSet{fapi.A256GCM},
		fapi.RSAOAEP256, fapi.A256GCM,
		encKeys,
	)

	signed, srvErr := h.server.SignUserInfoResponse(context.Background(), client, testUserInfoClaims(t))
	if srvErr != nil {
		t.Fatalf("SignUserInfoResponse: %v", srvErr)
	}

	decrypted, err := jwe.Decrypt(context.Background(), jwe.DecryptRequest{
		Algorithm: fapi.RSAOAEP256, Encryption: fapi.A256GCM,
		RecipientKey: rsaKey,
		Compact:      signed,
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

	compact, err := jose.ParseCompact(string(decrypted.Plaintext))
	if err != nil {
		t.Fatalf("ParseCompact: %v", err)
	}
	if err := compact.Verify(&h.serverKey.PublicKey, fapi.ES256); err != nil {
		t.Fatalf("Verify nested JWS: %v", err)
	}
}

// TestSignUserInfoResponseFailsWhenNotConfigured confirms
// Algorithms.UserInfo unset produces a clear ErrorServerError, not a
// silent fall-through to plain JSON — this method has one job.
func TestSignUserInfoResponseFailsWhenNotConfigured(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	client := testRegisteredClient(t)

	_, srvErr := h.server.SignUserInfoResponse(context.Background(), client, testUserInfoClaims(t))
	if srvErr == nil {
		t.Fatalf("SignUserInfoResponse(unconfigured) = nil error, want error")
	}
	if srvErr.Code() != server.ErrorServerError {
		t.Fatalf("error code = %q, want %q", srvErr.Code(), server.ErrorServerError)
	}
}

// TestSignUserInfoResponseRejectsEncryptionNotPermittedByServer covers
// the downgrade-relevant misconfiguration case: a client registered for
// encrypted UserInfo responses, but the operator's server-wide allow-list
// doesn't include the algorithm — encryptUserInfoResponse must fail
// rather than silently falling back to a bare signed JWT.
func TestSignUserInfoResponseRejectsEncryptionNotPermittedByServer(t *testing.T) {
	h, client := newHarnessWithUserInfo(t, nil, nil, fapi.RSAOAEP256, fapi.A256GCM, nil)

	_, srvErr := h.server.SignUserInfoResponse(context.Background(), client, testUserInfoClaims(t))
	if srvErr == nil {
		t.Fatalf("SignUserInfoResponse(server disallows configured encryption) = nil error, want error")
	}
	if srvErr.Code() != server.ErrorServerError {
		t.Fatalf("error code = %q, want %q", srvErr.Code(), server.ErrorServerError)
	}
}
