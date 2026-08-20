package server_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/extension"
	"github.com/idfoundry/fapigo/internal/clientassertion"
	"github.com/idfoundry/fapigo/internal/dpop"
	"github.com/idfoundry/fapigo/internal/requestobject"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
)

// --- fakes -----------------------------------------------------------

type fakeClientRepository struct {
	clients map[fapi.ClientID]storage.RegisteredClient
}

func (f *fakeClientRepository) ResolveClient(_ context.Context, id fapi.ClientID) (storage.RegisteredClient, error) {
	c, ok := f.clients[id]
	if !ok {
		return storage.RegisteredClient{}, fmt.Errorf("no such client %q", id)
	}
	return c, nil
}

// Capabilities is a test-only assertion so tests can exercise
// AssuranceProduction's storage.StoreAssurance check — it is not a real
// durability claim about this in-memory fake.
func (f *fakeClientRepository) Capabilities() storage.Capabilities {
	return storage.Capabilities{Durable: true, AtomicConsume: true, SerializableRedemption: true, CrossInstanceConsistent: true, EncryptedAtRest: true}
}

type fakeTransactionStore struct {
	mu                 sync.Mutex
	records            []storage.NewPARRecord
	byReference        map[string]storage.NewPARRecord
	referenceCompleted map[string]bool
	byHandle           map[string]fakePendingInteraction
	handleConsumed     map[string]bool
}

// fakePendingInteraction is what BeginAuthorization stashes per Handle:
// the reference it was minted from (needed at completion time to
// enforce single-use per Reference rather than per Handle — see
// storage.TransactionStore.BeginAuthorization's doc comment) alongside
// the data CompleteAuthorization ultimately returns.
type fakePendingInteraction struct {
	reference   string
	interaction storage.CompletedInteraction
}

func (f *fakeTransactionStore) CreatePAR(_ context.Context, record storage.NewPARRecord) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.records = append(f.records, record)
	if f.byReference == nil {
		f.byReference = make(map[string]storage.NewPARRecord)
	}
	f.byReference[record.Reference] = record
	return nil
}

func (f *fakeTransactionStore) BeginAuthorization(_ context.Context, txn storage.BeginAuthorizationTransaction) (storage.PushedAuthorizationRequest, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.referenceCompleted == nil {
		f.referenceCompleted = make(map[string]bool)
	}
	if f.referenceCompleted[txn.Reference] {
		return storage.PushedAuthorizationRequest{}, fmt.Errorf("request_uri already consumed")
	}
	record, ok := f.byReference[txn.Reference]
	if !ok {
		return storage.PushedAuthorizationRequest{}, fmt.Errorf("no such request_uri")
	}

	if f.byHandle == nil {
		f.byHandle = make(map[string]fakePendingInteraction)
	}
	f.byHandle[txn.Handle] = fakePendingInteraction{
		reference: txn.Reference,
		interaction: storage.CompletedInteraction{
			ClientID:    record.ClientID,
			Parameters:  record.Parameters,
			TokenClaims: record.TokenClaims,
			ExpiresAt:   txn.HandleExpiresAt,
		},
	}

	return storage.PushedAuthorizationRequest{
		ClientID:    record.ClientID,
		Parameters:  record.Parameters,
		TokenClaims: record.TokenClaims,
		ExpiresAt:   record.ExpiresAt,
	}, nil
}

func (f *fakeTransactionStore) CompleteAuthorization(_ context.Context, txn storage.CompleteAuthorizationTransaction) (storage.CompletedInteraction, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.handleConsumed == nil {
		f.handleConsumed = make(map[string]bool)
	}
	if f.handleConsumed[txn.Handle] {
		return storage.CompletedInteraction{}, fmt.Errorf("interaction handle already consumed")
	}
	pending, ok := f.byHandle[txn.Handle]
	if !ok {
		return storage.CompletedInteraction{}, fmt.Errorf("no such interaction handle")
	}
	if f.referenceCompleted[pending.reference] {
		return storage.CompletedInteraction{}, fmt.Errorf("request_uri already consumed")
	}
	f.handleConsumed[txn.Handle] = true
	f.referenceCompleted[pending.reference] = true
	return pending.interaction, nil
}

// Capabilities is a test-only assertion — see fakeClientRepository.Capabilities.
func (f *fakeTransactionStore) Capabilities() storage.Capabilities {
	return storage.Capabilities{Durable: true, AtomicConsume: true, SerializableRedemption: true, CrossInstanceConsistent: true, EncryptedAtRest: true}
}

type fakeReplayStore struct {
	mu   sync.Mutex
	seen map[[32]byte]bool
}

func (f *fakeReplayStore) UseOnce(_ context.Context, use storage.ReplayUse) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.seen == nil {
		f.seen = make(map[[32]byte]bool)
	}
	key := [32]byte{}
	copy(key[:], use.Digest[:])
	if f.seen[key] {
		return fmt.Errorf("replay detected")
	}
	f.seen[key] = true
	return nil
}

// Capabilities is a test-only assertion — see fakeClientRepository.Capabilities.
func (f *fakeReplayStore) Capabilities() storage.Capabilities {
	return storage.Capabilities{Durable: true, AtomicConsume: true, SerializableRedemption: true, CrossInstanceConsistent: true, EncryptedAtRest: true}
}

type fakeClientKeySource struct {
	keysByClient map[fapi.ClientID][]keys.VerificationKey
	err          error
}

func (f *fakeClientKeySource) ResolveVerificationKeys(_ context.Context, req keys.ClientKeyRequest) (keys.VerificationKeySet, error) {
	if f.err != nil {
		return keys.VerificationKeySet{}, f.err
	}
	return keys.VerificationKeySet{Keys: f.keysByClient[req.ClientID]}, nil
}

type fakeGrantStore struct {
	mu              sync.Mutex
	codes           []storage.NewAuthorizationCode
	byHash          map[[32]byte]storage.NewAuthorizationCode
	redeemed        map[[32]byte]bool
	codeAccessKey   map[[32]byte]string
	codeRefreshHash map[[32]byte][32]byte
	refreshTokens   []storage.NewRefreshToken
	refreshByHash   map[[32]byte]storage.NewRefreshToken
	refreshRevoked  map[[32]byte]bool
}

func (f *fakeGrantStore) CreateAuthorizationCode(_ context.Context, code storage.NewAuthorizationCode) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.codes = append(f.codes, code)
	if f.byHash == nil {
		f.byHash = make(map[[32]byte]storage.NewAuthorizationCode)
	}
	f.byHash[code.CodeHash] = code
	return nil
}

func (f *fakeGrantStore) RedeemAuthorizationCode(_ context.Context, redemption storage.AuthorizationCodeRedemption) (storage.RedeemedAuthorizationCode, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.redeemed == nil {
		f.redeemed = make(map[[32]byte]bool)
	}
	if f.redeemed[redemption.CodeHash] {
		err := &storage.AuthorizationCodeAlreadyRedeemedError{
			IssuedAccessTokenKey: f.codeAccessKey[redemption.CodeHash],
		}
		if hash, ok := f.codeRefreshHash[redemption.CodeHash]; ok {
			h := hash
			err.IssuedRefreshTokenHash = &h
		}
		return storage.RedeemedAuthorizationCode{}, err
	}
	code, ok := f.byHash[redemption.CodeHash]
	if !ok {
		return storage.RedeemedAuthorizationCode{}, fmt.Errorf("no such code")
	}
	f.redeemed[redemption.CodeHash] = true
	return storage.RedeemedAuthorizationCode{
		ClientID:                code.ClientID,
		RedirectURI:             code.RedirectURI,
		CodeChallenge:           code.CodeChallenge,
		CodeChallengeMethod:     code.CodeChallengeMethod,
		DPoPJKT:                 code.DPoPJKT,
		Subject:                 code.Subject,
		Scope:                   code.Scope,
		Nonce:                   code.Nonce,
		AuthTime:                code.AuthTime,
		ACR:                     code.ACR,
		AMR:                     code.AMR,
		TokenClaims:             code.TokenClaims,
		RequestedIDTokenClaims:  code.RequestedIDTokenClaims,
		RequestedUserinfoClaims: code.RequestedUserinfoClaims,
		ExpiresAt:               code.ExpiresAt,
	}, nil
}

func (f *fakeGrantStore) all() []storage.NewAuthorizationCode {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]storage.NewAuthorizationCode, len(f.codes))
	copy(out, f.codes)
	return out
}

func (f *fakeGrantStore) RecordIssuedAccessToken(_ context.Context, codeHash [32]byte, key string, _ time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.codeAccessKey == nil {
		f.codeAccessKey = make(map[[32]byte]string)
	}
	f.codeAccessKey[codeHash] = key
	return nil
}

func (f *fakeGrantStore) RecordIssuedRefreshToken(_ context.Context, codeHash [32]byte, refreshTokenHash [32]byte, _ time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.codeRefreshHash == nil {
		f.codeRefreshHash = make(map[[32]byte][32]byte)
	}
	f.codeRefreshHash[codeHash] = refreshTokenHash
	return nil
}

func (f *fakeGrantStore) RevokeRefreshToken(_ context.Context, tokenHash [32]byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.refreshRevoked == nil {
		f.refreshRevoked = make(map[[32]byte]bool)
	}
	f.refreshRevoked[tokenHash] = true
	return nil
}

func (f *fakeGrantStore) CreateRefreshToken(_ context.Context, tok storage.NewRefreshToken) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.refreshTokens = append(f.refreshTokens, tok)
	if f.refreshByHash == nil {
		f.refreshByHash = make(map[[32]byte]storage.NewRefreshToken)
	}
	f.refreshByHash[tok.TokenHash] = tok
	return nil
}

// RedeemRefreshToken is not single-use — see storage.GrantStore's doc
// comment (FAPI2-SP-FINAL 5.3.2.1-9): a refresh token stays valid for
// repeated use until it expires.
func (f *fakeGrantStore) RedeemRefreshToken(_ context.Context, redemption storage.RefreshTokenRedemption) (storage.RedeemedRefreshToken, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.refreshRevoked[redemption.TokenHash] {
		return storage.RedeemedRefreshToken{}, fmt.Errorf("refresh token has been revoked")
	}
	tok, ok := f.refreshByHash[redemption.TokenHash]
	if !ok {
		return storage.RedeemedRefreshToken{}, fmt.Errorf("no such refresh token")
	}
	return storage.RedeemedRefreshToken{
		ClientID:                tok.ClientID,
		Subject:                 tok.Subject,
		Scope:                   tok.Scope,
		Thumbprint:              tok.Thumbprint,
		AuthTime:                tok.AuthTime,
		ACR:                     tok.ACR,
		AMR:                     tok.AMR,
		TokenClaims:             tok.TokenClaims,
		RequestedIDTokenClaims:  tok.RequestedIDTokenClaims,
		RequestedUserinfoClaims: tok.RequestedUserinfoClaims,
		ExpiresAt:               tok.ExpiresAt,
	}, nil
}

// Capabilities is a test-only assertion — see fakeClientRepository.Capabilities.
func (f *fakeGrantStore) Capabilities() storage.Capabilities {
	return storage.Capabilities{Durable: true, AtomicConsume: true, SerializableRedemption: true, CrossInstanceConsistent: true, EncryptedAtRest: true}
}

// fakeKeyManager signs with a fixed ECDSA P-256 key using the same
// fixed-width R||S encoding internal/jose produces, so a signature it
// returns verifies correctly against internal/jarm.Verify in tests.
type fakeKeyManager struct {
	key   *ecdsa.PrivateKey
	keyID string
}

func (f *fakeKeyManager) Sign(_ context.Context, req keys.SigningRequest) (keys.Signature, error) {
	// keys.Signature.Value must match crypto.Signer's contract for the
	// key type — ASN.1 DER for ECDSA, exactly what *ecdsa.PrivateKey.Sign
	// would produce — not the fixed-width R||S JWS uses on the wire.
	der, err := ecdsa.SignASN1(rand.Reader, f.key, req.Digest)
	if err != nil {
		return keys.Signature{}, err
	}
	return keys.Signature{KeyID: f.keyID, Value: der}, nil
}

func (f *fakeKeyManager) PublicKey(_ context.Context, _ keys.SigningPurpose, _ fapi.SignatureAlgorithm) (keys.PublicKeyInfo, error) {
	return keys.PublicKeyInfo{KeyID: f.keyID, PublicKey: &f.key.PublicKey}, nil
}

type fakeAuditSink struct {
	mu     sync.Mutex
	events []server.AuditEvent
}

func (f *fakeAuditSink) Record(_ context.Context, event server.AuditEvent) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, event)
	return nil
}

func (f *fakeAuditSink) all() []server.AuditEvent {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]server.AuditEvent, len(f.events))
	copy(out, f.events)
	return out
}

// fakeRevocationSink is a server.RevocationSink test double that
// records every jti it's asked to revoke, so a test can assert
// ExchangeAuthorizationCode's reuse-detection path called it with the
// right value.
type fakeRevocationSink struct {
	mu      sync.Mutex
	revoked []string
}

func (f *fakeRevocationSink) Revoke(_ context.Context, jti string, _ time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.revoked = append(f.revoked, jti)
	return nil
}

func (f *fakeRevocationSink) all() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, len(f.revoked))
	copy(out, f.revoked)
	return out
}

type fixedClock struct{ now time.Time }

func (c fixedClock) Now() time.Time { return c.now }

// --- test harness ------------------------------------------------------

const testClientID = fapi.ClientID("client-123")
const testIssuer = "https://as.example"
const testRedirectURI = "https://rp.example/callback"
const testTokenEndpoint = "https://as.example/token"
const testAuthorizationEndpoint = "https://as.example/authorize"
const testPAREndpoint = "https://as.example/par"
const testJWKSEndpoint = "https://as.example/jwks"

func testEndpoints(t *testing.T) server.Endpoints {
	t.Helper()
	authorization, err := fapi.ParseEndpointURL(testAuthorizationEndpoint)
	if err != nil {
		t.Fatalf("ParseEndpointURL: %v", err)
	}
	token, err := fapi.ParseEndpointURL(testTokenEndpoint)
	if err != nil {
		t.Fatalf("ParseEndpointURL: %v", err)
	}
	par, err := fapi.ParseEndpointURL(testPAREndpoint)
	if err != nil {
		t.Fatalf("ParseEndpointURL: %v", err)
	}
	jwks, err := fapi.ParseEndpointURL(testJWKSEndpoint)
	if err != nil {
		t.Fatalf("ParseEndpointURL: %v", err)
	}
	return server.Endpoints{
		Authorization:              authorization,
		Token:                      token,
		PushedAuthorizationRequest: par,
		JWKS:                       jwks,
	}
}

func generateKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return key
}

type harness struct {
	server       *server.Server
	key          *ecdsa.PrivateKey
	serverKey    *ecdsa.PrivateKey
	transactions *fakeTransactionStore
	grants       *fakeGrantStore
	audit        *fakeAuditSink
	revocation   *fakeRevocationSink
	now          time.Time
}

func newHarness(t *testing.T, profile server.Profile, allowRequestObjects bool) harness {
	t.Helper()
	now := time.Now()
	key := generateKey(t)
	serverKey := generateKey(t)

	reqObjAlg := fapi.ES256
	if !allowRequestObjects {
		reqObjAlg = 0
	}
	client, err := storage.NewRegisteredClient(storage.RegisteredClientConfig{
		ID:                       testClientID,
		RedirectURIs:             []fapi.RegisteredRedirectURI{testRedirectURI},
		ClientAssertionAlgorithm: fapi.ES256,
		RequestObjectAlgorithm:   reqObjAlg,
		AllowedScopes:            []string{"openid", "accounts", "offline_access"},
	})
	if err != nil {
		t.Fatalf("NewRegisteredClient: %v", err)
	}

	issuer, err := fapi.ParseIssuerURL(testIssuer)
	if err != nil {
		t.Fatalf("ParseIssuerURL: %v", err)
	}

	transactions := &fakeTransactionStore{}
	grants := &fakeGrantStore{}
	audit := &fakeAuditSink{}
	revocation := &fakeRevocationSink{}

	cfg := server.Config{
		Issuer:    issuer,
		Endpoints: testEndpoints(t),
		Profile:   profile,
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
		},
		Assurance: server.AssuranceDevelopment,
	}
	serverKeyManager := &fakeKeyManager{key: serverKey, keyID: "as-key-1"}
	deps := server.Dependencies{
		Clients:      &fakeClientRepository{clients: map[fapi.ClientID]storage.RegisteredClient{testClientID: client}},
		Transactions: transactions,
		Grants:       grants,
		Replay:       &fakeReplayStore{},
		ClientKeys: &fakeClientKeySource{keysByClient: map[fapi.ClientID][]keys.VerificationKey{
			testClientID: {{Algorithm: fapi.ES256, PublicKey: &key.PublicKey}},
		}},
		Keys:         serverKeyManager,
		AccessTokens: server.JWTAccessTokens{Keys: serverKeyManager, Algorithm: fapi.ES256},
		Revocation:   revocation,
		Audit:        audit,
		Clock:        fixedClock{now: now},
		Random:       rand.Reader,
	}

	srv, err := server.New(cfg, deps)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	return harness{server: srv, key: key, serverKey: serverKey, transactions: transactions, grants: grants, audit: audit, revocation: revocation, now: now}
}

// newHarnessWithClientKeys mirrors newHarness but lets a test supply
// its own ClientKeySource — for exercising resolveClientKey's own
// candidate-matching logic (kid/algorithm skip-and-continue, upstream
// resolve failure) directly, none of which the default single-
// candidate-key harness ever needs to exercise.
func newHarnessWithClientKeys(t *testing.T, clientKeys keys.ClientKeySource) harness {
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
		},
		Assurance: server.AssuranceDevelopment,
	}
	serverKeyManager := &fakeKeyManager{key: serverKey, keyID: "as-key-1"}
	deps := server.Dependencies{
		Clients:      &fakeClientRepository{clients: map[fapi.ClientID]storage.RegisteredClient{testClientID: client}},
		Transactions: &fakeTransactionStore{},
		Grants:       &fakeGrantStore{},
		Replay:       &fakeReplayStore{},
		ClientKeys:   clientKeys,
		Keys:         serverKeyManager,
		AccessTokens: server.JWTAccessTokens{Keys: serverKeyManager, Algorithm: fapi.ES256},
		Revocation:   &fakeRevocationSink{},
		Audit:        &fakeAuditSink{},
		Clock:        fixedClock{now: now},
		Random:       rand.Reader,
	}

	srv, err := server.New(cfg, deps)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	return harness{server: srv, key: key, serverKey: serverKey, now: now}
}

// TestPushAuthorizationRequestClientAssertionSelectsMatchingKeyAmongCandidates
// proves resolveClientKey's candidate loop actually picks the right
// key by kid — not just that a lone key gets used, which is all
// newHarness's single-candidate setup can ever exercise. A decoy
// candidate (right algorithm, wrong kid) must be skipped in favor of
// the real one; if the loop instead picked the decoy, verifying a
// signature made by the real key against the decoy's public key would
// fail and this request would be rejected.
func TestPushAuthorizationRequestClientAssertionSelectsMatchingKeyAmongCandidates(t *testing.T) {
	decoyKey := generateKey(t)
	realKey := generateKey(t)
	h := newHarnessWithClientKeys(t, &fakeClientKeySource{keysByClient: map[fapi.ClientID][]keys.VerificationKey{
		testClientID: {
			{KeyID: "decoy-kid", Algorithm: fapi.ES256, PublicKey: &decoyKey.PublicKey},
			{KeyID: "real-kid", Algorithm: fapi.ES256, PublicKey: &realKey.PublicKey},
		},
	}})

	assertion, err := clientassertion.CreateAssertion(clientassertion.AssertionRequest{
		Signer: realKey, Algorithm: fapi.ES256, KeyID: "real-kid",
		ClientID: testClientID.String(), Audience: testIssuer,
		Now: h.now, Lifetime: 30 * time.Second,
	})
	if err != nil {
		t.Fatalf("CreateAssertion: %v", err)
	}

	if _, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
		HTTP: server.FormRequest{Parameters: plainFormParameters(t, assertion, nil)},
	}); err != nil {
		t.Fatalf("PushAuthorizationRequest: %v", err)
	}
}

// TestPushAuthorizationRequestRejectsClientKeyResolutionFailures covers
// resolveClientKey's remaining paths — every one of them collapses to
// the same ErrorInvalidClient/401 "no matching client key" from
// PushAuthorizationRequest's own perspective (see par.go), so this
// only proves each scenario is correctly rejected, not which internal
// branch fired.
func TestPushAuthorizationRequestRejectsClientKeyResolutionFailures(t *testing.T) {
	registeredKey := generateKey(t)
	cases := map[string]*fakeClientKeySource{
		"no candidate keys at all": {},
		"candidate kid does not match the assertion's kid": {
			keysByClient: map[fapi.ClientID][]keys.VerificationKey{
				testClientID: {{KeyID: "other-kid", Algorithm: fapi.ES256, PublicKey: &registeredKey.PublicKey}},
			},
		},
		"candidate algorithm does not match the client's registered algorithm": {
			keysByClient: map[fapi.ClientID][]keys.VerificationKey{
				testClientID: {{KeyID: "assertion-kid", Algorithm: fapi.PS256, PublicKey: &registeredKey.PublicKey}},
			},
		},
		"ClientKeySource itself errors": {err: fmt.Errorf("boom")},
	}
	for name, clientKeys := range cases {
		t.Run(name, func(t *testing.T) {
			h := newHarnessWithClientKeys(t, clientKeys)
			assertion, err := clientassertion.CreateAssertion(clientassertion.AssertionRequest{
				Signer: registeredKey, Algorithm: fapi.ES256, KeyID: "assertion-kid",
				ClientID: testClientID.String(), Audience: testIssuer,
				Now: h.now, Lifetime: 30 * time.Second,
			})
			if err != nil {
				t.Fatalf("CreateAssertion: %v", err)
			}
			_, err = h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
				HTTP: server.FormRequest{Parameters: plainFormParameters(t, assertion, nil)},
			})
			if err == nil {
				t.Fatalf("PushAuthorizationRequest = nil error, want error")
			}
			if code := serverErrorCode(t, err); code != server.ErrorInvalidClient {
				t.Fatalf("error code = %q, want %q", code, server.ErrorInvalidClient)
			}
		})
	}
}

func (h harness) clientAssertion(t *testing.T) string {
	t.Helper()
	assertion, err := clientassertion.CreateAssertion(clientassertion.AssertionRequest{
		Signer: h.key, Algorithm: fapi.ES256,
		ClientID: testClientID.String(), Audience: testIssuer,
		Now: h.now, Lifetime: 30 * time.Second,
	})
	if err != nil {
		t.Fatalf("CreateAssertion: %v", err)
	}
	return assertion
}

func jsonRaw(t *testing.T, v any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

func standardAuthParams(t *testing.T) map[string]json.RawMessage {
	t.Helper()
	return map[string]json.RawMessage{
		"response_type":         jsonRaw(t, "code"),
		"redirect_uri":          jsonRaw(t, testRedirectURI),
		"scope":                 jsonRaw(t, "openid accounts"),
		"code_challenge":        jsonRaw(t, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"),
		"code_challenge_method": jsonRaw(t, "S256"),
		"state":                 jsonRaw(t, "opaque-state"),
	}
}

func (h harness) requestObject(t *testing.T, params map[string]json.RawMessage) string {
	t.Helper()
	obj, err := requestobject.Create(requestobject.CreateParams{
		Signer: h.key, Algorithm: fapi.ES256,
		ClientID: testClientID.String(), Audience: testIssuer,
		Now: h.now, Lifetime: 30 * time.Second, Parameters: params,
	})
	if err != nil {
		t.Fatalf("requestobject.Create: %v", err)
	}
	return obj
}

func formParam(name, value string) server.FormParameter {
	return server.FormParameter{Name: name, Value: value}
}

func plainFormParameters(t *testing.T, assertion string, extra map[string]string) []server.FormParameter {
	t.Helper()
	params := []server.FormParameter{
		formParam("client_assertion", assertion),
		formParam("client_assertion_type", clientassertion.AssertionType),
		formParam("response_type", "code"),
		formParam("redirect_uri", testRedirectURI),
		formParam("scope", "openid accounts"),
		formParam("code_challenge", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"),
		formParam("code_challenge_method", "S256"),
		formParam("state", "opaque-state"),
	}
	for k, v := range extra {
		params = append(params, formParam(k, v))
	}
	return params
}

func serverErrorCode(t *testing.T, err error) server.ErrorCode {
	t.Helper()
	var srvErr *server.Error
	if !errors.As(err, &srvErr) {
		t.Fatalf("error %v is not a *server.Error", err)
	}
	return srvErr.Code()
}

// --- tests -------------------------------------------------------------

func TestPushAuthorizationRequestJARSuccess(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurityWithMessageSigning, true)
	requestObj := h.requestObject(t, standardAuthParams(t))

	result, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
		HTTP: server.FormRequest{Parameters: []server.FormParameter{
			formParam("client_assertion", h.clientAssertion(t)),
			formParam("client_assertion_type", clientassertion.AssertionType),
			formParam("request", requestObj),
		}},
	})
	if err != nil {
		t.Fatalf("PushAuthorizationRequest: %v", err)
	}
	if !strings.HasPrefix(result.RequestURI.String(), "urn:ietf:params:oauth:request_uri:") {
		t.Fatalf("RequestURI = %q, want urn:ietf:params:oauth:request_uri: prefix", result.RequestURI.String())
	}
	if result.ExpiresIn != 90*time.Second {
		t.Fatalf("ExpiresIn = %v, want 90s", result.ExpiresIn)
	}

	records := h.transactions.records
	if len(records) != 1 {
		t.Fatalf("len(records) = %d, want 1", len(records))
	}
	if records[0].ClientID != testClientID {
		t.Fatalf("records[0].ClientID = %q, want %q", records[0].ClientID, testClientID)
	}
	var scope string
	if err := json.Unmarshal(records[0].Parameters["scope"], &scope); err != nil || scope != "openid accounts" {
		t.Fatalf("records[0].Parameters[scope] = %q, want %q", scope, "openid accounts")
	}

	events := h.audit.all()
	if len(events) != 1 || events[0].Outcome != server.AuditOutcomeSuccess {
		t.Fatalf("audit events = %+v, want one success event", events)
	}
}

// RFC 9101 §5 (PAR-2.1): "request" and "request_uri" are mutually
// exclusive ways of conveying the same authorization request. PAR
// generates its own request_uri as this call's *result* — a client
// sending one as an *input* parameter here, alongside a valid signed
// "request", is never meaningful and must be rejected.
func TestPushAuthorizationRequestRejectsRequestUriAlongsideRequest(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurityWithMessageSigning, true)
	requestObj := h.requestObject(t, standardAuthParams(t))

	_, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
		HTTP: server.FormRequest{Parameters: []server.FormParameter{
			formParam("client_assertion", h.clientAssertion(t)),
			formParam("client_assertion_type", clientassertion.AssertionType),
			formParam("request", requestObj),
			formParam("request_uri", "urn:ietf:params:oauth:request_uri:bogus"),
		}},
	})
	if err == nil {
		t.Fatalf("PushAuthorizationRequest(request + request_uri) = nil error, want error")
	}
	if code := serverErrorCode(t, err); code != server.ErrorInvalidRequest {
		t.Fatalf("error code = %q, want %q", code, server.ErrorInvalidRequest)
	}
}

// A stray "request_uri" claim embedded inside the signed request object
// itself (as opposed to a sibling form parameter — see
// TestPushAuthorizationRequestRejectsRequestUriAlongsideRequest) is an
// unregistered parameter from inside the request object, so it must be
// reported as ErrorInvalidRequestObject (JAR-6.2), not the generic
// ErrorInvalidRequest a plain-form violation gets.
func TestPushAuthorizationRequestRejectsRequestUriInsideRequestObject(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurityWithMessageSigning, true)
	params := standardAuthParams(t)
	params["request_uri"] = jsonRaw(t, "urn:ietf:params:oauth:request_uri:bogus")
	requestObj := h.requestObject(t, params)

	_, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
		HTTP: server.FormRequest{Parameters: []server.FormParameter{
			formParam("client_assertion", h.clientAssertion(t)),
			formParam("client_assertion_type", clientassertion.AssertionType),
			formParam("request", requestObj),
		}},
	})
	if err == nil {
		t.Fatalf("PushAuthorizationRequest(request_uri inside request object) = nil error, want error")
	}
	if code := serverErrorCode(t, err); code != server.ErrorInvalidRequestObject {
		t.Fatalf("error code = %q, want %q", code, server.ErrorInvalidRequestObject)
	}
}

func TestPushAuthorizationRequestPlainSuccessUnderSecurityProfile(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)

	result, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
		HTTP: server.FormRequest{Parameters: plainFormParameters(t, h.clientAssertion(t), nil)},
	})
	if err != nil {
		t.Fatalf("PushAuthorizationRequest: %v", err)
	}
	if result.RequestURI.String() == "" {
		t.Fatalf("RequestURI is empty")
	}
	if len(h.transactions.records) != 1 {
		t.Fatalf("len(records) = %d, want 1", len(h.transactions.records))
	}
}

func TestPushAuthorizationRequestPlainRejectedUnderMessageSigningProfile(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurityWithMessageSigning, true)

	_, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
		HTTP: server.FormRequest{Parameters: plainFormParameters(t, h.clientAssertion(t), nil)},
	})
	if err == nil {
		t.Fatalf("PushAuthorizationRequest(plain, message-signing profile) = nil error, want error")
	}
	if code := serverErrorCode(t, err); code != server.ErrorInvalidRequest {
		t.Fatalf("error code = %q, want %q", code, server.ErrorInvalidRequest)
	}
}

func TestPushAuthorizationRequestMissingClientAssertion(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	params := plainFormParameters(t, "unused", nil)
	// Remove client_assertion.
	filtered := params[:0]
	for _, p := range params {
		if p.Name != "client_assertion" {
			filtered = append(filtered, p)
		}
	}

	_, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
		HTTP: server.FormRequest{Parameters: filtered},
	})
	if err == nil {
		t.Fatalf("PushAuthorizationRequest(no client_assertion) = nil error, want error")
	}
	if code := serverErrorCode(t, err); code != server.ErrorInvalidClient {
		t.Fatalf("error code = %q, want %q", code, server.ErrorInvalidClient)
	}
}

func TestPushAuthorizationRequestWrongAssertionType(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	params := plainFormParameters(t, h.clientAssertion(t), nil)
	for i := range params {
		if params[i].Name == "client_assertion_type" {
			params[i].Value = "urn:ietf:params:oauth:client-assertion-type:saml2-bearer"
		}
	}

	_, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
		HTTP: server.FormRequest{Parameters: params},
	})
	if code := serverErrorCode(t, err); code != server.ErrorInvalidClient {
		t.Fatalf("error code = %q, want %q", code, server.ErrorInvalidClient)
	}
}

func TestPushAuthorizationRequestUnknownClient(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	otherKey := generateKey(t)
	assertion, err := clientassertion.CreateAssertion(clientassertion.AssertionRequest{
		Signer: otherKey, Algorithm: fapi.ES256,
		ClientID: "unknown-client", Audience: testIssuer, Now: h.now, Lifetime: 30 * time.Second,
	})
	if err != nil {
		t.Fatalf("CreateAssertion: %v", err)
	}

	_, err = h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
		HTTP: server.FormRequest{Parameters: plainFormParameters(t, assertion, nil)},
	})
	if code := serverErrorCode(t, err); code != server.ErrorInvalidClient {
		t.Fatalf("error code = %q, want %q", code, server.ErrorInvalidClient)
	}
}

func TestPushAuthorizationRequestInvalidRedirectURI(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	params := plainFormParameters(t, h.clientAssertion(t), nil)
	for i := range params {
		if params[i].Name == "redirect_uri" {
			params[i].Value = "https://attacker.example/callback"
		}
	}

	_, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
		HTTP: server.FormRequest{Parameters: params},
	})
	if code := serverErrorCode(t, err); code != server.ErrorInvalidRequest {
		t.Fatalf("error code = %q, want %q", code, server.ErrorInvalidRequest)
	}
}

func TestPushAuthorizationRequestResponseTypeMustBeCode(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	params := plainFormParameters(t, h.clientAssertion(t), nil)
	for i := range params {
		if params[i].Name == "response_type" {
			params[i].Value = "code id_token"
		}
	}

	_, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
		HTTP: server.FormRequest{Parameters: params},
	})
	if code := serverErrorCode(t, err); code != server.ErrorInvalidRequest {
		t.Fatalf("error code = %q, want %q", code, server.ErrorInvalidRequest)
	}
}

func TestPushAuthorizationRequestMissingPKCE(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	params := plainFormParameters(t, h.clientAssertion(t), nil)
	filtered := params[:0]
	for _, p := range params {
		if p.Name != "code_challenge" {
			filtered = append(filtered, p)
		}
	}

	_, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
		HTTP: server.FormRequest{Parameters: filtered},
	})
	if code := serverErrorCode(t, err); code != server.ErrorInvalidRequest {
		t.Fatalf("error code = %q, want %q", code, server.ErrorInvalidRequest)
	}
}

func TestPushAuthorizationRequestRejectsPlainCodeChallengeMethod(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	params := plainFormParameters(t, h.clientAssertion(t), nil)
	for i := range params {
		if params[i].Name == "code_challenge_method" {
			params[i].Value = "plain"
		}
	}

	_, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
		HTTP: server.FormRequest{Parameters: params},
	})
	if code := serverErrorCode(t, err); code != server.ErrorInvalidRequest {
		t.Fatalf("error code = %q, want %q", code, server.ErrorInvalidRequest)
	}
}

func TestPushAuthorizationRequestScopeNotAllowed(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	params := plainFormParameters(t, h.clientAssertion(t), nil)
	for i := range params {
		if params[i].Name == "scope" {
			params[i].Value = "openid payments"
		}
	}

	_, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
		HTTP: server.FormRequest{Parameters: params},
	})
	if code := serverErrorCode(t, err); code != server.ErrorInvalidRequest {
		t.Fatalf("error code = %q, want %q", code, server.ErrorInvalidRequest)
	}
}

func TestPushAuthorizationRequestRejectsDuplicateParameter(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	params := plainFormParameters(t, h.clientAssertion(t), nil)
	params = append(params, formParam("state", "second-value"))

	_, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
		HTTP: server.FormRequest{Parameters: params},
	})
	if code := serverErrorCode(t, err); code != server.ErrorInvalidRequest {
		t.Fatalf("error code = %q, want %q", code, server.ErrorInvalidRequest)
	}
}

func TestPushAuthorizationRequestDetectsClientAssertionReplay(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	assertion := h.clientAssertion(t)

	if _, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
		HTTP: server.FormRequest{Parameters: plainFormParameters(t, assertion, nil)},
	}); err != nil {
		t.Fatalf("first PushAuthorizationRequest: %v", err)
	}

	_, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
		HTTP: server.FormRequest{Parameters: plainFormParameters(t, assertion, nil)},
	})
	if err == nil {
		t.Fatalf("second PushAuthorizationRequest (replayed assertion) = nil error, want error")
	}
	if code := serverErrorCode(t, err); code != server.ErrorInvalidClient {
		t.Fatalf("error code = %q, want %q", code, server.ErrorInvalidClient)
	}
}

func TestPushAuthorizationRequestDetectsRequestObjectReplay(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurityWithMessageSigning, true)
	requestObj := h.requestObject(t, standardAuthParams(t))

	buildParams := func() []server.FormParameter {
		return []server.FormParameter{
			formParam("client_assertion", h.clientAssertion(t)),
			formParam("client_assertion_type", clientassertion.AssertionType),
			formParam("request", requestObj),
		}
	}

	if _, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
		HTTP: server.FormRequest{Parameters: buildParams()},
	}); err != nil {
		t.Fatalf("first PushAuthorizationRequest: %v", err)
	}

	_, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
		HTTP: server.FormRequest{Parameters: buildParams()},
	})
	if err == nil {
		t.Fatalf("second PushAuthorizationRequest (replayed request object) = nil error, want error")
	}
	if code := serverErrorCode(t, err); code != server.ErrorInvalidRequestObject {
		t.Fatalf("error code = %q, want %q", code, server.ErrorInvalidRequestObject)
	}
}

func TestPushAuthorizationRequestClientNotPermittedRequestObject(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, false) // request objects not permitted for this client
	requestObj := h.requestObject(t, standardAuthParams(t))

	_, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
		HTTP: server.FormRequest{Parameters: []server.FormParameter{
			formParam("client_assertion", h.clientAssertion(t)),
			formParam("client_assertion_type", clientassertion.AssertionType),
			formParam("request", requestObj),
		}},
	})
	if code := serverErrorCode(t, err); code != server.ErrorInvalidRequestObject {
		t.Fatalf("error code = %q, want %q", code, server.ErrorInvalidRequestObject)
	}
}

func TestPushAuthorizationRequestAuditsFailure(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	filtered := []server.FormParameter{formParam("response_type", "code")} // no client_assertion at all

	_, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
		HTTP: server.FormRequest{Parameters: filtered},
	})
	if err == nil {
		t.Fatalf("PushAuthorizationRequest = nil error, want error")
	}
	events := h.audit.all()
	if len(events) != 1 || events[0].Outcome != server.AuditOutcomeFailure {
		t.Fatalf("audit events = %+v, want one failure event", events)
	}
}

// --- extension wiring --------------------------------------------------

func newHarnessWithExtensions(t *testing.T, profile server.Profile, registry *extension.Registry) harness {
	t.Helper()
	now := time.Now()
	key := generateKey(t)
	serverKey := generateKey(t)

	client, err := storage.NewRegisteredClient(storage.RegisteredClientConfig{
		ID:                       testClientID,
		RedirectURIs:             []fapi.RegisteredRedirectURI{testRedirectURI},
		ClientAssertionAlgorithm: fapi.ES256,
		RequestObjectAlgorithm:   fapi.ES256,
		AllowedScopes:            []string{"openid", "accounts"},
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
		Profile:   profile,
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
		},
		Assurance:  server.AssuranceDevelopment,
		Extensions: registry,
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
		Keys:         serverKeyManager,
		AccessTokens: server.JWTAccessTokens{Keys: serverKeyManager, Algorithm: fapi.ES256},
		Revocation:   server.NoRevocation{},
		Clock:        fixedClock{now: now},
		Random:       rand.Reader,
	}
	srv, err := server.New(cfg, deps)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	return harness{server: srv, key: key, serverKey: serverKey, now: now}
}

func TestPushAuthorizationRequestRejectsUnregisteredExtensionParameter(t *testing.T) {
	h := newHarnessWithExtensions(t, server.ProfileFAPISecurity, nil)
	params := plainFormParameters(t, h.clientAssertion(t), map[string]string{"x_custom": "hello"})

	_, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
		HTTP: server.FormRequest{Parameters: params},
	})
	if code := serverErrorCode(t, err); code != server.ErrorInvalidRequest {
		t.Fatalf("error code = %q, want %q", code, server.ErrorInvalidRequest)
	}
}

// OIDC Core §3.1.2.1's "prompt" parameter must not be rejected as an
// unregistered extension parameter — it's core, not a
// deployment-specific extension (see coreAuthorizationParameters). A
// client requesting offline_access commonly sends prompt=consent to
// guarantee a fresh consent screen (and hence a refresh token); a
// conformance-suite regression once had this parameter rejected
// outright, failing the refresh-token test.
func TestPushAuthorizationRequestAcceptsPromptParameter(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, false)
	params := plainFormParameters(t, h.clientAssertion(t), map[string]string{"prompt": "consent"})

	_, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
		HTTP: server.FormRequest{Parameters: params},
	})
	if err != nil {
		t.Fatalf("PushAuthorizationRequest: %v", err)
	}
}

// response_mode=jwt is mandatory for a JARM/message-signing client
// (OAuth Multiple Response Type Encoding Practices) but this package
// never reads it — JARM-or-not is entirely Config.Profile-driven. A
// conformance-suite regression once had it rejected outright as an
// unregistered parameter, failing PAR before the authorization flow
// could even begin under ProfileFAPISecurityWithMessageSigning.
func TestPushAuthorizationRequestAcceptsResponseModeParameter(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, false)
	params := plainFormParameters(t, h.clientAssertion(t), map[string]string{"response_mode": "jwt"})

	_, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
		HTTP: server.FormRequest{Parameters: params},
	})
	if err != nil {
		t.Fatalf("PushAuthorizationRequest: %v", err)
	}
}

func TestPushAuthorizationRequestAcceptsRegisteredExtensionParameter(t *testing.T) {
	def := extension.Definition[string]{
		Name: "x_custom", Cardinality: extension.Single,
		AllowedSources: extension.SourcePlainParameter, MaxBytes: 64,
	}
	registry, err := extension.NewRegistry(def)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	h := newHarnessWithExtensions(t, server.ProfileFAPISecurity, registry)
	params := plainFormParameters(t, h.clientAssertion(t), map[string]string{"x_custom": "hello"})

	if _, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
		HTTP: server.FormRequest{Parameters: params},
	}); err != nil {
		t.Fatalf("PushAuthorizationRequest: %v", err)
	}
}

// --- DPoP proof at the PAR endpoint (RFC 9449 §10) ----------------------

func createDPoPProofForPAR(t *testing.T, key *ecdsa.PrivateKey, now time.Time) string {
	t.Helper()
	parURL, err := url.Parse(testPAREndpoint)
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}
	proof, err := dpop.CreateProof(dpop.ProofRequest{
		Signer: key, Algorithm: fapi.ES256, Method: "POST", URL: parURL, Now: now,
	})
	if err != nil {
		t.Fatalf("dpop.CreateProof: %v", err)
	}
	return proof
}

// A DPoP proof presented to the PAR endpoint with no explicit dpop_jkt
// parameter implicitly binds the resulting authorization code to that
// proof's own key — not just whichever key later shows up at the token
// endpoint.
func TestPushAuthorizationRequestDerivesImplicitDPoPJKTFromPARProof(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	dpopKey := generateKey(t)
	thumbprint, err := jwkThumbprintFor(dpopKey)
	if err != nil {
		t.Fatalf("thumbprint: %v", err)
	}
	params := plainFormParameters(t, h.clientAssertion(t), nil)

	_, err = h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
		HTTP:      server.FormRequest{Parameters: params},
		DPoPProof: createDPoPProofForPAR(t, dpopKey, h.now),
	})
	if err != nil {
		t.Fatalf("PushAuthorizationRequest: %v", err)
	}
	if len(h.transactions.records) != 1 {
		t.Fatalf("len(records) = %d, want 1", len(h.transactions.records))
	}
	var storedJKT string
	if err := json.Unmarshal(h.transactions.records[0].Parameters["dpop_jkt"], &storedJKT); err != nil {
		t.Fatalf("dpop_jkt not stored as a string: %v", err)
	}
	if storedJKT != thumbprint.String() {
		t.Fatalf("stored dpop_jkt = %q, want %q (the PAR-time DPoP proof's own key)", storedJKT, thumbprint.String())
	}
}

func TestPushAuthorizationRequestAcceptsMatchingDPoPJKTAtPAR(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	dpopKey := generateKey(t)
	thumbprint, err := jwkThumbprintFor(dpopKey)
	if err != nil {
		t.Fatalf("thumbprint: %v", err)
	}
	params := plainFormParameters(t, h.clientAssertion(t), map[string]string{"dpop_jkt": thumbprint.String()})

	_, err = h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
		HTTP:      server.FormRequest{Parameters: params},
		DPoPProof: createDPoPProofForPAR(t, dpopKey, h.now),
	})
	if err != nil {
		t.Fatalf("PushAuthorizationRequest: %v", err)
	}
}

func TestPushAuthorizationRequestRejectsMismatchedDPoPJKTAtPAR(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	declaredKey := generateKey(t)
	declaredThumbprint, err := jwkThumbprintFor(declaredKey)
	if err != nil {
		t.Fatalf("thumbprint: %v", err)
	}
	proofKey := generateKey(t) // a different key than the one declared via dpop_jkt
	params := plainFormParameters(t, h.clientAssertion(t), map[string]string{"dpop_jkt": declaredThumbprint.String()})

	_, err = h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
		HTTP:      server.FormRequest{Parameters: params},
		DPoPProof: createDPoPProofForPAR(t, proofKey, h.now),
	})
	if code := serverErrorCode(t, err); code != server.ErrorInvalidRequest {
		t.Fatalf("error code = %q, want %q", code, server.ErrorInvalidRequest)
	}
}

// TestErrorAccessors verifies server.Error's own public contract —
// Code, PublicDescription, HTTPStatus, Error and Unwrap — which,
// despite being ARCHITECTURE.md design rule 16 ("errors carry their
// own exposure"), had no direct test of its own: existing tests only
// ever check Code(). A malformed client_assertion is the simplest
// trigger that carries a real underlying cause, exercising Unwrap for
// real rather than against a nil cause.
func TestErrorAccessors(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)

	_, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
		HTTP: server.FormRequest{Parameters: plainFormParameters(t, "not-a-jwt", nil)},
	})
	if err == nil {
		t.Fatalf("PushAuthorizationRequest(malformed client_assertion) = nil error, want error")
	}
	serr, ok := err.(*server.Error)
	if !ok {
		t.Fatalf("error type = %T, want *server.Error", err)
	}
	if serr.Code() != server.ErrorInvalidClient {
		t.Fatalf("Code() = %q, want %q", serr.Code(), server.ErrorInvalidClient)
	}
	if serr.PublicDescription() != "malformed client assertion" {
		t.Fatalf("PublicDescription() = %q, want %q", serr.PublicDescription(), "malformed client assertion")
	}
	if serr.HTTPStatus() != 401 {
		t.Fatalf("HTTPStatus() = %d, want 401", serr.HTTPStatus())
	}
	if !strings.Contains(serr.Error(), serr.PublicDescription()) {
		t.Fatalf("Error() = %q, want it to include PublicDescription() %q", serr.Error(), serr.PublicDescription())
	}
	if serr.Unwrap() == nil {
		t.Fatalf("Unwrap() = nil, want the underlying client-assertion parse error")
	}
}

// TestErrorAccessorsWithoutCause covers Error()'s other format branch —
// TestErrorAccessors above only ever exercises the with-cause branch.
// A request with no client_assertion at all is the simplest trigger
// for a server.Error that carries no underlying cause.
func TestErrorAccessorsWithoutCause(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)

	_, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
		HTTP: server.FormRequest{Parameters: []server.FormParameter{formParam("response_type", "code")}},
	})
	if err == nil {
		t.Fatalf("PushAuthorizationRequest(no client_assertion) = nil error, want error")
	}
	serr, ok := err.(*server.Error)
	if !ok {
		t.Fatalf("error type = %T, want *server.Error", err)
	}
	if serr.Unwrap() != nil {
		t.Fatalf("Unwrap() = %v, want nil", serr.Unwrap())
	}
	if serr.Error() != "server: invalid_client: client authentication is required" {
		t.Fatalf("Error() = %q, want %q", serr.Error(), "server: invalid_client: client authentication is required")
	}
}
