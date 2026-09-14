package server_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/clientattestation"
	"github.com/idfoundry/fapigo/internal/jose"
	"github.com/idfoundry/fapigo/internal/token"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
)

const testAttesterIssuer = "https://attester.example.com"

func createAttestationHeader(t *testing.T, attesterKey *ecdsa.PrivateKey, subject string, instancePub *ecdsa.PublicKey, now time.Time, lifetime time.Duration) string {
	t.Helper()
	jwk, err := jose.NewJWK(instancePub, fapi.ES256)
	if err != nil {
		t.Fatalf("NewJWK: %v", err)
	}
	jwkJSON, err := jwk.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}
	payload, err := json.Marshal(map[string]any{
		"iss": testAttesterIssuer,
		"sub": subject,
		"iat": now.Unix(),
		"exp": now.Add(lifetime).Unix(),
		"cnf": map[string]any{"jwk": json.RawMessage(jwkJSON)},
	})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	compact, err := jose.Sign(attesterKey, jose.Header{Algorithm: fapi.ES256, Type: clientattestation.TypHeader}, payload)
	if err != nil {
		t.Fatalf("jose.Sign: %v", err)
	}
	return compact
}

func createAttestationPoPHeader(t *testing.T, instanceKey *ecdsa.PrivateKey, clientID, audience, jti string, now time.Time) string {
	t.Helper()
	payload, err := json.Marshal(map[string]any{
		"iss": clientID,
		"aud": audience,
		"jti": jti,
		"iat": now.Unix(),
	})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	compact, err := jose.Sign(instanceKey, jose.Header{Algorithm: fapi.ES256, Type: clientattestation.PoPTypHeader}, payload)
	if err != nil {
		t.Fatalf("jose.Sign: %v", err)
	}
	return compact
}

// newHarnessWithAttestationClientCredentials mirrors
// newHarnessWithClientCredentialsGrant, except testClientID is
// registered with ClientAuthMethodAttestation (trusting
// testAttesterIssuer, signed with ES256) instead of private_key_jwt,
// and Config.AttestationBasedClientAuthentication is enabled.
// deps.ClientKeys resolves attesterKey's own public key for
// testClientID — fakeClientKeySource ignores req.Purpose entirely (see
// its own definition), the same way keys/ephemeral's real
// ClientKeySource does, which is exactly what lets a single per-client
// key list serve both keys.ClientAssertionVerification and
// keys.AttestationVerification lookups in tests without needing a
// second fake.
func newHarnessWithAttestationClientCredentials(t *testing.T, attesterKey *ecdsa.PrivateKey) harness {
	t.Helper()
	now := time.Now()
	serverKey := generateKey(t)

	client, err := storage.NewRegisteredClient(storage.RegisteredClientConfig{
		ID:                           testClientID,
		RedirectURIs:                 []fapi.RegisteredRedirectURI{testRedirectURI},
		ClientAuthMethod:             storage.ClientAuthMethodAttestation,
		ExpectedAttesterIssuer:       testAttesterIssuer,
		ClientAttestationAlgorithm:   fapi.ES256,
		AllowedScopes:                []string{"accounts"},
		AllowsClientCredentialsGrant: true,
	})
	if err != nil {
		t.Fatalf("NewRegisteredClient: %v", err)
	}

	issuer, err := fapi.ParseIssuerURL(testIssuer)
	if err != nil {
		t.Fatalf("ParseIssuerURL: %v", err)
	}

	audit := &fakeAuditSink{}
	revocation := &fakeRevocationSink{}

	cfg := server.Config{
		Issuer:    issuer,
		Endpoints: testEndpoints(t),
		Profile:   server.ProfileFAPISecurity,
		Algorithms: server.AlgorithmPolicy{
			ClientAssertion:      server.AlgorithmSet{fapi.ES256},
			RequestObject:        server.AlgorithmSet{fapi.ES256},
			JARM:                 fapi.ES256,
			IDToken:              fapi.ES256,
			ClientAttestation:    server.AlgorithmSet{fapi.ES256},
			ClientAttestationPoP: server.AlgorithmSet{fapi.ES256},
		},
		Limits: server.Limits{
			PushedRequestLifetime:        90 * time.Second,
			MaxClientAssertionLifetime:   time.Minute,
			MaxRequestObjectLifetime:     time.Minute,
			InteractionLifetime:          5 * time.Minute,
			AuthorizationCodeLifetime:    time.Minute,
			JARMResponseLifetime:         time.Minute,
			AccessTokenLifetime:          5 * time.Minute,
			IDTokenLifetime:              5 * time.Minute,
			RefreshTokenLifetime:         5 * time.Minute,
			MaxDPoPProofAge:              time.Minute,
			MaxClockSkew:                 5 * time.Second,
			MaxClientAttestationLifetime: time.Hour,
			MaxClientAttestationPoPAge:   time.Minute,
		},
		Assurance:                            server.AssuranceDevelopment,
		ClientCredentialsGrant:               true,
		AttestationBasedClientAuthentication: true,
	}
	serverKeyManager := &fakeKeyManager{key: serverKey, keyID: "as-key-1"}
	deps := server.Dependencies{
		Clients:      &fakeClientRepository{clients: map[fapi.ClientID]storage.RegisteredClient{testClientID: client}},
		Transactions: &fakeTransactionStore{},
		Grants:       &fakeGrantStore{},
		Replay:       &fakeReplayStore{},
		ClientKeys: &fakeClientKeySource{keysByClient: map[fapi.ClientID][]keys.VerificationKey{
			testClientID: {{Algorithm: fapi.ES256, PublicKey: &attesterKey.PublicKey}},
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
	return harness{server: srv, serverKey: serverKey, audit: audit, revocation: revocation, now: now}
}

func attestationClientCredentialsFormParams(scope string) []server.FormParameter {
	return []server.FormParameter{
		formParam("grant_type", "client_credentials"),
		formParam("scope", scope),
	}
}

func TestRequestClientCredentialsToken_AttestationSuccess(t *testing.T) {
	attesterKey := generateKey(t)
	instanceKey := generateKey(t)
	dpopKey := generateKey(t)
	h := newHarnessWithAttestationClientCredentials(t, attesterKey)

	attestation := createAttestationHeader(t, attesterKey, testClientID.String(), &instanceKey.PublicKey, h.now, time.Hour)
	pop := createAttestationPoPHeader(t, instanceKey, testClientID.String(), testIssuer, "jti-1", h.now)

	result, err := h.server.RequestClientCredentialsToken(context.Background(), server.ClientCredentialsTokenRequest{
		HTTP:                  server.FormRequest{Parameters: attestationClientCredentialsFormParams("accounts")},
		ClientAttestations:    []string{attestation},
		ClientAttestationPoPs: []string{pop},
		DPoPProofs:            []string{createDPoPProof(t, dpopKey, h.now)},
	})
	if err != nil {
		t.Fatalf("RequestClientCredentialsToken: %v", err)
	}
	if result.AccessToken.Reveal() == "" {
		t.Fatalf("AccessToken is empty")
	}

	parsedAT, err := token.ParseAccessToken(result.AccessToken.Reveal())
	if err != nil {
		t.Fatalf("ParseAccessToken: %v", err)
	}
	validatedAT, err := parsedAT.Validate(&h.serverKey.PublicKey, token.AccessTokenValidatePolicy{
		ExpectedIssuer: testIssuer, ExpectedAudience: testIssuer,
		Algorithm: fapi.ES256, Now: h.now, MaxLifetime: 10 * time.Minute,
	})
	if err != nil {
		t.Fatalf("Validate access token: %v", err)
	}
	if validatedAT.ClientID != testClientID.String() {
		t.Fatalf("access token ClientID = %q, want %q", validatedAT.ClientID, testClientID)
	}
}

func TestRequestClientCredentialsToken_AttestationRejectsWhenDisabled(t *testing.T) {
	attesterKey := generateKey(t)
	instanceKey := generateKey(t)
	h := newHarnessWithAttestationClientCredentials(t, attesterKey)

	// Rebuild the same harness but with the feature disabled, to
	// confirm the deployment-wide switch is actually load-bearing, not
	// just checked once at server.New time.
	issuer, err := fapi.ParseIssuerURL(testIssuer)
	if err != nil {
		t.Fatalf("ParseIssuerURL: %v", err)
	}
	client, err := storage.NewRegisteredClient(storage.RegisteredClientConfig{
		ID: testClientID, RedirectURIs: []fapi.RegisteredRedirectURI{testRedirectURI},
		ClientAuthMethod: storage.ClientAuthMethodAttestation, ExpectedAttesterIssuer: testAttesterIssuer,
		ClientAttestationAlgorithm: fapi.ES256, AllowedScopes: []string{"accounts"}, AllowsClientCredentialsGrant: true,
	})
	if err != nil {
		t.Fatalf("NewRegisteredClient: %v", err)
	}
	serverKey := generateKey(t)
	serverKeyManager := &fakeKeyManager{key: serverKey, keyID: "as-key-1"}
	cfg := server.Config{
		Issuer: issuer, Endpoints: testEndpoints(t), Profile: server.ProfileFAPISecurity,
		Algorithms: server.AlgorithmPolicy{ClientAssertion: server.AlgorithmSet{fapi.ES256}, RequestObject: server.AlgorithmSet{fapi.ES256}, JARM: fapi.ES256, IDToken: fapi.ES256},
		Limits: server.Limits{
			PushedRequestLifetime: 90 * time.Second, MaxClientAssertionLifetime: time.Minute, MaxRequestObjectLifetime: time.Minute,
			InteractionLifetime: 5 * time.Minute, AuthorizationCodeLifetime: time.Minute, JARMResponseLifetime: time.Minute,
			AccessTokenLifetime: 5 * time.Minute, IDTokenLifetime: 5 * time.Minute, RefreshTokenLifetime: 5 * time.Minute,
			MaxDPoPProofAge: time.Minute, MaxClockSkew: 5 * time.Second,
		},
		Assurance: server.AssuranceDevelopment, ClientCredentialsGrant: true,
		// AttestationBasedClientAuthentication left false.
	}
	deps := server.Dependencies{
		Clients:      &fakeClientRepository{clients: map[fapi.ClientID]storage.RegisteredClient{testClientID: client}},
		Transactions: &fakeTransactionStore{}, Grants: &fakeGrantStore{}, Replay: &fakeReplayStore{},
		ClientKeys: &fakeClientKeySource{keysByClient: map[fapi.ClientID][]keys.VerificationKey{
			testClientID: {{Algorithm: fapi.ES256, PublicKey: &attesterKey.PublicKey}},
		}},
		Keys: serverKeyManager, AccessTokens: server.JWTAccessTokens{Keys: serverKeyManager, Algorithm: fapi.ES256},
		Revocation: &fakeRevocationSink{}, Audit: &fakeAuditSink{}, Clock: fixedClock{now: h.now}, Random: rand.Reader,
	}
	srv, err := server.New(cfg, deps)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}

	attestation := createAttestationHeader(t, attesterKey, testClientID.String(), &instanceKey.PublicKey, h.now, time.Hour)
	pop := createAttestationPoPHeader(t, instanceKey, testClientID.String(), testIssuer, "jti-1", h.now)

	_, err = srv.RequestClientCredentialsToken(context.Background(), server.ClientCredentialsTokenRequest{
		HTTP:                  server.FormRequest{Parameters: attestationClientCredentialsFormParams("accounts")},
		ClientAttestations:    []string{attestation},
		ClientAttestationPoPs: []string{pop},
	})
	if err == nil {
		t.Fatalf("RequestClientCredentialsToken succeeded with AttestationBasedClientAuthentication disabled")
	}
}

func TestRequestClientCredentialsToken_AttestationRejectsWrongAttesterIssuer(t *testing.T) {
	attesterKey := generateKey(t)
	instanceKey := generateKey(t)
	h := newHarnessWithAttestationClientCredentials(t, attesterKey)

	payload, err := json.Marshal(map[string]any{
		"iss": "https://wrong-attester.example.com",
		"sub": testClientID.String(),
		"exp": h.now.Add(time.Hour).Unix(),
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	jwk, err := jose.NewJWK(&instanceKey.PublicKey, fapi.ES256)
	if err != nil {
		t.Fatalf("NewJWK: %v", err)
	}
	jwkJSON, err := jwk.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(payload, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	m["cnf"] = map[string]any{"jwk": json.RawMessage(jwkJSON)}
	payload, err = json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	attestation, err := jose.Sign(attesterKey, jose.Header{Algorithm: fapi.ES256, Type: clientattestation.TypHeader}, payload)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	pop := createAttestationPoPHeader(t, instanceKey, testClientID.String(), testIssuer, "jti-1", h.now)

	_, err = h.server.RequestClientCredentialsToken(context.Background(), server.ClientCredentialsTokenRequest{
		HTTP:                  server.FormRequest{Parameters: attestationClientCredentialsFormParams("accounts")},
		ClientAttestations:    []string{attestation},
		ClientAttestationPoPs: []string{pop},
	})
	if err == nil {
		t.Fatalf("RequestClientCredentialsToken accepted an attestation from an untrusted attester")
	}
}

func TestRequestClientCredentialsToken_AttestationRejectsMultipleHeaders(t *testing.T) {
	attesterKey := generateKey(t)
	instanceKey := generateKey(t)
	h := newHarnessWithAttestationClientCredentials(t, attesterKey)

	attestation := createAttestationHeader(t, attesterKey, testClientID.String(), &instanceKey.PublicKey, h.now, time.Hour)
	pop := createAttestationPoPHeader(t, instanceKey, testClientID.String(), testIssuer, "jti-1", h.now)

	_, err := h.server.RequestClientCredentialsToken(context.Background(), server.ClientCredentialsTokenRequest{
		HTTP:                  server.FormRequest{Parameters: attestationClientCredentialsFormParams("accounts")},
		ClientAttestations:    []string{attestation, attestation},
		ClientAttestationPoPs: []string{pop},
	})
	if err == nil {
		t.Fatalf("RequestClientCredentialsToken accepted two OAuth-Client-Attestation headers")
	}
}

func TestRequestClientCredentialsToken_AttestationRejectsReplayedPoP(t *testing.T) {
	attesterKey := generateKey(t)
	instanceKey := generateKey(t)
	h := newHarnessWithAttestationClientCredentials(t, attesterKey)

	attestation := createAttestationHeader(t, attesterKey, testClientID.String(), &instanceKey.PublicKey, h.now, time.Hour)
	pop := createAttestationPoPHeader(t, instanceKey, testClientID.String(), testIssuer, "same-jti", h.now)

	// Each request gets its own fresh DPoP proof (DPoP has its own,
	// separate jti-based replay protection) so only the reused
	// attestation PoP jti can explain a second-request rejection.
	firstDPoPKey := generateKey(t)
	req := server.ClientCredentialsTokenRequest{
		HTTP:                  server.FormRequest{Parameters: attestationClientCredentialsFormParams("accounts")},
		ClientAttestations:    []string{attestation},
		ClientAttestationPoPs: []string{pop},
		DPoPProofs:            []string{createDPoPProof(t, firstDPoPKey, h.now)},
	}
	if _, err := h.server.RequestClientCredentialsToken(context.Background(), req); err != nil {
		t.Fatalf("first request: %v", err)
	}

	secondDPoPKey := generateKey(t)
	req.DPoPProofs = []string{createDPoPProof(t, secondDPoPKey, h.now)}
	if _, err := h.server.RequestClientCredentialsToken(context.Background(), req); err == nil {
		t.Fatalf("second request with the same PoP jti succeeded, want replay rejection")
	}
}

func TestMetadata_AttestationBasedClientAuthentication(t *testing.T) {
	attesterKey := generateKey(t)
	h := newHarnessWithAttestationClientCredentials(t, attesterKey)

	md := h.server.Metadata(context.Background())
	found := false
	for _, m := range md.TokenEndpointAuthMethodsSupported {
		if m == "attest_jwt_client_auth" {
			found = true
		}
	}
	if !found {
		t.Errorf("TokenEndpointAuthMethodsSupported = %v, want it to contain attest_jwt_client_auth", md.TokenEndpointAuthMethodsSupported)
	}
	if len(md.ClientAttestationSigningAlgValuesSupported) == 0 {
		t.Errorf("ClientAttestationSigningAlgValuesSupported is empty")
	}
	if len(md.ClientAttestationPoPSigningAlgValuesSupported) == 0 {
		t.Errorf("ClientAttestationPoPSigningAlgValuesSupported is empty")
	}
}

func TestMetadata_OmitsAttestationWhenDisabled(t *testing.T) {
	h := newHarnessWithClientCredentialsGrant(t, storage.SenderConstrainDPoP, true)

	md := h.server.Metadata(context.Background())
	for _, m := range md.TokenEndpointAuthMethodsSupported {
		if m == "attest_jwt_client_auth" {
			t.Errorf("TokenEndpointAuthMethodsSupported unexpectedly contains attest_jwt_client_auth")
		}
	}
	if md.ClientAttestationSigningAlgValuesSupported != nil {
		t.Errorf("ClientAttestationSigningAlgValuesSupported = %v, want nil", md.ClientAttestationSigningAlgValuesSupported)
	}
}
