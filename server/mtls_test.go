package server_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/clientassertion"
	"github.com/idfoundry/fapigo/internal/mtls"
	"github.com/idfoundry/fapigo/internal/token"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
)

// selfSignedTestClientCert generates a throwaway self-signed
// ExtKeyUsageClientAuth certificate — standing in for a real mTLS
// connection's own presented client certificate, the same in-memory
// generate-a-cert approach cmd/conformance-as/smoke_test.go's own
// selfSignedCert helper uses for the server-cert side.
func selfSignedTestClientCert(t *testing.T) *x509.Certificate {
	t.Helper()
	return selfSignedTestClientCertWithSAN(t, func(*x509.Certificate) {})
}

// selfSignedTestClientCertWithSAN mirrors selfSignedTestClientCert
// exactly, but lets a caller populate the certificate's own
// subjectAltName entries (DNSNames/URIs/IPAddresses/EmailAddresses)
// before it's signed — for exercising the four SAN-based
// ClientAuthMethodTLSClientAuthSAN* variants (see client_auth_mtls_test.go).
func selfSignedTestClientCertWithSAN(t *testing.T, mutate func(*x509.Certificate)) *x509.Certificate {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		t.Fatalf("generate serial: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "test-mtls-client"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	mutate(template)
	der, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return cert
}

// newHarnessWithSenderConstrainMTLS mirrors newHarness (baseline
// profile, request objects allowed) exactly, except testClientID is
// registered with SenderConstrain: storage.SenderConstrainMTLS instead
// of the default DPoP — every other harness field (key, serverKey,
// now, stores) behaves identically, so h.clientAssertion(t) and every
// other harness helper still apply unchanged.
func newHarnessWithSenderConstrainMTLS(t *testing.T) harness {
	t.Helper()
	now := time.Now()
	key := generateKey(t)
	serverKey := generateKey(t)

	client, err := storage.NewRegisteredClient(storage.RegisteredClientConfig{
		ID:                       testClientID,
		RedirectURIs:             []fapi.RegisteredRedirectURI{testRedirectURI},
		ClientAssertionAlgorithm: fapi.ES256,
		RequestObjectAlgorithm:   fapi.ES256,
		SenderConstrain:          storage.SenderConstrainMTLS,
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

// newHarnessWithSenderConstrainMTLSAndAliases is
// newHarnessWithSenderConstrainMTLS plus Config.MTLSEndpoints
// configured, so an mTLS-bound client's client assertion may name
// either the issuer or one of these alias URLs as "aud" — see
// acceptableClientAssertionAudiences' own doc comment (server/par.go).
// Returns the alias token endpoint URL for a test to build an
// assertion against.
func newHarnessWithSenderConstrainMTLSAndAliases(t *testing.T) (harness, string) {
	t.Helper()
	now := time.Now()
	key := generateKey(t)
	serverKey := generateKey(t)

	client, err := storage.NewRegisteredClient(storage.RegisteredClientConfig{
		ID:                       testClientID,
		RedirectURIs:             []fapi.RegisteredRedirectURI{testRedirectURI},
		ClientAssertionAlgorithm: fapi.ES256,
		SenderConstrain:          storage.SenderConstrainMTLS,
		AllowedScopes:            []string{"openid", "accounts", "offline_access"},
	})
	if err != nil {
		t.Fatalf("NewRegisteredClient: %v", err)
	}

	issuer, err := fapi.ParseIssuerURL(testIssuer)
	if err != nil {
		t.Fatalf("ParseIssuerURL: %v", err)
	}
	mtlsToken, err := fapi.ParseEndpointURL("https://mtls.as.example/token")
	if err != nil {
		t.Fatalf("ParseEndpointURL: %v", err)
	}

	cfg := server.Config{
		Issuer:        issuer,
		Endpoints:     testEndpoints(t),
		MTLSEndpoints: server.MTLSEndpoints{Token: mtlsToken},
		Profile:       server.ProfileFAPISecurity,
		Algorithms: server.AlgorithmPolicy{
			ClientAssertion: server.AlgorithmSet{fapi.ES256},
			RequestObject:   server.AlgorithmSet{fapi.ES256},
			IDToken:         fapi.ES256,
		},
		Limits: server.Limits{
			PushedRequestLifetime:      90 * time.Second,
			MaxClientAssertionLifetime: time.Minute,
			MaxRequestObjectLifetime:   time.Minute,
			InteractionLifetime:        5 * time.Minute,
			AuthorizationCodeLifetime:  time.Minute,
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
		Keys:         serverKeyManager,
		AccessTokens: server.JWTAccessTokens{Keys: serverKeyManager, Algorithm: fapi.ES256},
		Revocation:   &fakeRevocationSink{},
		Clock:        fixedClock{now: now},
		Random:       rand.Reader,
	}
	srv, err := server.New(cfg, deps)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	return harness{server: srv, key: key, serverKey: serverKey, now: now}, mtlsToken.String()
}

// TestExchangeAuthorizationCodeAcceptsMTLSAliasAsClientAssertionAudience
// covers RFC 7523 §3's own looseness ("aud"... identifies the AS,
// not necessarily one fixed URL): an mTLS-bound client may call the
// token endpoint via its RFC 8705 §5 alias and sign its client
// assertion's "aud" against that alias URL rather than the issuer,
// since both identify the same authorization server. Scoped to the
// token endpoint specifically — see
// TestPushAuthorizationRequestRejectsMTLSAliasAsClientAssertionAudience
// for why PAR must reject this exact same value.
func TestExchangeAuthorizationCodeAcceptsMTLSAliasAsClientAssertionAudience(t *testing.T) {
	h, mtlsToken := newHarnessWithSenderConstrainMTLSAndAliases(t)
	code := completeSuccessfulAuthorization(t, h, []string{"openid", "accounts"})
	cert := selfSignedTestClientCert(t)
	assertion, err := clientassertion.CreateAssertion(clientassertion.AssertionRequest{
		Signer: h.key, Algorithm: fapi.ES256,
		ClientID: testClientID.String(), Audience: mtlsToken,
		Now: h.now, Lifetime: 30 * time.Second,
	})
	if err != nil {
		t.Fatalf("CreateAssertion: %v", err)
	}
	if _, err := h.server.ExchangeAuthorizationCode(context.Background(), server.AuthorizationCodeExchangeRequest{
		HTTP:            server.FormRequest{Parameters: exchangeFormParams(assertion, code, testRedirectURI, testCodeVerifier)},
		PeerCertificate: cert,
	}); err != nil {
		t.Fatalf("ExchangeAuthorizationCode: %v", err)
	}
}

// TestPushAuthorizationRequestRejectsMTLSAliasAsClientAssertionAudience
// confirms PAR rejects the token endpoint's own mTLS alias as a client
// assertion audience — confirmed live against the OIDF conformance
// suite's own
// fapi2-security-profile-final-par-test-token-endpoint-url-as-audience-fails
// module (which probes with the plain URL; the same
// acceptableClientAssertionAudiences scoping applies identically to its
// mTLS alias). See that function's own doc comment for why PAR accepts
// no endpoint-URL audience at all, aliased or not.
func TestPushAuthorizationRequestRejectsMTLSAliasAsClientAssertionAudience(t *testing.T) {
	h, mtlsToken := newHarnessWithSenderConstrainMTLSAndAliases(t)
	assertion, err := clientassertion.CreateAssertion(clientassertion.AssertionRequest{
		Signer: h.key, Algorithm: fapi.ES256,
		ClientID: testClientID.String(), Audience: mtlsToken,
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
}

// TestPushAuthorizationRequestRejectsMTLSAliasForDPoPClient confirms
// the widened audience set above is scoped to a SenderConstrainMTLS
// client only — a DPoP-bound client's assertion must still name the
// issuer exactly, even when Config.MTLSEndpoints happens to be
// configured for some other client.
func TestPushAuthorizationRequestRejectsMTLSAliasForDPoPClient(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	assertion, err := clientassertion.CreateAssertion(clientassertion.AssertionRequest{
		Signer: h.key, Algorithm: fapi.ES256,
		ClientID: testClientID.String(), Audience: "https://mtls.as.example/token",
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
}

func TestExchangeAuthorizationCodeWithMTLSBinding(t *testing.T) {
	h := newHarnessWithSenderConstrainMTLS(t)
	code := completeSuccessfulAuthorization(t, h, []string{"openid", "accounts"})
	cert := selfSignedTestClientCert(t)

	result, err := h.server.ExchangeAuthorizationCode(context.Background(), server.AuthorizationCodeExchangeRequest{
		HTTP:            server.FormRequest{Parameters: exchangeFormParams(h.clientAssertion(t), code, testRedirectURI, testCodeVerifier)},
		PeerCertificate: cert,
	})
	if err != nil {
		t.Fatalf("ExchangeAuthorizationCode: %v", err)
	}
	if result.TokenType != "Bearer" {
		t.Fatalf("TokenType = %q, want %q (RFC 8705 §3.4)", result.TokenType, "Bearer")
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
	if validatedAT.X5TS256 != mtls.Thumbprint(cert) {
		t.Fatalf("access token X5TS256 = %q, want %q", validatedAT.X5TS256, mtls.Thumbprint(cert))
	}
	if validatedAT.JKT != "" {
		t.Fatalf("access token JKT = %q, want empty (mTLS-bound, not DPoP-bound)", validatedAT.JKT)
	}
}

func TestExchangeAuthorizationCodeMTLSRequiresPeerCertificate(t *testing.T) {
	h := newHarnessWithSenderConstrainMTLS(t)
	code := completeSuccessfulAuthorization(t, h, []string{"openid", "accounts"})

	_, err := h.server.ExchangeAuthorizationCode(context.Background(), server.AuthorizationCodeExchangeRequest{
		HTTP: server.FormRequest{Parameters: exchangeFormParams(h.clientAssertion(t), code, testRedirectURI, testCodeVerifier)},
		// PeerCertificate intentionally omitted.
	})
	if err == nil {
		t.Fatalf("ExchangeAuthorizationCode(no peer certificate) = nil error, want error")
	}
}

// TestExchangeAuthorizationCodeMTLSIgnoresDPoPProof confirms an
// mTLS-bound client's DPoP proof (if it sent one anyway) plays no role
// — the access token is still issued and bound via PeerCertificate,
// mirroring how a DPoP-bound client's stray, unrelated headers are
// similarly inert.
func TestExchangeAuthorizationCodeMTLSIgnoresDPoPProof(t *testing.T) {
	h := newHarnessWithSenderConstrainMTLS(t)
	code := completeSuccessfulAuthorization(t, h, []string{"openid", "accounts"})
	cert := selfSignedTestClientCert(t)

	result, err := h.server.ExchangeAuthorizationCode(context.Background(), server.AuthorizationCodeExchangeRequest{
		HTTP:            server.FormRequest{Parameters: exchangeFormParams(h.clientAssertion(t), code, testRedirectURI, testCodeVerifier)},
		DPoPProofs:      []string{createDPoPProof(t, generateKey(t), h.now)},
		PeerCertificate: cert,
	})
	if err != nil {
		t.Fatalf("ExchangeAuthorizationCode: %v", err)
	}
	if result.TokenType != "Bearer" {
		t.Fatalf("TokenType = %q, want %q", result.TokenType, "Bearer")
	}
}

func TestRefreshAccessTokenWithMTLSBinding(t *testing.T) {
	h := newHarnessWithSenderConstrainMTLS(t)
	code := completeSuccessfulAuthorization(t, h, []string{"openid", "accounts", "offline_access"})
	firstCert := selfSignedTestClientCert(t)

	first, err := h.server.ExchangeAuthorizationCode(context.Background(), server.AuthorizationCodeExchangeRequest{
		HTTP:            server.FormRequest{Parameters: exchangeFormParams(h.clientAssertion(t), code, testRedirectURI, testCodeVerifier)},
		PeerCertificate: firstCert,
	})
	if err != nil {
		t.Fatalf("ExchangeAuthorizationCode: %v", err)
	}
	if !first.HasRefreshToken {
		t.Fatalf("expected a refresh token since scope included offline_access")
	}

	// RFC 9449 §5's "refresh binds to whatever key shows up" carve-out
	// applies the same way to mTLS: a different certificate at refresh
	// time is expected and correctly handled, not an error — see
	// RefreshTokenRequest.PeerCertificate's own doc comment.
	secondCert := selfSignedTestClientCert(t)
	refreshed, err := h.server.RefreshAccessToken(context.Background(), server.RefreshTokenRequest{
		HTTP: server.FormRequest{Parameters: []server.FormParameter{
			formParam("client_assertion", h.clientAssertion(t)),
			formParam("client_assertion_type", clientassertion.AssertionType),
			formParam("grant_type", "refresh_token"),
			formParam("refresh_token", first.RefreshToken.Reveal()),
		}},
		PeerCertificate: secondCert,
	})
	if err != nil {
		t.Fatalf("RefreshAccessToken: %v", err)
	}
	if refreshed.TokenType != "Bearer" {
		t.Fatalf("TokenType = %q, want %q", refreshed.TokenType, "Bearer")
	}

	parsedAT, err := token.ParseAccessToken(refreshed.AccessToken.Reveal())
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
	if validatedAT.X5TS256 != mtls.Thumbprint(secondCert) {
		t.Fatalf("refreshed access token X5TS256 = %q, want %q (bound to the certificate presented at refresh time)", validatedAT.X5TS256, mtls.Thumbprint(secondCert))
	}
}

func TestServerMetadataOmitsMTLSEndpointAliasesWhenUnconfigured(t *testing.T) {
	h := newHarnessWithSenderConstrainMTLS(t)
	md := h.server.Metadata(context.Background())
	if md.MTLSEndpointAliases != nil {
		t.Fatalf("MTLSEndpointAliases = %+v, want nil (Config.MTLSEndpoints was never set)", md.MTLSEndpointAliases)
	}
	// RFC 8705 §3.3: this boolean advertises the same capability
	// MTLSEndpointAliases does — must track it exactly, never be true
	// on its own.
	if md.TLSClientCertificateBoundAccessTokens {
		t.Fatalf("TLSClientCertificateBoundAccessTokens = true, want false (Config.MTLSEndpoints was never set)")
	}
	if containsString(md.TokenEndpointAuthMethodsSupported, "self_signed_tls_client_auth") || containsString(md.TokenEndpointAuthMethodsSupported, "tls_client_auth") {
		t.Fatalf("TokenEndpointAuthMethodsSupported = %v, want neither mTLS method (Config.MTLSEndpoints was never set)", md.TokenEndpointAuthMethodsSupported)
	}
}

func TestServerMetadataAdvertisesMTLSEndpointAliasesWhenConfigured(t *testing.T) {
	mtlsToken, err := fapi.ParseEndpointURL("https://mtls.as.example/token")
	if err != nil {
		t.Fatalf("ParseEndpointURL: %v", err)
	}
	mtlsPAR, err := fapi.ParseEndpointURL("https://mtls.as.example/par")
	if err != nil {
		t.Fatalf("ParseEndpointURL: %v", err)
	}

	// No newHarness* variant exposes its own Config for mutation, and
	// the only field under test (Config.MTLSEndpoints) doesn't depend
	// on anything else a harness sets up — so this test builds a
	// server directly instead.
	issuer, err := fapi.ParseIssuerURL(testIssuer)
	if err != nil {
		t.Fatalf("ParseIssuerURL: %v", err)
	}
	serverKey := generateKey(t)
	serverKeyManager := &fakeKeyManager{key: serverKey, keyID: "as-key-1"}
	srv, err := server.New(server.Config{
		Issuer:    issuer,
		Endpoints: testEndpoints(t),
		Profile:   server.ProfileFAPISecurity,
		MTLSEndpoints: server.MTLSEndpoints{
			Token:                      mtlsToken,
			PushedAuthorizationRequest: mtlsPAR,
		},
		Algorithms: server.AlgorithmPolicy{
			ClientAssertion: server.AlgorithmSet{fapi.ES256},
			RequestObject:   server.AlgorithmSet{fapi.ES256},
			IDToken:         fapi.ES256,
		},
		Limits: server.Limits{
			PushedRequestLifetime:      90 * time.Second,
			MaxClientAssertionLifetime: time.Minute,
			MaxRequestObjectLifetime:   time.Minute,
			InteractionLifetime:        5 * time.Minute,
			AuthorizationCodeLifetime:  time.Minute,
			AccessTokenLifetime:        5 * time.Minute,
			IDTokenLifetime:            5 * time.Minute,
			RefreshTokenLifetime:       5 * time.Minute,
			MaxDPoPProofAge:            time.Minute,
			MaxClockSkew:               5 * time.Second,
		},
		Assurance: server.AssuranceDevelopment,
	}, server.Dependencies{
		Clients:      &fakeClientRepository{},
		Transactions: &fakeTransactionStore{},
		Grants:       &fakeGrantStore{},
		Replay:       &fakeReplayStore{},
		ClientKeys:   &fakeClientKeySource{},
		Keys:         serverKeyManager,
		AccessTokens: server.JWTAccessTokens{Keys: serverKeyManager, Algorithm: fapi.ES256},
		Revocation:   &fakeRevocationSink{},
		Clock:        fixedClock{now: time.Now()},
		Random:       rand.Reader,
	})
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}

	md := srv.Metadata(context.Background())
	if md.MTLSEndpointAliases == nil {
		t.Fatalf("MTLSEndpointAliases = nil, want non-nil")
	}
	if md.MTLSEndpointAliases.TokenEndpoint.String() != mtlsToken.String() {
		t.Errorf("MTLSEndpointAliases.TokenEndpoint = %q, want %q", md.MTLSEndpointAliases.TokenEndpoint.String(), mtlsToken.String())
	}
	if md.MTLSEndpointAliases.PushedAuthorizationRequestEndpoint.String() != mtlsPAR.String() {
		t.Errorf("MTLSEndpointAliases.PushedAuthorizationRequestEndpoint = %q, want %q", md.MTLSEndpointAliases.PushedAuthorizationRequestEndpoint.String(), mtlsPAR.String())
	}
	if !md.MTLSEndpointAliases.BackchannelAuthenticationEndpoint.IsZero() {
		t.Errorf("MTLSEndpointAliases.BackchannelAuthenticationEndpoint = %q, want zero", md.MTLSEndpointAliases.BackchannelAuthenticationEndpoint.String())
	}
	if !md.TLSClientCertificateBoundAccessTokens {
		t.Errorf("TLSClientCertificateBoundAccessTokens = false, want true (RFC 8705 §3.3)")
	}
	// RFC 8705 §2: a client can only ever present a certificate for
	// authentication once an mTLS-requesting listener exists at all —
	// the same precondition TLSClientCertificateBoundAccessTokens is
	// gated on above — so both auth methods appear here alongside
	// private_key_jwt, not in place of it.
	if !containsString(md.TokenEndpointAuthMethodsSupported, "private_key_jwt") {
		t.Errorf("TokenEndpointAuthMethodsSupported = %v, want to still contain private_key_jwt", md.TokenEndpointAuthMethodsSupported)
	}
	if !containsString(md.TokenEndpointAuthMethodsSupported, "self_signed_tls_client_auth") {
		t.Errorf("TokenEndpointAuthMethodsSupported = %v, want to contain self_signed_tls_client_auth", md.TokenEndpointAuthMethodsSupported)
	}
	if !containsString(md.TokenEndpointAuthMethodsSupported, "tls_client_auth") {
		t.Errorf("TokenEndpointAuthMethodsSupported = %v, want to contain tls_client_auth", md.TokenEndpointAuthMethodsSupported)
	}
}
