package server_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"net"
	"net/url"
	"strings"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/clientassertion"
	"github.com/idfoundry/fapigo/internal/dpop"
	"github.com/idfoundry/fapigo/internal/mtls"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
	"github.com/idfoundry/fapigo/storage/memstore"
)

// newHarnessWithClientAuthSelfSignedTLS mirrors newHarnessWithSenderConstrainMTLS
// exactly, except testClientID is registered under
// ClientAuthMethodSelfSignedTLSClientAuth (identity proven by
// certificate thumbprint, not a signed assertion) instead of the
// default private_key_jwt. SenderConstrain is also set to
// SenderConstrainMTLS, so the same certificate serves both roles — a
// realistic combined deployment, and it keeps token-exchange tests from
// also needing an unrelated DPoP proof. Returns the certificate
// registered as this client's identity.
func newHarnessWithClientAuthSelfSignedTLS(t *testing.T) (harness, *x509.Certificate) {
	t.Helper()
	now := time.Now()
	serverKey := generateKey(t)
	cert := selfSignedTestClientCert(t)

	client, err := storage.NewRegisteredClient(storage.RegisteredClientConfig{
		ID:                            testClientID,
		RedirectURIs:                  []fapi.RegisteredRedirectURI{testRedirectURI},
		ClientAuthMethod:              storage.ClientAuthMethodSelfSignedTLSClientAuth,
		ExpectedCertificateThumbprint: mtls.Thumbprint(cert),
		SenderConstrain:               storage.SenderConstrainMTLS,
		AllowedScopes:                 []string{"openid", "accounts", "offline_access"},
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
		ClientKeys:   &fakeClientKeySource{},
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
	return harness{server: srv, serverKey: serverKey, now: now}, cert
}

// newHarnessWithClientAuthTLSSubjectDN mirrors
// newHarnessWithClientAuthSelfSignedTLS, except testClientID is
// registered under ClientAuthMethodTLSClientAuth — identity proven by
// exact subject-DN match — with ExpectedSubjectDN set to cert's own
// serialized subject.
func newHarnessWithClientAuthTLSSubjectDN(t *testing.T) (harness, *x509.Certificate) {
	t.Helper()
	cert := selfSignedTestClientCert(t)
	return newHarnessWithClientAuthTLSSubjectDNValue(t, cert, cert.Subject.String()), cert
}

// newHarnessWithClientAuthTLSSubjectDNValue lets a test register a
// deliberately different ExpectedSubjectDN than cert's own — used by
// TestPushAuthorizationRequestTLSClientAuthCaseSensitiveSubjectDN to
// exercise a mismatch that differs only in case.
func newHarnessWithClientAuthTLSSubjectDNValue(t *testing.T, cert *x509.Certificate, expectedSubjectDN string) harness {
	t.Helper()
	now := time.Now()
	serverKey := generateKey(t)

	client, err := storage.NewRegisteredClient(storage.RegisteredClientConfig{
		ID:                testClientID,
		RedirectURIs:      []fapi.RegisteredRedirectURI{testRedirectURI},
		ClientAuthMethod:  storage.ClientAuthMethodTLSClientAuth,
		ExpectedSubjectDN: expectedSubjectDN,
		SenderConstrain:   storage.SenderConstrainMTLS,
		AllowedScopes:     []string{"openid", "accounts", "offline_access"},
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
		ClientKeys:   &fakeClientKeySource{},
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
	return harness{server: srv, serverKey: serverKey, now: now}
}

// newHarnessWithClientAuthTLSSAN generalizes
// newHarnessWithClientAuthTLSSubjectDNValue across all four SAN-based
// ClientAuthMethodTLSClientAuthSAN* variants: registers testClientID
// under method with registeredValue as the matching Expected* field,
// and builds a certificate whose own subjectAltName entries are
// populated by certSAN (selfSignedTestClientCertWithSAN, mtls_test.go).
func newHarnessWithClientAuthTLSSAN(t *testing.T, method storage.ClientAuthMethod, registeredValue string, certSAN func(*x509.Certificate)) (harness, *x509.Certificate) {
	t.Helper()
	now := time.Now()
	serverKey := generateKey(t)
	cert := selfSignedTestClientCertWithSAN(t, certSAN)

	cfg := storage.RegisteredClientConfig{
		ID:               testClientID,
		RedirectURIs:     []fapi.RegisteredRedirectURI{testRedirectURI},
		ClientAuthMethod: method,
		SenderConstrain:  storage.SenderConstrainMTLS,
		AllowedScopes:    []string{"openid", "accounts", "offline_access"},
	}
	switch method {
	case storage.ClientAuthMethodTLSClientAuthSANDNS:
		cfg.ExpectedSANDNS = registeredValue
	case storage.ClientAuthMethodTLSClientAuthSANURI:
		cfg.ExpectedSANURI = registeredValue
	case storage.ClientAuthMethodTLSClientAuthSANIP:
		cfg.ExpectedSANIP = registeredValue
	case storage.ClientAuthMethodTLSClientAuthSANEmail:
		cfg.ExpectedSANEmail = registeredValue
	}
	client, err := storage.NewRegisteredClient(cfg)
	if err != nil {
		t.Fatalf("NewRegisteredClient: %v", err)
	}

	issuer, err := fapi.ParseIssuerURL(testIssuer)
	if err != nil {
		t.Fatalf("ParseIssuerURL: %v", err)
	}

	srvCfg := server.Config{
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
		ClientKeys:   &fakeClientKeySource{},
		Keys:         serverKeyManager,
		AccessTokens: server.JWTAccessTokens{Keys: serverKeyManager, Algorithm: fapi.ES256},
		Revocation:   &fakeRevocationSink{},
		Clock:        fixedClock{now: now},
		Random:       rand.Reader,
	}

	srv, err := server.New(srvCfg, deps)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	return harness{server: srv, serverKey: serverKey, now: now}, cert
}

// certFormParameters builds a standard authorization request's form
// body for a client authenticating via a plain client_id (no
// client_assertion) — the RFC 8705 §2 shape.
func certFormParameters(extra map[string]string) []server.FormParameter {
	params := []server.FormParameter{
		formParam("client_id", testClientID.String()),
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

// completeSuccessfulCertAuthorization mirrors completeSuccessfulAuthorization
// exactly, except PAR authenticates via client_id+cert instead of
// h.clientAssertion(t) — for a harness whose client has no signing key
// at all (client_auth_mtls harnesses set h.key to its zero value).
func completeSuccessfulCertAuthorization(t *testing.T, h harness, cert *x509.Certificate, grantedScope []string) string {
	t.Helper()
	pushResult, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
		HTTP: server.FormRequest{Parameters: []server.FormParameter{
			formParam("client_id", testClientID.String()),
			formParam("response_type", "code"),
			formParam("redirect_uri", testRedirectURI),
			formParam("scope", "openid accounts offline_access"),
			formParam("code_challenge", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"),
			formParam("code_challenge_method", "S256"),
			formParam("state", "opaque-state"),
		}},
		PeerCertificate: cert,
	})
	if err != nil {
		t.Fatalf("PushAuthorizationRequest: %v", err)
	}
	action, err := h.server.BeginAuthorization(context.Background(), server.BeginAuthorizationRequest{
		RequestURI: pushResult.RequestURI.String(), ClientID: testClientID,
	})
	if err != nil {
		t.Fatalf("BeginAuthorization: %v", err)
	}
	required, ok := action.(server.InteractionRequired)
	if !ok {
		t.Fatalf("action = %T, want server.InteractionRequired", action)
	}

	subjectID, err := server.NewSubjectID("user-1")
	if err != nil {
		t.Fatalf("NewSubjectID: %v", err)
	}
	subject, err := server.NewAuthenticatedSubject(subjectID)
	if err != nil {
		t.Fatalf("NewAuthenticatedSubject: %v", err)
	}
	authCtx, err := server.NewAuthenticationContext(h.now, "urn:mace:incommon:iap:silver", []string{"pwd"})
	if err != nil {
		t.Fatalf("NewAuthenticationContext: %v", err)
	}

	result, err := h.server.CompleteAuthorization(context.Background(), server.CompleteAuthorizationRequest{
		Handle: required.Handle,
		Result: server.Authorize(subject, authCtx, server.GrantedAuthorization{Scope: grantedScope}),
	})
	if err != nil {
		t.Fatalf("CompleteAuthorization: %v", err)
	}
	redirect, ok := result.(server.AuthorizationRedirect)
	if !ok {
		t.Fatalf("result = %T, want server.AuthorizationRedirect", result)
	}
	dest := redirect.Destination().URL()
	code := dest.Query().Get("code")
	if code == "" {
		t.Fatalf("redirect missing code parameter: %q", dest.String())
	}
	return code
}

func TestPushAuthorizationRequestSelfSignedTLSClientAuthSuccess(t *testing.T) {
	h, cert := newHarnessWithClientAuthSelfSignedTLS(t)
	if _, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
		HTTP:            server.FormRequest{Parameters: certFormParameters(nil)},
		PeerCertificate: cert,
	}); err != nil {
		t.Fatalf("PushAuthorizationRequest: %v", err)
	}
}

func TestExchangeAuthorizationCodeSelfSignedTLSClientAuthSuccess(t *testing.T) {
	h, cert := newHarnessWithClientAuthSelfSignedTLS(t)
	code := completeSuccessfulCertAuthorization(t, h, cert, []string{"openid", "accounts"})

	result, err := h.server.ExchangeAuthorizationCode(context.Background(), server.AuthorizationCodeExchangeRequest{
		HTTP: server.FormRequest{Parameters: []server.FormParameter{
			formParam("client_id", testClientID.String()),
			formParam("grant_type", "authorization_code"),
			formParam("code", code),
			formParam("redirect_uri", testRedirectURI),
			formParam("code_verifier", testCodeVerifier),
		}},
		PeerCertificate: cert,
	})
	if err != nil {
		t.Fatalf("ExchangeAuthorizationCode: %v", err)
	}
	if result.TokenType != "Bearer" {
		t.Fatalf("TokenType = %q, want %q", result.TokenType, "Bearer")
	}
}

func TestPushAuthorizationRequestSelfSignedTLSClientAuthRejectsMismatchedCertificate(t *testing.T) {
	h, _ := newHarnessWithClientAuthSelfSignedTLS(t)
	wrongCert := selfSignedTestClientCert(t)
	_, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
		HTTP:            server.FormRequest{Parameters: certFormParameters(nil)},
		PeerCertificate: wrongCert,
	})
	if err == nil {
		t.Fatalf("PushAuthorizationRequest(mismatched cert) = nil error, want error")
	}
	if code := serverErrorCode(t, err); code != server.ErrorInvalidClient {
		t.Fatalf("error code = %q, want %q", code, server.ErrorInvalidClient)
	}
}

func TestPushAuthorizationRequestCertClientAuthRequiresPeerCertificate(t *testing.T) {
	h, _ := newHarnessWithClientAuthSelfSignedTLS(t)
	_, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
		HTTP: server.FormRequest{Parameters: certFormParameters(nil)},
		// PeerCertificate intentionally omitted.
	})
	if err == nil {
		t.Fatalf("PushAuthorizationRequest(no peer certificate) = nil error, want error")
	}
	if code := serverErrorCode(t, err); code != server.ErrorInvalidClient {
		t.Fatalf("error code = %q, want %q", code, server.ErrorInvalidClient)
	}
}

// TestPushAuthorizationRequestRejectsClientAssertionForCertRegisteredClient
// covers the shape-mismatch direction where a client registered for
// certificate-based authentication instead presents a signed
// client_assertion — rejected outright, before any signature
// verification is attempted, since this client isn't registered for
// private_key_jwt at all.
func TestPushAuthorizationRequestRejectsClientAssertionForCertRegisteredClient(t *testing.T) {
	h, cert := newHarnessWithClientAuthSelfSignedTLS(t)
	key := generateKey(t)
	assertion, err := clientassertion.CreateAssertion(clientassertion.AssertionRequest{
		Signer: key, Algorithm: fapi.ES256,
		ClientID: testClientID.String(), Audience: testIssuer,
		Now: h.now, Lifetime: 30 * time.Second,
	})
	if err != nil {
		t.Fatalf("CreateAssertion: %v", err)
	}
	_, err = h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
		HTTP:            server.FormRequest{Parameters: plainFormParameters(t, assertion, nil)},
		PeerCertificate: cert,
	})
	if err == nil {
		t.Fatalf("PushAuthorizationRequest(client_assertion for cert-registered client) = nil error, want error")
	}
	if code := serverErrorCode(t, err); code != server.ErrorInvalidClient {
		t.Fatalf("error code = %q, want %q", code, server.ErrorInvalidClient)
	}
}

// TestPushAuthorizationRequestRejectsCertAuthForPrivateKeyJWTClient
// covers the opposite shape-mismatch direction: a plain client_id plus
// a peer certificate is not sufficient to authenticate a client that's
// registered for private_key_jwt.
func TestPushAuthorizationRequestRejectsCertAuthForPrivateKeyJWTClient(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	cert := selfSignedTestClientCert(t)
	_, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
		HTTP:            server.FormRequest{Parameters: certFormParameters(nil)},
		PeerCertificate: cert,
	})
	if err == nil {
		t.Fatalf("PushAuthorizationRequest(cert auth for private_key_jwt client) = nil error, want error")
	}
	if code := serverErrorCode(t, err); code != server.ErrorInvalidClient {
		t.Fatalf("error code = %q, want %q", code, server.ErrorInvalidClient)
	}
}

func TestPushAuthorizationRequestTLSClientAuthSuccess(t *testing.T) {
	h, cert := newHarnessWithClientAuthTLSSubjectDN(t)
	if _, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
		HTTP:            server.FormRequest{Parameters: certFormParameters(nil)},
		PeerCertificate: cert,
	}); err != nil {
		t.Fatalf("PushAuthorizationRequest: %v", err)
	}
}

func TestPushAuthorizationRequestTLSClientAuthRejectsMismatchedSubject(t *testing.T) {
	h, cert := newHarnessWithClientAuthTLSSubjectDN(t)
	// selfSignedTestClientCert always uses the same CommonName, so a
	// second call wouldn't actually differ in Subject — mutate a copy of
	// the registered cert's own Subject instead, to guarantee a genuine
	// mismatch while everything else about the certificate (and
	// therefore its thumbprint, irrelevant here) stays realistic.
	wrongCert := *cert
	wrongCert.Subject.CommonName = "someone-else"
	_, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
		HTTP:            server.FormRequest{Parameters: certFormParameters(nil)},
		PeerCertificate: &wrongCert,
	})
	if err == nil {
		t.Fatalf("PushAuthorizationRequest(mismatched subject) = nil error, want error")
	}
	if code := serverErrorCode(t, err); code != server.ErrorInvalidClient {
		t.Fatalf("error code = %q, want %q", code, server.ErrorInvalidClient)
	}
}

// TestPushAuthorizationRequestTLSClientAuthCaseSensitiveSubjectDN
// documents the deliberate simplification ExpectedSubjectDN's own doc
// comment describes — exact string match via crypto/x509's own
// Subject.String() serialization, not full RFC 4514 canonicalization —
// as intended, tested behavior: a registered DN differing from the
// certificate's own serialized subject only in case is rejected, not
// treated as equivalent.
func TestPushAuthorizationRequestTLSClientAuthCaseSensitiveSubjectDN(t *testing.T) {
	cert := selfSignedTestClientCert(t)
	mismatched := strings.ToUpper(cert.Subject.String())
	h := newHarnessWithClientAuthTLSSubjectDNValue(t, cert, mismatched)

	_, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
		HTTP:            server.FormRequest{Parameters: certFormParameters(nil)},
		PeerCertificate: cert,
	})
	if err == nil {
		t.Fatalf("PushAuthorizationRequest(case-mismatched subject DN) = nil error, want error")
	}
	if code := serverErrorCode(t, err); code != server.ErrorInvalidClient {
		t.Fatalf("error code = %q, want %q", code, server.ErrorInvalidClient)
	}
}

// TestPushAuthorizationRequestTLSClientAuthSAN covers all four
// SAN-based ClientAuthMethodTLSClientAuthSAN* variants (RFC 8705 §2.1's
// tls_client_auth_san_dns/_san_uri/_san_ip/_san_email) — for each, a
// certificate whose relevant SAN entry matches the registration
// succeeds, and one whose entry differs is rejected.
func TestPushAuthorizationRequestTLSClientAuthSAN(t *testing.T) {
	cases := []struct {
		name   string
		method storage.ClientAuthMethod
		value  string
		wrong  string
		mutate func(cert *x509.Certificate, value string)
	}{
		{
			name: "DNS", method: storage.ClientAuthMethodTLSClientAuthSANDNS,
			value: "client.example.com", wrong: "someone-else.example.com",
			mutate: func(cert *x509.Certificate, value string) { cert.DNSNames = []string{value} },
		},
		{
			name: "URI", method: storage.ClientAuthMethodTLSClientAuthSANURI,
			value: "https://client.example.com/id", wrong: "https://someone-else.example.com/id",
			mutate: func(cert *x509.Certificate, value string) {
				u, err := url.Parse(value)
				if err != nil {
					t.Fatalf("url.Parse(%q): %v", value, err)
				}
				cert.URIs = []*url.URL{u}
			},
		},
		{
			name: "IP", method: storage.ClientAuthMethodTLSClientAuthSANIP,
			value: "203.0.113.5", wrong: "203.0.113.6",
			mutate: func(cert *x509.Certificate, value string) { cert.IPAddresses = []net.IP{net.ParseIP(value)} },
		},
		{
			name: "Email", method: storage.ClientAuthMethodTLSClientAuthSANEmail,
			value: "client@example.com", wrong: "someone-else@example.com",
			mutate: func(cert *x509.Certificate, value string) { cert.EmailAddresses = []string{value} },
		},
	}
	for _, tc := range cases {
		t.Run(tc.name+"/Success", func(t *testing.T) {
			h, cert := newHarnessWithClientAuthTLSSAN(t, tc.method, tc.value, func(c *x509.Certificate) { tc.mutate(c, tc.value) })
			if _, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
				HTTP:            server.FormRequest{Parameters: certFormParameters(nil)},
				PeerCertificate: cert,
			}); err != nil {
				t.Fatalf("PushAuthorizationRequest: %v", err)
			}
		})
		t.Run(tc.name+"/RejectsMismatch", func(t *testing.T) {
			h, cert := newHarnessWithClientAuthTLSSAN(t, tc.method, tc.value, func(c *x509.Certificate) { tc.mutate(c, tc.wrong) })
			_, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
				HTTP:            server.FormRequest{Parameters: certFormParameters(nil)},
				PeerCertificate: cert,
			})
			if err == nil {
				t.Fatalf("PushAuthorizationRequest(mismatched %s) = nil error, want error", tc.name)
			}
			if code := serverErrorCode(t, err); code != server.ErrorInvalidClient {
				t.Fatalf("error code = %q, want %q", code, server.ErrorInvalidClient)
			}
		})
	}
}

// TestBeginBackchannelAuthenticationCertClientAuthReachesPeerCertificate
// proves BeginBackchannelAuthenticationRequest.PeerCertificate (new —
// CIBA's begin request previously carried no peer certificate field at
// all, since sender-constraining never needed one this early) actually
// reaches authenticateClient, mirroring PAR's own new field.
func TestBeginBackchannelAuthenticationCertClientAuthReachesPeerCertificate(t *testing.T) {
	now := time.Now()
	serverKey := generateKey(t)
	cert := selfSignedTestClientCert(t)

	client, err := storage.NewRegisteredClient(storage.RegisteredClientConfig{
		ID:                            testClientID,
		RedirectURIs:                  []fapi.RegisteredRedirectURI{testRedirectURI},
		ClientAuthMethod:              storage.ClientAuthMethodSelfSignedTLSClientAuth,
		ExpectedCertificateThumbprint: mtls.Thumbprint(cert),
		AllowedScopes:                 []string{"openid", "accounts"},
		BackchannelAuthenticationRequestAlgorithm: fapi.ES256,
	})
	if err != nil {
		t.Fatalf("NewRegisteredClient: %v", err)
	}

	issuer, err := fapi.ParseIssuerURL(testIssuer)
	if err != nil {
		t.Fatalf("ParseIssuerURL: %v", err)
	}
	backchannelEndpoint, err := fapi.ParseEndpointURL(testBackchannelAuthenticationEndpoint)
	if err != nil {
		t.Fatalf("ParseEndpointURL: %v", err)
	}
	endpoints := testEndpoints(t)
	endpoints.BackchannelAuthentication = backchannelEndpoint

	cfg := server.Config{
		Issuer:    issuer,
		Endpoints: endpoints,
		Profile:   server.ProfileFAPISecurity,
		Algorithms: server.AlgorithmPolicy{
			ClientAssertion:                  server.AlgorithmSet{fapi.ES256},
			RequestObject:                    server.AlgorithmSet{fapi.ES256},
			JARM:                             fapi.ES256,
			IDToken:                          fapi.ES256,
			BackchannelAuthenticationRequest: server.AlgorithmSet{fapi.ES256},
		},
		Limits: server.Limits{
			PushedRequestLifetime:                       90 * time.Second,
			MaxClientAssertionLifetime:                  time.Minute,
			MaxRequestObjectLifetime:                    time.Minute,
			InteractionLifetime:                         5 * time.Minute,
			AuthorizationCodeLifetime:                   time.Minute,
			JARMResponseLifetime:                        time.Minute,
			AccessTokenLifetime:                         5 * time.Minute,
			IDTokenLifetime:                             5 * time.Minute,
			RefreshTokenLifetime:                        5 * time.Minute,
			MaxDPoPProofAge:                             time.Minute,
			MaxClockSkew:                                5 * time.Second,
			BackchannelAuthenticationRequestLifetime:    2 * time.Minute,
			MaxBackchannelAuthenticationRequestLifetime: time.Minute,
			BackchannelAuthenticationPollInterval:       time.Millisecond,
		},
		Assurance: server.AssuranceDevelopment,
	}
	serverKeyManager := &fakeKeyManager{key: serverKey, keyID: "as-key-1"}
	deps := server.Dependencies{
		Clients:             &fakeClientRepository{clients: map[fapi.ClientID]storage.RegisteredClient{testClientID: client}},
		Transactions:        &fakeTransactionStore{},
		Grants:              &fakeGrantStore{},
		Replay:              &fakeReplayStore{},
		ClientKeys:          &fakeClientKeySource{},
		Keys:                serverKeyManager,
		AccessTokens:        server.JWTAccessTokens{Keys: serverKeyManager, Algorithm: fapi.ES256},
		Revocation:          server.NoRevocation{},
		Clock:               fixedClock{now: now},
		Random:              rand.Reader,
		Backchannel:         memstore.NewBackchannelAuthenticationStore(),
		BackchannelNotifier: server.NoBackchannelNotifications{},
	}
	srv, err := server.New(cfg, deps)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}

	// authenticateClient runs before this package ever looks at the
	// "request" parameter (see BeginBackchannelAuthentication), so no
	// signed request object is needed to reach and exercise the new
	// PeerCertificate-required check.
	action, err := srv.BeginBackchannelAuthentication(context.Background(), server.BeginBackchannelAuthenticationRequest{
		HTTP: server.FormRequest{Parameters: []server.FormParameter{
			formParam("client_id", testClientID.String()),
		}},
		// PeerCertificate intentionally omitted — proves the field is
		// actually read: without it, client authentication must fail
		// with ErrorInvalidClient, the same "certificate required"
		// rejection PAR's own PeerCertificate-omitted test exercises.
	})
	if err != nil {
		t.Fatalf("BeginBackchannelAuthentication: %v", err)
	}
	localErr, ok := action.(server.BackchannelAuthenticationLocalError)
	if !ok {
		t.Fatalf("action = %T, want server.BackchannelAuthenticationLocalError", action)
	}
	if localErr.Error.Code() != server.ErrorInvalidClient {
		t.Fatalf("Code = %q, want %q", localErr.Error.Code(), server.ErrorInvalidClient)
	}
}

// newHarnessWithClientAuthMTLSAndDPoP is unlike every other harness in
// this file: SenderConstrain stays at its default (DPoP), while
// ClientAuthMethod is still SelfSignedTLSClientAuth — the combination
// that was never exercised until this test, and the one the live OIDF
// conformance suite hit first (a client_auth_type=mtls,
// sender_constrain=dpop plan): a client authenticating via certificate
// must reach the mTLS-alias URL to present it at all, so its DPoP
// proof's own "htu" legitimately names that alias rather than the plain
// endpoint. Config.MTLSEndpoints uses deliberately different URLs from
// testEndpoints(t)'s plain ones, so a test here genuinely exercises
// verifyDPoPAtEitherEndpoint's fallback rather than happening to match
// by coincidence.
func newHarnessWithClientAuthMTLSAndDPoP(t *testing.T) (harness, *x509.Certificate, string, string) {
	t.Helper()
	now := time.Now()
	serverKey := generateKey(t)
	cert := selfSignedTestClientCert(t)

	client, err := storage.NewRegisteredClient(storage.RegisteredClientConfig{
		ID:                            testClientID,
		RedirectURIs:                  []fapi.RegisteredRedirectURI{testRedirectURI},
		ClientAuthMethod:              storage.ClientAuthMethodSelfSignedTLSClientAuth,
		ExpectedCertificateThumbprint: mtls.Thumbprint(cert),
		AllowedScopes:                 []string{"openid", "accounts", "offline_access"},
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
	mtlsPAR, err := fapi.ParseEndpointURL("https://mtls.as.example/par")
	if err != nil {
		t.Fatalf("ParseEndpointURL: %v", err)
	}

	cfg := server.Config{
		Issuer:        issuer,
		Endpoints:     testEndpoints(t),
		MTLSEndpoints: server.MTLSEndpoints{Token: mtlsToken, PushedAuthorizationRequest: mtlsPAR},
		Profile:       server.ProfileFAPISecurity,
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
		ClientKeys:   &fakeClientKeySource{},
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
	return harness{server: srv, serverKey: serverKey, now: now}, cert, mtlsToken.String(), mtlsPAR.String()
}

func dpopProofForURL(t *testing.T, key *ecdsa.PrivateKey, rawURL string, now time.Time) string {
	t.Helper()
	target, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}
	proof, err := dpop.CreateProof(dpop.ProofRequest{
		Signer: key, Algorithm: fapi.ES256, Method: "POST", URL: target, Now: now,
	})
	if err != nil {
		t.Fatalf("dpop.CreateProof: %v", err)
	}
	return proof
}

// TestPushAuthorizationRequestCertClientAuthAcceptsDPoPProofAtMTLSAlias
// and TestExchangeAuthorizationCodeCertClientAuthAcceptsDPoPProofAtMTLSAlias
// cover the gap the live OIDF conformance suite found: a client
// registered for certificate-based authentication but plain DPoP
// sender-constraining must call the mTLS-alias URL to present its
// certificate at all, so its DPoP proof's own "htu" legitimately names
// that alias rather than this server's plain endpoint. Before
// verifyDPoPAtEitherEndpoint, this server rejected such a proof
// outright with ErrURIMismatch, wrapped as "DPoP proof verification
// failed" — confirmed live, not just reasoned about (see
// ARCHITECTURE.md's conformance strategy section for the exact
// suite-side failure this reproduces).
func TestPushAuthorizationRequestCertClientAuthAcceptsDPoPProofAtMTLSAlias(t *testing.T) {
	h, cert, _, mtlsPAR := newHarnessWithClientAuthMTLSAndDPoP(t)
	dpopKey := generateKey(t)

	if _, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
		HTTP:            server.FormRequest{Parameters: certFormParameters(nil)},
		DPoPProof:       dpopProofForURL(t, dpopKey, mtlsPAR, h.now),
		PeerCertificate: cert,
	}); err != nil {
		t.Fatalf("PushAuthorizationRequest: %v", err)
	}
}

func TestExchangeAuthorizationCodeCertClientAuthAcceptsDPoPProofAtMTLSAlias(t *testing.T) {
	h, cert, mtlsToken, _ := newHarnessWithClientAuthMTLSAndDPoP(t)
	code := completeSuccessfulCertAuthorization(t, h, cert, []string{"openid", "accounts"})
	dpopKey := generateKey(t)

	result, err := h.server.ExchangeAuthorizationCode(context.Background(), server.AuthorizationCodeExchangeRequest{
		HTTP: server.FormRequest{Parameters: []server.FormParameter{
			formParam("client_id", testClientID.String()),
			formParam("grant_type", "authorization_code"),
			formParam("code", code),
			formParam("redirect_uri", testRedirectURI),
			formParam("code_verifier", testCodeVerifier),
		}},
		DPoPProof:       dpopProofForURL(t, dpopKey, mtlsToken, h.now),
		PeerCertificate: cert,
	})
	if err != nil {
		t.Fatalf("ExchangeAuthorizationCode: %v", err)
	}
	if result.TokenType != "DPoP" {
		t.Fatalf("TokenType = %q, want %q", result.TokenType, "DPoP")
	}
}
