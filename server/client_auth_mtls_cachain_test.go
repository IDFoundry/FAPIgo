package server_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/url"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/mtls"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
)

// testCA generates a throwaway self-signed CA certificate and returns it
// alongside its private key and a *x509.CertPool containing only it —
// standing in for a deployment's real client-certificate issuing CA, the
// way selfSignedTestClientCert stands in for a real client certificate.
func testCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey, *x509.CertPool) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		t.Fatalf("generate CA serial: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "test-mtls-ca"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create CA certificate: %v", err)
	}
	ca, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA certificate: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	return ca, priv, pool
}

// caSignedTestClientCertWithSAN mirrors selfSignedTestClientCertWithSAN
// (mtls_test.go) exactly, except the resulting certificate is signed by
// caCert/caKey (testCA) rather than being self-signed — for exercising
// Dependencies.ClientCertificateTrust's TrustedClientCAs chain-trust
// check, which a self-signed certificate can never satisfy against an
// independent CA pool.
func caSignedTestClientCertWithSAN(t *testing.T, caCert *x509.Certificate, caKey *ecdsa.PrivateKey, mutate func(*x509.Certificate)) *x509.Certificate {
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
	der, err := x509.CreateCertificate(rand.Reader, template, caCert, &priv.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return cert
}

// newHarnessWithClientAuthTLSSubjectDNAndCAs mirrors
// newHarnessWithClientAuthTLSSubjectDNValue exactly, but also sets
// Dependencies.ClientCertificateTrust to server.TrustedClientCAs{Roots: roots}.
func newHarnessWithClientAuthTLSSubjectDNAndCAs(t *testing.T, cert *x509.Certificate, expectedSubjectDN string, roots *x509.CertPool) harness {
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
			MaxIDTokenClaimsBytes:      4096,
			RefreshTokenLifetime:       5 * time.Minute,
			MaxDPoPProofAge:            time.Minute,
			MaxClockSkew:               5 * time.Second,
		},
		Assurance: server.AssuranceDevelopment,
	}
	serverKeyManager := &fakeKeyManager{key: serverKey, keyID: "as-key-1"}
	deps := server.Dependencies{
		Clients:                &fakeClientRepository{clients: map[fapi.ClientID]storage.RegisteredClient{testClientID: client}},
		Transactions:           &fakeTransactionStore{},
		Grants:                 &fakeGrantStore{},
		Replay:                 &fakeReplayStore{},
		ClientKeys:             &fakeClientKeySource{},
		Keys:                   serverKeyManager,
		AccessTokens:           server.JWTAccessTokens{Keys: serverKeyManager, Algorithm: fapi.ES256},
		Revocation:             &fakeRevocationSink{},
		Clock:                  fixedClock{now: now},
		Random:                 rand.Reader,
		ClientCertificateTrust: server.TrustedClientCAs{Roots: roots},
	}

	srv, err := server.New(cfg, deps)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	return harness{server: srv, serverKey: serverKey, now: now}
}

// newHarnessWithClientAuthTLSSANAndCAs mirrors newHarnessWithClientAuthTLSSAN
// exactly, but also sets Dependencies.ClientCertificateTrust to
// server.TrustedClientCAs{Roots: roots}.
func newHarnessWithClientAuthTLSSANAndCAs(t *testing.T, method storage.ClientAuthMethod, registeredValue string, certSAN func(*x509.Certificate), roots *x509.CertPool) (harness, *x509.Certificate) {
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
			MaxIDTokenClaimsBytes:      4096,
			RefreshTokenLifetime:       5 * time.Minute,
			MaxDPoPProofAge:            time.Minute,
			MaxClockSkew:               5 * time.Second,
		},
		Assurance: server.AssuranceDevelopment,
	}
	serverKeyManager := &fakeKeyManager{key: serverKey, keyID: "as-key-1"}
	deps := server.Dependencies{
		Clients:                &fakeClientRepository{clients: map[fapi.ClientID]storage.RegisteredClient{testClientID: client}},
		Transactions:           &fakeTransactionStore{},
		Grants:                 &fakeGrantStore{},
		Replay:                 &fakeReplayStore{},
		ClientKeys:             &fakeClientKeySource{},
		Keys:                   serverKeyManager,
		AccessTokens:           server.JWTAccessTokens{Keys: serverKeyManager, Algorithm: fapi.ES256},
		Revocation:             &fakeRevocationSink{},
		Clock:                  fixedClock{now: now},
		Random:                 rand.Reader,
		ClientCertificateTrust: server.TrustedClientCAs{Roots: roots},
	}

	srv, err := server.New(srvCfg, deps)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	return harness{server: srv, serverKey: serverKey, now: now}, cert
}

// TestPushAuthorizationRequestTLSClientAuthSANRejectsUntrustedChainWhenTrustedClientCAsSet
// covers all four SAN-based ClientAuthMethodTLSClientAuthSAN* variants'
// own chain-trust check: a certificate whose SAN entry matches the
// registration but that doesn't chain to the configured TrustedClientCAs
// must still be rejected, mirroring
// TestPushAuthorizationRequestTLSClientAuthRejectsUntrustedChainWhenTrustedClientCAsSet
// for the plain subject-DN method.
func TestPushAuthorizationRequestTLSClientAuthSANRejectsUntrustedChainWhenTrustedClientCAsSet(t *testing.T) {
	cases := []struct {
		name   string
		method storage.ClientAuthMethod
		value  string
		mutate func(cert *x509.Certificate, value string)
	}{
		{
			name: "DNS", method: storage.ClientAuthMethodTLSClientAuthSANDNS, value: "client.example.com",
			mutate: func(cert *x509.Certificate, value string) { cert.DNSNames = []string{value} },
		},
		{
			name: "URI", method: storage.ClientAuthMethodTLSClientAuthSANURI, value: "https://client.example.com/id",
			mutate: func(cert *x509.Certificate, value string) {
				u, err := url.Parse(value)
				if err != nil {
					t.Fatalf("url.Parse(%q): %v", value, err)
				}
				cert.URIs = []*url.URL{u}
			},
		},
		{
			name: "IP", method: storage.ClientAuthMethodTLSClientAuthSANIP, value: "203.0.113.5",
			mutate: func(cert *x509.Certificate, value string) { cert.IPAddresses = []net.IP{net.ParseIP(value)} },
		},
		{
			name: "Email", method: storage.ClientAuthMethodTLSClientAuthSANEmail, value: "client@example.com",
			mutate: func(cert *x509.Certificate, value string) { cert.EmailAddresses = []string{value} },
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, roots := testCA(t)
			h, cert := newHarnessWithClientAuthTLSSANAndCAs(t, tc.method, tc.value, func(c *x509.Certificate) { tc.mutate(c, tc.value) }, roots)
			_, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
				HTTP:            server.FormRequest{Parameters: certFormParameters(nil)},
				PeerCertificate: cert,
			})
			if err == nil {
				t.Fatalf("PushAuthorizationRequest(untrusted chain, %s) = nil error, want error", tc.name)
			}
			if code := serverErrorCode(t, err); code != server.ErrorInvalidClient {
				t.Fatalf("error code = %q, want %q", code, server.ErrorInvalidClient)
			}
		})
	}
}

func TestPushAuthorizationRequestTLSClientAuthRejectsUntrustedChainWhenTrustedClientCAsSet(t *testing.T) {
	_, _, roots := testCA(t)
	// Self-signed, not issued by the CA in roots — subject matches, but
	// the chain doesn't, so this must be rejected even though the exact
	// same certificate would pass with NoClientCertificateChainTrust{} (see
	// TestPushAuthorizationRequestTLSClientAuthSuccess).
	cert := selfSignedTestClientCert(t)
	h := newHarnessWithClientAuthTLSSubjectDNAndCAs(t, cert, cert.Subject.String(), roots)

	_, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
		HTTP:            server.FormRequest{Parameters: certFormParameters(nil)},
		PeerCertificate: cert,
	})
	if err == nil {
		t.Fatal("PushAuthorizationRequest(untrusted chain) = nil error, want error")
	}
	if code := serverErrorCode(t, err); code != server.ErrorInvalidClient {
		t.Fatalf("error code = %q, want %q", code, server.ErrorInvalidClient)
	}
}

func TestPushAuthorizationRequestTLSClientAuthAcceptsTrustedChainWhenTrustedClientCAsSet(t *testing.T) {
	caCert, caKey, roots := testCA(t)
	cert := caSignedTestClientCertWithSAN(t, caCert, caKey, func(*x509.Certificate) {})
	h := newHarnessWithClientAuthTLSSubjectDNAndCAs(t, cert, cert.Subject.String(), roots)

	if _, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
		HTTP:            server.FormRequest{Parameters: certFormParameters(nil)},
		PeerCertificate: cert,
	}); err != nil {
		t.Fatalf("PushAuthorizationRequest: %v", err)
	}
}

// TestPushAuthorizationRequestSelfSignedTLSClientAuthUnaffectedByTrustedClientCAs
// confirms ClientAuthMethodSelfSignedTLSClientAuth's thumbprint match
// needs no chain trust: it must still succeed under a certificate that
// cannot possibly verify against an unrelated TrustedClientCAs pool, per
// TrustedClientCAs' own doc comment.
func TestPushAuthorizationRequestSelfSignedTLSClientAuthUnaffectedByTrustedClientCAs(t *testing.T) {
	_, _, roots := testCA(t)
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
			MaxIDTokenClaimsBytes:      4096,
			RefreshTokenLifetime:       5 * time.Minute,
			MaxDPoPProofAge:            time.Minute,
			MaxClockSkew:               5 * time.Second,
		},
		Assurance: server.AssuranceDevelopment,
	}
	serverKeyManager := &fakeKeyManager{key: serverKey, keyID: "as-key-1"}
	deps := server.Dependencies{
		Clients:                &fakeClientRepository{clients: map[fapi.ClientID]storage.RegisteredClient{testClientID: client}},
		Transactions:           &fakeTransactionStore{},
		Grants:                 &fakeGrantStore{},
		Replay:                 &fakeReplayStore{},
		ClientKeys:             &fakeClientKeySource{},
		Keys:                   serverKeyManager,
		AccessTokens:           server.JWTAccessTokens{Keys: serverKeyManager, Algorithm: fapi.ES256},
		Revocation:             &fakeRevocationSink{},
		Clock:                  fixedClock{now: now},
		Random:                 rand.Reader,
		ClientCertificateTrust: server.TrustedClientCAs{Roots: roots},
	}
	srv, err := server.New(cfg, deps)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	h := harness{server: srv, serverKey: serverKey, now: now}

	if _, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
		HTTP:            server.FormRequest{Parameters: certFormParameters(nil)},
		PeerCertificate: cert,
	}); err != nil {
		t.Fatalf("PushAuthorizationRequest: %v", err)
	}
}
