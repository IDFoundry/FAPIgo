package server_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/idfoundry/fapigo/fapihttp"
	"github.com/idfoundry/fapigo/server"
)

// federationNetwork is where a test federation's servers listen, and the
// fetcher a server under test reaches them with.
type federationNetwork interface {
	// serve starts h on a TLS test server, closed when t ends.
	serve(t *testing.T, h http.Handler) *httptest.Server
	// fetcher is a federation fetcher trusting servers' certificates.
	fetcher(t *testing.T, servers []*httptest.Server) *fapihttp.Client
}

// loopbackFederation serves on loopback, for a fetcher with fapihttp's
// loopback exception, which only development assurance accepts.
type loopbackFederation struct{}

func (loopbackFederation) serve(t *testing.T, h http.Handler) *httptest.Server {
	t.Helper()
	s := httptest.NewTLSServer(h)
	t.Cleanup(s.Close)
	return s
}

func (loopbackFederation) fetcher(t *testing.T, servers []*httptest.Server) *fapihttp.Client {
	t.Helper()
	pool := x509.NewCertPool()
	for _, s := range servers {
		pool.AddCert(s.Certificate())
	}
	fetcher, err := fapihttp.New(&http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}, fapihttp.Config{
		MaxResponseBytes: 1 << 16, RequestTimeout: 5 * time.Second, MaxRedirects: 1,
		AllowLoopbackHTTP: true,
	})
	if err != nil {
		t.Fatalf("fapihttp.New: %v", err)
	}
	return fetcher
}

// privateFederation serves on ip, a private address of this machine, with
// cert, a certificate for that address, for a fetcher hardened for
// production: its AllowedPrivateHosts names ip alone, and nothing in it
// grants loopback.
type privateFederation struct {
	ip   string
	cert tls.Certificate
}

// newPrivateFederation is a privateFederation on a private IPv4 address
// of this machine, skipping t where there is none.
func newPrivateFederation(t *testing.T) privateFederation {
	t.Helper()
	ip := privateIPv4(t)
	key := generateKey(t)
	leaf := selfSignedTestClientCertForKey(t, key, func(c *x509.Certificate) {
		c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		c.IPAddresses = []net.IP{ip}
	})
	return privateFederation{ip: ip.String(), cert: tls.Certificate{Certificate: [][]byte{leaf.Raw}, PrivateKey: key, Leaf: leaf}}
}

// privateIPv4 is a private (RFC 1918) IPv4 address of a network
// interface of this machine that is up, or t is skipped where there is
// none.
func privateIPv4(t *testing.T) net.IP {
	t.Helper()
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Skipf("listing network interfaces: %v", err)
	}
	for _, iface := range interfaces {
		if ip := upPrivateIPv4(iface); ip != nil {
			return ip
		}
	}
	t.Skip("no private IPv4 address for a fetcher hardened for production to reach")
	return nil
}

// upPrivateIPv4 is iface's first private IPv4 address, or nil if it has
// none or isn't up.
func upPrivateIPv4(iface net.Interface) net.IP {
	if iface.Flags&net.FlagUp == 0 {
		return nil
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return nil
	}
	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok && ipNet.IP.To4() != nil && ipNet.IP.IsPrivate() {
			return ipNet.IP.To4()
		}
	}
	return nil
}

func (p privateFederation) serve(t *testing.T, h http.Handler) *httptest.Server {
	t.Helper()
	l, err := net.Listen("tcp", net.JoinHostPort(p.ip, "0"))
	if err != nil {
		t.Fatalf("listen on %s: %v", p.ip, err)
	}
	s := httptest.NewUnstartedServer(h)
	_ = s.Listener.Close() // the loopback listener NewUnstartedServer opened
	s.Listener = l
	s.TLS = &tls.Config{Certificates: []tls.Certificate{p.cert}, MinVersion: tls.VersionTLS12}
	s.StartTLS()
	t.Cleanup(s.Close)
	return s
}

func (p privateFederation) fetcher(t *testing.T, _ []*httptest.Server) *fapihttp.Client {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(p.cert.Leaf)
	hc, err := fapihttp.NewClient(fapihttp.TransportConfig{
		DialTimeout: 5 * time.Second, TLSHandshakeTimeout: 5 * time.Second,
		AllowedPrivateHosts: []string{p.ip}, RootCAs: pool,
	})
	if err != nil {
		t.Fatalf("fapihttp.NewClient: %v", err)
	}
	fetcher, err := fapihttp.New(hc, fapihttp.Config{
		MaxResponseBytes: 1 << 16, RequestTimeout: 5 * time.Second, MaxRedirects: 1,
		AllowedPrivateHosts: []string{p.ip},
	})
	if err != nil {
		t.Fatalf("fapihttp.New: %v", err)
	}
	if !fetcher.HardenedForProduction() {
		t.Fatal("the private federation's fetcher isn't hardened for production")
	}
	return fetcher
}

// newDevelopmentGrantsServer is newAutomaticRegistrationTestServer, under
// AssuranceDevelopment, with the operator enabling client_credentials and
// CIBA for every automatically registered client (enableFederatedGrants).
func newDevelopmentGrantsServer(t *testing.T, f *automaticRegistrationFixture) *server.Server {
	t.Helper()
	return newAutomaticRegistrationTestServer(t, f, enableFederatedGrants(t))
}

// newProductionGrantsServer is a server under AssuranceProduction
// registering f's RP automatically, with the operator enabling
// client_credentials and CIBA for every automatically registered client.
// f's fetcher must be hardened for production (privateFederation).
func newProductionGrantsServer(t *testing.T, f *automaticRegistrationFixture) *server.Server {
	t.Helper()
	cfg, deps := cibaConfigAndDeps(t, server.AssuranceProduction, server.NoBackchannelNotifications{})
	cfg.ClientCredentialsGrant = true
	cfg.AutomaticRegistration = validAutomaticRegistrationServerConfig(f)
	cfg.AutomaticRegistration.AllowsClientCredentialsGrant = true
	cfg.AutomaticRegistration.AllowsCIBA = true
	deps.FederationHTTP, deps.Clock = f.fetcher, fixedClock{now: f.now}
	srv, err := server.New(cfg, deps)
	if err != nil {
		t.Fatalf("server.New(production): %v", err)
	}
	return srv
}

// TestAutomaticRegistrationOmittedGrantTypesMeansCodeFlowOnly: a Relying
// Party whose resolved metadata leaves grant_types out is registered for
// the authorization code flow alone (OpenID Connect Dynamic Client
// Registration 1.0 §2, RFC 7591 §2). Though the operator enables
// client_credentials and CIBA for every automatically registered client,
// no superior's policy bounds grant_types, and the RP publishes CIBA's
// signing algorithm and delivery mode, both grants are refused with
// unauthorized_client, while its pushed authorization request is
// accepted. A Relying Party listing both grants gets them. Each runs over
// a Trust Anchor -> Intermediate -> RP chain at both assurance levels:
// production resolves the chain through a fetcher hardened for
// production, so that federation listens on a private address of this
// machine, and its subtest is skipped where there is none.
func TestAutomaticRegistrationOmittedGrantTypesMeansCodeFlowOnly(t *testing.T) {
	listsBoth := map[string]any{"grant_types": []string{"authorization_code", "client_credentials", server.CIBAGrantType}}
	for _, level := range []struct {
		name      string
		network   func(*testing.T) federationNetwork
		newServer func(*testing.T, *automaticRegistrationFixture) *server.Server
	}{
		{"development", func(*testing.T) federationNetwork { return loopbackFederation{} }, newDevelopmentGrantsServer},
		{"production", func(t *testing.T) federationNetwork { return newPrivateFederation(t) }, newProductionGrantsServer},
	} {
		t.Run(level.name, func(t *testing.T) {
			network := level.network(t)
			for _, tc := range []struct {
				name        string
				extra       map[string]any
				wantGranted bool
			}{
				{name: "grant_types left out"},
				{name: "grant_types listing both", extra: listsBoth, wantGranted: true},
			} {
				t.Run(tc.name, func(t *testing.T) {
					f := setupBranchFixtureOn(t, network, "", "", tc.extra)
					srv := level.newServer(t, f)
					checkFederatedGrants(t, srv, f, tc.wantGranted)
					checkFederatedCodeFlow(t, srv, f)
				})
			}
		})
	}
}

// checkFederatedCodeFlow fails t unless srv accepts a pushed
// authorization request from f's RP: an automatically registered RP keeps
// the authorization code flow, with grant_types or without.
func checkFederatedCodeFlow(t *testing.T, srv *server.Server, f *automaticRegistrationFixture) {
	t.Helper()
	if _, err := srv.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
		HTTP: server.FormRequest{Parameters: plainFormParameters(t, federatedAssertion(t, f), nil)},
	}); err != nil {
		t.Errorf("PushAuthorizationRequest = %v, want the authorization code flow registered", err)
	}
}
