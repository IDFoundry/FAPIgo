package fapihttp_test

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/url"
	"slices"
	"testing"

	"github.com/idfoundry/fapigo/fapihttp"
)

func hardenedClient(t *testing.T, cfg fapihttp.TransportConfig) *http.Client {
	t.Helper()
	c, err := fapihttp.NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c
}

// TestHardeningOfRecognisesNewClient: NewClient's client, and a copy of
// it with its own Timeout and CheckRedirect, are recognised, with the
// exceptions they were built with; adding a client certificate
// afterwards doesn't change that.
func TestHardeningOfRecognisesNewClient(t *testing.T) {
	cfg := fapihttp.RecommendedTransportConfig()
	cfg.AllowedPrivateHosts = []string{"as.internal"}
	c := hardenedClient(t, cfg)

	h, ok := fapihttp.HardeningOf(c)
	if !ok {
		t.Fatal("HardeningOf(NewClient's client) = false, want true")
	}
	if h.AllowsLoopback() {
		t.Error("AllowsLoopback = true, want false")
	}
	if got := h.AllowedPrivateHosts(); !slices.Equal(got, []string{"as.internal"}) {
		t.Errorf("AllowedPrivateHosts = %v, want [as.internal]", got)
	}
	h.AllowedPrivateHosts()[0] = "changed"
	if got := h.AllowedPrivateHosts(); got[0] != "as.internal" {
		t.Errorf("AllowedPrivateHosts returned shared storage: %v", got)
	}

	copied := *c
	copied.Timeout = 5
	copied.CheckRedirect = nil
	if _, ok := fapihttp.HardeningOf(&copied); !ok {
		t.Error("HardeningOf(a copy of NewClient's client) = false, want true")
	}

	c.Transport.(*http.Transport).TLSClientConfig.Certificates = []tls.Certificate{{}}
	if _, ok := fapihttp.HardeningOf(c); !ok {
		t.Error("HardeningOf after adding a client certificate = false, want true")
	}
}

// TestHardeningOfReportsLoopback: a transport built with a loopback
// exception says so.
func TestHardeningOfReportsLoopback(t *testing.T) {
	for name, set := range map[string]func(*fapihttp.TransportConfig){
		"hosts": func(c *fapihttp.TransportConfig) { c.AllowLoopbackHosts = true },
		"http":  func(c *fapihttp.TransportConfig) { c.AllowLoopbackHTTP = true },
		"named": func(c *fapihttp.TransportConfig) { c.AllowedLoopbackHosts = []string{"localhost"} },
	} {
		t.Run(name, func(t *testing.T) {
			cfg := fapihttp.RecommendedTransportConfig()
			set(&cfg)
			h, ok := fapihttp.HardeningOf(hardenedClient(t, cfg))
			if !ok || !h.AllowsLoopback() {
				t.Errorf("HardeningOf = %v, %v; want recognised, allowing loopback", h.AllowsLoopback(), ok)
			}
		})
	}
}

// TestHardeningOfRefusesOtherClients: clients NewClient didn't build,
// and its transport cloned or wrapped, aren't recognised.
func TestHardeningOfRefusesOtherClients(t *testing.T) {
	c := hardenedClient(t, fapihttp.RecommendedTransportConfig())
	for name, other := range map[string]*http.Client{
		"nil":             nil,
		"default client":  http.DefaultClient,
		"default":         {Transport: http.DefaultTransport},
		"plain transport": {Transport: &http.Transport{}},
		"cloned":          {Transport: c.Transport.(*http.Transport).Clone()},
		"wrapped":         {Transport: wrapper{c.Transport}},
	} {
		if _, ok := fapihttp.HardeningOf(other); ok {
			t.Errorf("%s: HardeningOf = true, want false", name)
		}
	}
	if _, ok := fapihttp.HardeningOfTransport(nil); ok {
		t.Error("HardeningOfTransport(nil) = true, want false")
	}
}

type wrapper struct{ http.RoundTripper }

// TestHardeningOfRefusesTamperedTransports: once anything that decides
// where the transport connects, or how it checks the server, has been
// changed, it isn't recognised any more.
func TestHardeningOfRefusesTamperedTransports(t *testing.T) {
	other := hardenedClient(t, fapihttp.RecommendedTransportConfig())
	otherDialer := other.Transport.(*http.Transport).DialContext
	dialer := (&net.Dialer{}).DialContext
	for name, tamper := range map[string]func(*http.Transport){
		"proxy":           func(t *http.Transport) { t.Proxy = func(*http.Request) (*url.URL, error) { return nil, nil } },
		"dial context":    func(t *http.Transport) { t.DialContext = dialer },
		"no dial context": func(t *http.Transport) { t.DialContext = nil },
		"dial":            func(t *http.Transport) { t.Dial = func(string, string) (net.Conn, error) { return nil, nil } }, //nolint:staticcheck // the deprecated field is still settable
		"dial tls": func(t *http.Transport) {
			t.DialTLS = func(string, string) (net.Conn, error) { return nil, nil } //nolint:staticcheck // the deprecated field is still settable
		},
		"dial tls context": func(t *http.Transport) {
			t.DialTLSContext = func(context.Context, string, string) (net.Conn, error) { return nil, nil }
		},
		"no tls config":         func(t *http.Transport) { t.TLSClientConfig = nil },
		"skip verify":           func(t *http.Transport) { t.TLSClientConfig.InsecureSkipVerify = true },
		"tls 1.0 minimum":       func(t *http.Transport) { t.TLSClientConfig.MinVersion = tls.VersionTLS10 },
		"tls 1.1 maximum":       func(t *http.Transport) { t.TLSClientConfig.MaxVersion = tls.VersionTLS11 },
		"replaced tls config":   func(t *http.Transport) { t.TLSClientConfig = &tls.Config{} },
		"another hardened dial": func(t *http.Transport) { t.DialContext = otherDialer },
	} {
		t.Run(name, func(t *testing.T) {
			c := hardenedClient(t, fapihttp.RecommendedTransportConfig())
			tamper(c.Transport.(*http.Transport))
			_, ok := fapihttp.HardeningOf(c)
			// Another NewClient transport's dialer validates addresses
			// just the same, and the check can't tell them apart.
			if want := name == "another hardened dial"; ok != want {
				t.Errorf("HardeningOf = %v, want %v", ok, want)
			}
		})
	}
}

// TestNewClientPresentsCertificates: TransportConfig's client
// certificate fields reach the transport's TLS configuration.
func TestNewClientPresentsCertificates(t *testing.T) {
	cert := tls.Certificate{Certificate: [][]byte{{1}}}
	get := func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &cert, nil }
	cfg := fapihttp.RecommendedTransportConfig()
	cfg.Certificates = []tls.Certificate{cert}
	cfg.GetClientCertificate = get
	tlsCfg := hardenedClient(t, cfg).Transport.(*http.Transport).TLSClientConfig
	if len(tlsCfg.Certificates) != 1 || tlsCfg.GetClientCertificate == nil {
		t.Errorf("TLSClientConfig = %d certificates, GetClientCertificate set %v; want 1, true", len(tlsCfg.Certificates), tlsCfg.GetClientCertificate != nil)
	}
}
