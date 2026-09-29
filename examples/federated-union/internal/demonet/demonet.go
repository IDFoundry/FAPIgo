// Package demonet runs every entity of the demo federation on one local
// HTTPS listener, telling them apart by host name, and gives each entity
// an HTTP client that reaches the others through that same listener.
//
// Host names are subdomains of "localhost" (id.eastmark.localhost, ...):
// browsers resolve those to the loopback address on their own (RFC 6761),
// and the clients built here dial the listener directly, so nothing needs
// adding to /etc/hosts. The TLS certificate is issued at startup by a
// throwaway certificate authority, written out so a browser can be told
// to trust it.
package demonet

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Net is the demo's shared network: one TLS certificate covering every
// entity host, and the address every client dials.
type Net struct {
	addr    string
	caPEM   []byte
	caPool  *x509.CertPool
	serving tls.Certificate
	log     *FetchLog
}

// New issues a certificate for hosts, signed by a fresh demo CA, for a
// listener at addr (host:port, the address clients dial).
func New(addr string, hosts []string) (*Net, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Meridian Union demo CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(30 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, err
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: hosts[0]},
		DNSNames:     hosts,
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(30 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}

	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	return &Net{
		addr:    addr,
		caPEM:   pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
		caPool:  pool,
		serving: tls.Certificate{Certificate: [][]byte{leafDER}, PrivateKey: leafKey},
		log:     &FetchLog{},
	}, nil
}

// CAPEM is the demo CA certificate, PEM-encoded.
func (n *Net) CAPEM() []byte { return n.caPEM }

// ServerTLS is the listener's TLS configuration.
func (n *Net) ServerTLS() *tls.Config {
	return &tls.Config{Certificates: []tls.Certificate{n.serving}, MinVersion: tls.VersionTLS12}
}

// Log is the record of every request the entities have made to each
// other.
func (n *Net) Log() *FetchLog { return n.log }

// Client is an HTTP client for the entity at host: it trusts the demo CA,
// dials the demo listener whatever host a URL names, never follows
// redirects (fapihttp handles those itself), and records each request in
// Log under from.
func (n *Net) Client(from string) *http.Client {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: n.caPool, MinVersion: tls.VersionTLS12},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, n.addr)
		},
	}
	return &http.Client{
		Transport: &loggingTransport{from: from, next: transport, log: n.log},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: 10 * time.Second,
	}
}

// Browser is an HTTP client for driving the demo's pages in a test: like
// Client, but following redirects and keeping cookies with jar.
func (n *Net) Browser(jar http.CookieJar) *http.Client {
	c := n.Client("browser")
	c.CheckRedirect = nil
	c.Jar = jar
	return c
}

// HostRouter dispatches each request to the handler registered for its
// Host header, ignoring the port.
type HostRouter map[string]http.Handler

func (h HostRouter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	if i := strings.LastIndexByte(host, ':'); i >= 0 {
		host = host[:i]
	}
	handler, ok := h[strings.ToLower(host)]
	if !ok {
		http.Error(w, fmt.Sprintf("no demo entity at %q", host), http.StatusNotFound)
		return
	}
	handler.ServeHTTP(w, r)
}

// FetchEntry is one request an entity made to another.
type FetchEntry struct {
	Time   time.Time
	From   string
	Method string
	URL    string
	Status int
	Err    string
}

// FetchLog keeps the most recent requests between entities.
type FetchLog struct {
	mu      sync.Mutex
	entries []FetchEntry
}

const maxFetchEntries = 300

func (l *FetchLog) add(e FetchEntry) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.entries = append(l.entries, e)
	if len(l.entries) > maxFetchEntries {
		l.entries = l.entries[len(l.entries)-maxFetchEntries:]
	}
}

// Recent returns up to n entries, newest first.
func (l *FetchLog) Recent(n int) []FetchEntry {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]FetchEntry, 0, n)
	for i := len(l.entries) - 1; i >= 0 && len(out) < n; i-- {
		out = append(out, l.entries[i])
	}
	return out
}

type loggingTransport struct {
	from string
	next http.RoundTripper
	log  *FetchLog
}

func (t *loggingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	entry := FetchEntry{Time: time.Now(), From: t.from, Method: r.Method, URL: r.URL.String()}
	res, err := t.next.RoundTrip(r)
	if err != nil {
		entry.Err = err.Error()
	} else {
		entry.Status = res.StatusCode
	}
	if t.from != "browser" {
		t.log.add(entry)
	}
	return res, err
}
