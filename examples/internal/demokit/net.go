// Package demokit is the local network every FAPIgo example demo runs
// on: one HTTPS listener for all of a demo's entities, told apart by
// host name, an HTTP client per entity that reaches the others through
// that same listener, and a Chrome window that accepts the demo's
// certificate.
//
// Host names are subdomains of "localhost" (bank.localhost, ...):
// browsers resolve those to the loopback address on their own (RFC 6761),
// and the clients built here dial the listener directly, so nothing needs
// adding to /etc/hosts. The TLS certificate is issued by a demo
// certificate authority that can only vouch for *.localhost, both kept in
// a state directory so a browser can be told to trust the CA once.
package demokit

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Net is the demo's shared network: one TLS certificate covering every
// entity host, and the address every client dials.
type Net struct {
	addr    string
	caPath  string
	caPool  *x509.CertPool
	serving tls.Certificate
	log     *FetchLog
}

// New builds the demo network for a listener at addr (host:port, the
// address clients dial), serving a certificate for hosts. The demo CA
// that issues it is named caName, which is what a browser's trust store
// shows. stateDir keeps the CA and that certificate across runs, so a
// browser told to trust the CA (or to accept the certificate) once stays
// that way; an empty stateDir issues both afresh and keeps nothing.
func New(addr string, hosts []string, stateDir, caName string) (*Net, error) {
	certs, err := loadOrIssue(stateDir, caName, hosts, time.Now())
	if err != nil {
		return nil, fmt.Errorf("demo certificates: %w", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(certs.ca)
	n := &Net{addr: addr, caPool: pool, serving: certs.serving, log: &FetchLog{}}
	if stateDir != "" {
		n.caPath = filepath.Join(stateDir, caCertFile)
	}
	return n, nil
}

// CAPath is where the demo CA certificate is kept, for a browser to
// trust; "" when New was given no state directory.
func (n *Net) CAPath() string { return n.caPath }

// ServingSPKIHash identifies the serving certificate's key for Chrome's
// --ignore-certificate-errors-spki-list, which accepts that one
// certificate without trusting the CA.
func (n *Net) ServingSPKIHash() string { return spkiHash(n.serving.Leaf) }

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
