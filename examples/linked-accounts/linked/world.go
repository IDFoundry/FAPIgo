// Package linked builds the linked-accounts demo: Pocketwise, a
// budgeting app, links an Alder Bank customer's accounts for 90 days.
// The customer approves once; after that Pocketwise syncs on its own,
// redeeming its refresh token for a fresh DPoP-bound access token, with
// no browser involved. The customer can withdraw Pocketwise's access at
// any time from the bank's Connected apps page, and the consent runs out
// after 90 days — a demo clock fast-forwards to show it. An attack lab
// tries to misuse the long-lived access.
//
// Everything runs in one process behind a demokit.HostRouter, each party
// at its own *.localhost host.
package linked

import (
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/idfoundry/fapigo/examples/internal/demokit"
	"github.com/idfoundry/fapigo/fapihttp"
)

// Hosts, one per party.
const (
	consoleHost    = "console.localhost"
	pocketwiseHost = "pocketwise.localhost" // Pocketwise, and the attack lab
	bankHost       = "bank.localhost"       // Alder Bank's authorization server, sign-in and Connected apps
	apiHost        = "api.bank.localhost"   // Alder Bank's account information API
)

// Hosts is every host name the demo serves, for its TLS certificate.
func Hosts() []string { return []string{consoleHost, pocketwiseHost, bankHost, apiHost} }

// consentLifetime is how long a customer's approval lasts: the bank's
// refresh token lifetime.
const consentLifetime = 90 * 24 * time.Hour

// clock is the demo's clock: real time, plus however far the console
// has fast-forwarded it. The bank, its API and Pocketwise all read it,
// so tokens, proofs and their checks stay consistent.
type clock struct {
	mu     sync.Mutex
	offset time.Duration
}

// Now implements server.Clock and client.Clock.
func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return time.Now().Add(c.offset)
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.offset += d
}

func (c *clock) daysAhead() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return int(c.offset / (24 * time.Hour))
}

// World is the whole running demo.
type World struct {
	port   int
	net    *demokit.Net
	router demokit.HostRouter
	clock  *clock

	bank       *bank
	api        *api
	pocketwise *pocketwise
}

// New builds the demo for a listener on port, reached through n.
func New(port int, n *demokit.Net) (*World, error) {
	w := &World{port: port, net: n, router: demokit.HostRouter{}, clock: &clock{}}
	apps, err := w.newApps()
	if err != nil {
		return nil, fmt.Errorf("client keys: %w", err)
	}
	if w.bank, err = w.newBank(apps); err != nil {
		return nil, fmt.Errorf("bank: %w", err)
	}
	if w.api, err = w.newAPI(); err != nil {
		return nil, fmt.Errorf("api: %w", err)
	}
	w.pocketwise = w.newPocketwise(apps)
	w.newConsole()
	return w, nil
}

// Handler serves every party.
func (w *World) Handler() http.Handler { return w.router }

// URL is the address of host's page at path.
func (w *World) URL(host, path string) string {
	if w.port == 443 {
		return "https://" + host + path
	}
	return fmt.Sprintf("https://%s:%d%s", host, w.port, path)
}

// fetcher is a hardened HTTP client for the party at host, going
// through the demo network.
func (w *World) fetcher(host string) (*fapihttp.Client, error) {
	return fapihttp.New(w.net.Client(host), fapihttp.Config{
		MaxResponseBytes: 1 << 20, RequestTimeout: 10 * time.Second, MaxRedirects: 2,
		// Every demo host is a *.localhost name, which RFC 6761 reserves
		// for loopback. https only: nothing here is served over http.
		AllowLoopbackHosts: true,
	})
}
