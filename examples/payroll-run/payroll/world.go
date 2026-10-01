// Package payroll builds the payroll-run demo: Ledgerline, a payroll
// provider, pays its customer Harbour Coffee's staff from Harbour
// Coffee's account at Alder Bank, server to server. There is no end user
// and no browser in the flow: Ledgerline authenticates to the bank with a
// TLS client certificate the bank's CA issued (RFC 8705 §2,
// tls_client_auth), receives an access token bound to that certificate
// (RFC 8705 §3) through the client credentials grant, and the payroll
// batch it may submit is a Rich Authorization Request (RFC 9396) the
// bank checks against Harbour Coffee's standing mandate. An attack lab
// tries each way around that, and a rotation panel replaces Ledgerline's
// certificate.
//
// Everything runs in one process behind a demokit.HostRouter, each party
// at its own *.localhost host.
package payroll

import (
	"fmt"
	"net/http"
	"time"

	"github.com/idfoundry/fapigo/examples/internal/demokit"
	"github.com/idfoundry/fapigo/fapihttp"
)

// Hosts, one per party.
const (
	consoleHost    = "console.localhost"
	ledgerlineHost = "ledgerline.localhost" // Ledgerline's dashboard, and the attack lab
	bankHost       = "bank.localhost"       // Alder Bank's authorization server
	mtlsHost       = "mtls.bank.localhost"  // its token endpoint, for clients with a certificate
	apiHost        = "api.bank.localhost"   // Alder Bank's payroll API
)

// Hosts is every host name the demo serves, for its TLS certificate.
func Hosts() []string { return []string{consoleHost, ledgerlineHost, bankHost, mtlsHost, apiHost} }

// ClientCertificateHosts are the hosts that ask for a TLS client
// certificate (demokit.Net.ServerTLS). A browser never visits them, so
// it never shows a certificate picker.
func ClientCertificateHosts() []string { return []string{mtlsHost, apiHost} }

// World is the whole running demo.
type World struct {
	port   int
	net    *demokit.Net
	router demokit.HostRouter

	// Alder Bank's client certificate PKI: the root, the issuing CA in
	// use, and the retired issuing CA the root revoked.
	rootCA, clientCA, retiredCA *pki

	bank       *bank
	api        *api
	ledgerline *ledgerline
}

// New builds the demo for a listener on port, reached through n.
func New(port int, n *demokit.Net) (*World, error) {
	w := &World{port: port, net: n, router: demokit.HostRouter{}}
	var err error
	if err = w.newBankPKI(time.Now()); err != nil {
		return nil, fmt.Errorf("bank PKI: %w", err)
	}
	certs, err := w.issueCertificates(time.Now())
	if err != nil {
		return nil, fmt.Errorf("certificates: %w", err)
	}
	if w.bank, err = w.newBank(certs); err != nil {
		return nil, fmt.Errorf("bank: %w", err)
	}
	if w.api, err = w.newAPI(); err != nil {
		return nil, fmt.Errorf("api: %w", err)
	}
	w.ledgerline = w.newLedgerline(certs)
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
