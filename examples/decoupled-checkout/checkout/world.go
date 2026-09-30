// Package checkout builds the decoupled-checkout demo: Alder Bank
// approves payments and account access on its customer's phone, for a
// request started on another device — Harbour Coffee's till, or the
// Pocketwise budgeting app — using OpenID Connect Client-Initiated
// Backchannel Authentication (CIBA) with Rich Authorization Requests
// (RFC 9396) describing exactly what is being approved.
//
// Everything runs in one process behind a demokit.HostRouter, each party
// at its own *.localhost host.
package checkout

import (
	"context"
	"crypto"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/examples/internal/demokit"
	"github.com/idfoundry/fapigo/fapihttp"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/keys/ephemeral"
)

// Hosts, one per party.
const (
	bankHost       = "bank.localhost"       // Alder Bank's authorization server
	phoneHost      = "phone.localhost"      // Alder Bank's app, on the customer's phone
	apiHost        = "api.bank.localhost"   // Alder Bank's payments and accounts APIs
	tillHost       = "till.localhost"       // Harbour Coffee's checkout till
	pocketwiseHost = "pocketwise.localhost" // the Pocketwise budgeting app
	consoleHost    = "console.localhost"
)

// Hosts is every host name the demo serves, for its TLS certificate.
func Hosts() []string {
	return []string{consoleHost, bankHost, phoneHost, apiHost, tillHost, pocketwiseHost}
}

// customer is one of Alder Bank's customers.
type customer struct {
	loginHint string // what they type at the till or in the app
	name      string
	accounts  []bankAccount
}

type bankAccount struct {
	iban, name, balance string
}

var customers = []customer{
	{loginHint: "sam", name: "Sam Rivera", accounts: []bankAccount{
		{iban: "XA21ALDR00001234567890", name: "Everyday", balance: "1,284.17"},
		{iban: "XA07ALDR00009876543210", name: "Savings", balance: "8,020.00"},
	}},
}

func customerByHint(hint string) (customer, bool) {
	for _, c := range customers {
		if c.loginHint == hint {
			return c, true
		}
	}
	return customer{}, false
}

// payees is Alder Bank's directory of the accounts it can confirm a
// name for (like a confirmation-of-payee check): what the phone shows as
// verified, as opposed to the name a merchant put in its own request.
var payees = map[string]string{
	tillIBAN: "Harbour Coffee",
}

const tillIBAN = "XA55ALDR00004242424242"

// World is the whole running demo.
type World struct {
	port   int
	net    *demokit.Net
	router demokit.HostRouter

	bank       *bank
	phone      *phone
	api        *api
	till       *till
	pocketwise *pocketwise
}

// New builds the demo for a listener on port, reached through n.
func New(port int, n *demokit.Net) (*World, error) {
	w := &World{port: port, net: n, router: demokit.HostRouter{}}
	tillKeys, err := newClientKeys("harbour-coffee-till-1")
	if err != nil {
		return nil, err
	}
	pocketwiseKeys, err := newClientKeys("pocketwise-1")
	if err != nil {
		return nil, err
	}
	if w.bank, err = w.newBank(tillKeys, pocketwiseKeys); err != nil {
		return nil, fmt.Errorf("bank: %w", err)
	}
	w.phone = w.newPhone()
	if w.api, err = w.newAPI(); err != nil {
		return nil, fmt.Errorf("api: %w", err)
	}
	if w.till, err = w.newTill(tillKeys); err != nil {
		return nil, fmt.Errorf("till: %w", err)
	}
	w.pocketwise = w.newPocketwise(pocketwiseKeys)
	if err := w.newConsole(); err != nil {
		return nil, fmt.Errorf("console: %w", err)
	}
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

// clientKeys is a client's signing keys: one key for its client
// assertions and signed backchannel authentication requests, published
// to the bank as authJWKS, and a separate DPoP key.
type clientKeys struct {
	manager  keys.KeyManager
	authJWKS json.RawMessage
}

func newClientKeys(kid string) (clientKeys, error) {
	auth, err := ephemeral.GenerateSigner(fapi.ES256)
	if err != nil {
		return clientKeys{}, err
	}
	dpop, err := ephemeral.GenerateSigner(fapi.ES256)
	if err != nil {
		return clientKeys{}, err
	}
	manager, err := keys.NewKeyManagerFromSigners(
		map[keys.SigningPurpose]crypto.Signer{
			keys.ClientAuthentication: auth, keys.BackchannelAuthenticationRequestSigning: auth, keys.DPoPProofSigning: dpop,
		},
		map[keys.SigningPurpose]fapi.SignatureAlgorithm{
			keys.ClientAuthentication: fapi.ES256, keys.BackchannelAuthenticationRequestSigning: fapi.ES256, keys.DPoPProofSigning: fapi.ES256,
		},
		map[keys.SigningPurpose]string{keys.ClientAuthentication: kid, keys.BackchannelAuthenticationRequestSigning: kid},
	)
	if err != nil {
		return clientKeys{}, err
	}
	set, err := keys.PublicJWKS(context.Background(), []keys.SigningKeyUse{{Manager: manager, Purpose: keys.ClientAuthentication, Algorithm: fapi.ES256}}, nil)
	if err != nil {
		return clientKeys{}, err
	}
	jwks, err := json.Marshal(set)
	if err != nil {
		return clientKeys{}, err
	}
	return clientKeys{manager: manager, authJWKS: jwks}, nil
}
