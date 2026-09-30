// Package payment builds the payment-consent demo: Northgate Outfitters,
// a web shop, takes payment by bank from an Alder Bank customer through
// the FAPI 2.0 Message Signing redirect flow — a signed request object
// pushed to the bank (PAR), a consent screen showing the payment from its
// Rich Authorization Request (RFC 9396), a signed authorization response
// (JARM) and a DPoP-bound access token — with an attack lab that tries to
// break each of those protections.
//
// Everything runs in one process behind a demokit.HostRouter, each party
// at its own *.localhost host.
package payment

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
	consoleHost = "console.localhost"
	shopHost    = "shop.localhost"     // Northgate Outfitters
	bankHost    = "bank.localhost"     // Alder Bank's authorization server and sign-in
	apiHost     = "api.bank.localhost" // Alder Bank's payments API
)

// Hosts is every host name the demo serves, for its TLS certificate.
func Hosts() []string { return []string{consoleHost, shopHost, bankHost, apiHost} }

// customer is one of Alder Bank's customers.
type customer struct {
	username, pin, name string
	account             bankAccount
}

type bankAccount struct{ iban, name string }

var customers = []customer{
	{username: "sam", pin: "2468", name: "Sam Rivera", account: bankAccount{iban: "XA21ALDR00001234567890", name: "Everyday"}},
	// The attack lab's attacker: a customer of the same bank, with a
	// payment of their own to approve.
	{username: "alex", pin: "1357", name: "Alex Moreau", account: bankAccount{iban: "XA64ALDR00001111222233", name: "Current"}},
}

func customerByName(username string) (customer, bool) {
	for _, c := range customers {
		if c.username == username {
			return c, true
		}
	}
	return customer{}, false
}

func (a bankAccount) describe() string { return a.name + " ····" + a.iban[len(a.iban)-4:] }

// shopIBAN is Northgate Outfitters' account at Alder Bank.
const shopIBAN = "XA37ALDR00007777888899"

// payees is Alder Bank's directory of the accounts it can confirm a
// name for: what its consent screen shows as verified, as opposed to the
// name a shop put in its own request.
var payees = map[string]string{shopIBAN: "Northgate Outfitters"}

// World is the whole running demo.
type World struct {
	port   int
	net    *demokit.Net
	router demokit.HostRouter

	bank *bank
	api  *api
	shop *shop
}

// New builds the demo for a listener on port, reached through n.
func New(port int, n *demokit.Net) (*World, error) {
	w := &World{port: port, net: n, router: demokit.HostRouter{}}
	shopKeys, err := newClientKeys("northgate-1")
	if err != nil {
		return nil, err
	}
	if w.bank, err = w.newBank(shopKeys); err != nil {
		return nil, fmt.Errorf("bank: %w", err)
	}
	if w.api, err = w.newAPI(); err != nil {
		return nil, fmt.Errorf("api: %w", err)
	}
	if w.shop, err = w.newShop(shopKeys); err != nil {
		return nil, fmt.Errorf("shop: %w", err)
	}
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

// clientKeys is the shop's signing keys: one key for its client
// assertions and request objects, published to the bank as authJWKS, and
// a separate DPoP key.
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
			keys.ClientAuthentication: auth, keys.RequestObjectSigning: auth, keys.DPoPProofSigning: dpop,
		},
		map[keys.SigningPurpose]fapi.SignatureAlgorithm{
			keys.ClientAuthentication: fapi.ES256, keys.RequestObjectSigning: fapi.ES256, keys.DPoPProofSigning: fapi.ES256,
		},
		map[keys.SigningPurpose]string{keys.ClientAuthentication: kid, keys.RequestObjectSigning: kid},
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
