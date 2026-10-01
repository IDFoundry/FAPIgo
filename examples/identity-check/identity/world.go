// Package identity builds the identity-check demo: Fernway, a fintech
// opening a savings account, verifies who its new customer is by having
// them sign in at their bank, Alder Bank, acting as an OpenID Provider.
// Fernway asks for exactly the identity claims it needs (OIDC Core §5.5
// "claims"), and for a strong, recent sign-in ("acr_values", "max_age").
// The customer sees each claim with the bank's value and can withhold
// any of them. The ID token and the UserInfo response come back signed
// by the bank and encrypted to Fernway. A second relying party,
// Brightline Rentals, asks for less. An attack lab tries to get around
// each protection.
//
// Everything runs in one process behind a demokit.HostRouter, each party
// at its own *.localhost host.
package identity

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/idfoundry/fapigo/examples/internal/demokit"
	"github.com/idfoundry/fapigo/fapihttp"
)

// Hosts, one per party.
const (
	consoleHost    = "console.localhost"
	fernwayHost    = "fernway.localhost"    // Fernway, and the attack lab
	brightlineHost = "brightline.localhost" // Brightline Rentals
	bankHost       = "bank.localhost"       // Alder Bank's OpenID Provider
)

// Hosts is every host name the demo serves, for its TLS certificate.
func Hosts() []string { return []string{consoleHost, fernwayHost, brightlineHost, bankHost} }

// customer is one of Alder Bank's customers, with the identity the bank
// verified when they opened their account.
type customer struct {
	username, pin string
	claims        map[string]any // OIDC Core §5.1 standard claims
}

var customers = []customer{
	{username: "sam", pin: "2468", claims: map[string]any{
		"given_name": "Sam", "family_name": "Rivera", "birthdate": "1991-04-12",
		"email": "sam.rivera@example.com", "email_verified": true, "phone_number": "+44 7700 900461",
		"address": map[string]string{"street_address": "14 Quay Street", "locality": "Northport", "postal_code": "NP1 4QS", "country": "XA"},
	}},
	// The attack lab's other customer, whose ID token and UserInfo
	// response it tries to pass off as Sam's.
	{username: "alex", pin: "1357", claims: map[string]any{
		"given_name": "Alex", "family_name": "Moreau", "birthdate": "1988-09-30",
		"email": "alex.moreau@example.com", "email_verified": true, "phone_number": "+44 7700 900782",
		"address": map[string]string{"street_address": "3 Mill Lane", "locality": "Southport", "postal_code": "SP7 2AB", "country": "XA"},
	}},
}

func customerByName(username string) (customer, bool) {
	for _, c := range customers {
		if c.username == username {
			return c, true
		}
	}
	return customer{}, false
}

// claimValue is c's claim name, JSON-encoded, and whether c has one.
func (c customer) claimValue(name string) (json.RawMessage, bool) {
	v, ok := c.claims[name]
	if !ok {
		return nil, false
	}
	raw, err := json.Marshal(v)
	return raw, err == nil
}

// World is the whole running demo.
type World struct {
	port   int
	net    *demokit.Net
	router demokit.HostRouter

	bank                *bank
	fernway, brightline *relyingParty
	// captured is what the attack lab has captured from other sign-ins.
	captured captures
}

// New builds the demo for a listener on port, reached through n.
func New(port int, n *demokit.Net) (*World, error) {
	w := &World{port: port, net: n, router: demokit.HostRouter{}}
	var err error
	if w.fernway, err = w.newRelyingParty(fernwaySetup); err != nil {
		return nil, fmt.Errorf("fernway: %w", err)
	}
	if w.brightline, err = w.newRelyingParty(brightlineSetup); err != nil {
		return nil, fmt.Errorf("brightline: %w", err)
	}
	if w.bank, err = w.newBank(w.fernway, w.brightline); err != nil {
		return nil, fmt.Errorf("bank: %w", err)
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
