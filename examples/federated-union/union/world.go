// Package union builds the Meridian Union: three fictional countries
// whose national federations join a regional OpenID Federation, so a
// service in one country can accept a citizen of another without either
// side registering with the other in advance.
//
// Every entity — the Union, each national authority, accreditation body,
// identity provider and service — runs in one process behind a
// demonet.HostRouter, each at its own *.localhost host.
package union

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"sync/atomic"
	"time"

	"github.com/idfoundry/fapigo/examples/federated-union/internal/demonet"
	"github.com/idfoundry/fapigo/fapihttp"
	"github.com/idfoundry/fapigo/federation"
	"github.com/idfoundry/fapigo/keys"
)

// country is one Union member.
type country struct {
	key      string // host label: northland, southport, eastmark
	name     string // Northland
	idpName  string // NorthID
	color    string // accent colour in the pages
	citizens []citizen
}

var countries = []country{
	{key: "northland", name: "Northland", idpName: "NorthID", color: "#2563eb", citizens: []citizen{
		{sub: "nl-4417", given: "Astrid", family: "Holm", birthdate: "1988-03-14", email: "astrid.holm@mail.northland.example", address: "12 Fjord Lane, Kalvik"},
		{sub: "nl-9021", given: "Leif", family: "Brandt", birthdate: "1975-11-02", email: "leif.brandt@mail.northland.example", address: "3 Harbour Row, Nordby"},
	}},
	{key: "southport", name: "Southport", idpName: "SouthID", color: "#059669", citizens: []citizen{
		{sub: "sp-1180", given: "Marisol", family: "Vega", birthdate: "1992-07-21", email: "marisol.vega@mail.southport.example", address: "48 Palm Street, Porto Sul"},
	}},
	{key: "eastmark", name: "Eastmark", idpName: "EastID", color: "#d97706", citizens: []citizen{
		{sub: "em-3306", given: "Tomas", family: "Novak", birthdate: "1983-01-30", email: "tomas.novak@mail.eastmark.example", address: "7 Linden Square, Ostrava Nova"},
		{sub: "em-5512", given: "Ilse", family: "Varga", birthdate: "1999-09-09", email: "ilse.varga@mail.eastmark.example", address: "21 River Walk, Marktel"},
	}},
}

// service is a relying party of the demo.
type serviceSpec struct {
	host, name, country string
}

var services = []serviceSpec{
	{host: "bank.southport.localhost", name: "Southport Savings Bank", country: "southport"},
	{host: "telco.eastmark.localhost", name: "Eastmark Telecom", country: "eastmark"},
}

// localhost is the suffix every demo host shares.
const localhost = ".localhost"

// countryHost is role's host in country, e.g. id.eastmark.localhost.
func countryHost(role, countryKey string) string { return role + "." + countryKey + localhost }

const (
	unionHost    = "union.localhost"
	consoleHost  = "console.localhost"
	impostorHost = "bank.northland.localhost"
)

// Scenes are the switches the console flips.
type Scenes struct {
	// SuspendEastmark: the Union stops vouching for Eastmark's national
	// authority, cutting Eastmark off from the rest of the Union.
	SuspendEastmark atomic.Bool
	// ForgeEastmarkMark: EastID replaces its accredited level-of-assurance
	// Trust Mark with one it issued itself.
	ForgeEastmarkMark atomic.Bool
	// CompromiseEastmark: Eastmark's national authority starts vouching
	// for an impostor claiming a Northland host.
	CompromiseEastmark atomic.Bool
}

// World is the whole running federation.
type World struct {
	port   int
	net    *demonet.Net
	scenes Scenes

	union        *entity
	authorities  map[string]*entity // country key -> national authority
	accreditors  map[string]*accreditation
	idps         map[string]*identityProvider
	services     []*relyingParty
	impostor     *entity
	entities     []*entity // every entity, for the console
	loaHighType  string
	router       demonet.HostRouter
	consoleState *console
}

// Hosts is every host name the demo serves, for its TLS certificate.
func Hosts() []string {
	hosts := []string{unionHost, consoleHost, impostorHost}
	for _, c := range countries {
		hosts = append(hosts, countryHost("ta", c.key), countryHost("accreditation", c.key), countryHost("id", c.key))
	}
	for _, s := range services {
		hosts = append(hosts, s.host)
	}
	return hosts
}

// New builds the federation for a listener on port, reached through n.
func New(port int, n *demonet.Net) (*World, error) {
	w := &World{
		port: port, net: n,
		authorities: map[string]*entity{},
		accreditors: map[string]*accreditation{},
		idps:        map[string]*identityProvider{},
		router:      demonet.HostRouter{},
	}
	w.loaHighType = w.entityID(unionHost) + "/marks/loa-high"
	if err := w.build(); err != nil {
		return nil, err
	}
	return w, nil
}

// Handler serves every entity.
func (w *World) Handler() http.Handler { return w.router }

// Scenes is the console's switches.
func (w *World) Scenes() *Scenes { return &w.scenes }

// URL is the address of host's page at path.
func (w *World) URL(host, path string) string { return w.entityID(host) + path }

func (w *World) entityID(host string) string {
	if w.port == 443 {
		return "https://" + host
	}
	return fmt.Sprintf("https://%s:%d", host, w.port)
}

// fetcher is the hardened federation fetch client for the entity at
// host, going through the demo network.
func (w *World) fetcher(host string) (*fapihttp.Client, error) {
	return fapihttp.New(w.net.Client(host), fapihttp.Config{
		MaxResponseBytes: 1 << 20, RequestTimeout: 10 * time.Second, MaxRedirects: 2,
		// Every demo host resolves to the loopback address.
		AllowLoopbackHTTP: true,
	})
}

// anchor is a Trust Anchor as a resolver is configured with it: the
// entity ID and the keys it's trusted with, provided out of band.
func anchor(e *entity) federation.TrustAnchor {
	return federation.TrustAnchor{EntityID: e.id, JWKS: e.key.jwks}
}

// resolverFor is a Trust Chain resolver trusting anchors, fetching as
// host.
func (w *World) resolverFor(host string, anchors ...*entity) (*federation.Resolver, error) {
	fetcher, err := w.fetcher(host)
	if err != nil {
		return nil, err
	}
	tas := make([]federation.TrustAnchor, len(anchors))
	for i, a := range anchors {
		tas[i] = anchor(a)
	}
	return federation.NewResolver(federation.Config{
		TrustAnchors: tas,
		Limits: federation.Limits{
			MaxPathLength: 4, MaxAuthorityHints: 5,
			MaxStatementLifetime: statementLifetime + time.Hour, MaxClockSkew: 30 * time.Second,
		},
	}, federation.Dependencies{HTTP: fetcher, Clock: federation.SystemClock{}})
}

func (w *World) add(e *entity) error {
	if err := e.init(); err != nil {
		return err
	}
	w.entities = append(w.entities, e)
	w.router[e.host] = e.mux
	return nil
}

// build creates every entity: the Union first, then each country's
// authority, accreditation body and identity provider, then the
// services, then the impostor used by the compromise scene.
func (w *World) build() error {
	unionKey, err := newSigningKey("union-1", keys.FederationEntitySigning)
	if err != nil {
		return err
	}
	w.union = &entity{
		id: w.entityID(unionHost), host: unionHost, name: "Meridian Union", role: "Union trust anchor",
		key:              unionKey,
		trustMarkIssuers: map[string][]string{},
	}
	for _, c := range countries {
		w.union.trustMarkIssuers[w.loaHighType] = append(w.union.trustMarkIssuers[w.loaHighType], w.entityID(countryHost("accreditation", c.key)))
	}
	w.union.subordinates = w.unionSubordinates
	if err := w.add(w.union); err != nil {
		return err
	}

	for _, c := range countries {
		if err := w.buildCountry(c); err != nil {
			return err
		}
	}
	for _, s := range services {
		rp, err := w.newRelyingParty(s)
		if err != nil {
			return err
		}
		w.services = append(w.services, rp)
	}

	impostorKey, err := newSigningKey("impostor-1", keys.FederationEntitySigning)
	if err != nil {
		return err
	}
	w.impostor = &entity{
		id: w.entityID(impostorHost), host: impostorHost, name: "Northland Bank (impostor)", role: "impostor service",
		country: "eastmark", key: impostorKey,
		authorityHints: []string{w.entityID(countryHost("ta", "eastmark"))},
		metadata: func(context.Context) (map[string]json.RawMessage, error) {
			return map[string]json.RawMessage{"openid_relying_party": json.RawMessage(`{"client_name":"Northland Bank","response_types":["code"]}`)}, nil
		},
	}
	if err := w.add(w.impostor); err != nil {
		return err
	}

	c, err := w.newConsole()
	if err != nil {
		return err
	}
	w.consoleState = c
	return nil
}

// unionSubordinates is who the Union vouches for: each national
// authority, confined to its own country's hosts and to at most one
// level of entities below it, under the Union's baseline policy.
func (w *World) unionSubordinates() map[string]subordinate {
	out := map[string]subordinate{}
	for _, c := range countries {
		if c.key == "eastmark" && w.scenes.SuspendEastmark.Load() {
			continue
		}
		ta := w.authorities[c.key]
		out[ta.id] = subordinate{
			jwks: ta.key.jwks,
			constraints: &federation.Constraints{
				MaxPathLength: 1, HasMaxPathLength: true,
				NamingConstraints: &federation.NamingConstraints{Permitted: []string{"." + c.key + localhost}},
			},
			policy: federation.MetadataPolicy{
				"openid_relying_party": {
					"grant_types":                {"subset_of": json.RawMessage(`["authorization_code","refresh_token"]`)},
					"token_endpoint_auth_method": {"one_of": json.RawMessage(`["private_key_jwt"]`)},
				},
			},
		}
	}
	return out
}

// buildCountry creates c's national authority, accreditation body and
// identity provider.
func (w *World) buildCountry(c country) error {
	taHost := countryHost("ta", c.key)
	taKey, err := newSigningKey(c.key+"-ta-1", keys.FederationEntitySigning)
	if err != nil {
		return err
	}
	ta := &entity{
		id: w.entityID(taHost), host: taHost, name: c.name + " Federation Authority", role: "national authority",
		country: c.key, key: taKey,
		authorityHints: []string{w.union.id},
		// A service trusting its own authority directly finishes its
		// Trust Chains there, so the authority publishes which
		// accreditation bodies it recognises too — the same ones the
		// Union does.
		trustMarkIssuers: w.union.trustMarkIssuers,
	}
	ta.subordinates = func() map[string]subordinate { return w.nationalSubordinates(c) }
	w.authorities[c.key] = ta
	if err := w.add(ta); err != nil {
		return err
	}

	acc, err := w.newAccreditation(c, ta)
	if err != nil {
		return err
	}
	w.accreditors[c.key] = acc

	idp, err := w.newIdentityProvider(c, ta)
	if err != nil {
		return err
	}
	w.idps[c.key] = idp
	return nil
}

// nationalSubordinates is who c's national authority vouches for: its
// accreditation body, identity provider and services — plus, once
// compromised, the impostor.
func (w *World) nationalSubordinates(c country) map[string]subordinate {
	out := map[string]subordinate{}
	if acc, ok := w.accreditors[c.key]; ok {
		out[acc.entity.id] = subordinate{jwks: acc.entity.key.jwks}
	}
	if idp, ok := w.idps[c.key]; ok {
		out[idp.entity.id] = subordinate{jwks: idp.entity.key.jwks}
	}
	for _, rp := range w.services {
		if rp.country.key == c.key {
			out[rp.entity.id] = subordinate{jwks: rp.entity.key.jwks, policy: nationalServicePolicy(c)}
		}
	}
	if c.key == "eastmark" && w.scenes.CompromiseEastmark.Load() && w.impostor != nil {
		out[w.impostor.id] = subordinate{jwks: w.impostor.key.jwks}
	}
	return out
}

// nationalServicePolicy is what each country adds on top of the Union's
// baseline for its own services: Southport requires a named, contactable
// operator.
func nationalServicePolicy(c country) federation.MetadataPolicy {
	if c.key != "southport" {
		return nil
	}
	return federation.MetadataPolicy{
		"openid_relying_party": {
			"contacts": {"essential": json.RawMessage(`true`)},
		},
	}
}

// countryByKey returns the country with key.
func countryByKey(key string) country {
	for _, c := range countries {
		if c.key == key {
			return c
		}
	}
	return country{}
}

// sortedEntities is every entity grouped for the console: the Union,
// then each country's entities, then the impostor.
func (w *World) sortedEntities() []*entity {
	out := append([]*entity{}, w.entities...)
	order := map[string]int{"": 0, "northland": 1, "southport": 2, "eastmark": 3}
	sort.SliceStable(out, func(i, j int) bool { return order[out[i].country] < order[out[j].country] })
	return out
}
