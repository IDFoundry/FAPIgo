// Command conformance-federation-trust-anchor is a minimal, standing
// OpenID Federation 1.0 Trust Anchor, standing in for a real one (e.g.
// https://trust-anchor.authlete.net/, the example the OIDF conformance
// suite's own "Deployed federation entity test" plan configs use) so
// this repo's own AS/RP can be tested as a real leaf entity of a real
// Trust Chain without depending on third-party infrastructure.
//
// It is throwaway conformance-run tooling, not library code (see
// ARCHITECTURE.md's "No public JOSE utility package" and
// conformance/server/scripts/generate-client-key's own doc comment for
// this repo's established precedent) — but the actual federation logic
// it wires into net/http is entirely this module's own public API:
// federation.SelfIssuer for its own Entity Configuration,
// federation.SubordinateIssuer for the Subordinate Statements it issues
// about each configured subordinate, federation.SubjectFromFetchRequest/
// RejectUnsupportedListingFilters for the Fetch/List request-shape
// checks OpenID Federation 1.0 §8.2/§9 require, federation.Resolver/
// federation.ResolveIssuer for its own /resolve endpoint (§8.3) — this
// Trust Anchor resolves each of its own subordinates against itself,
// the same real Trust Chain walk any other Resolver performs, not a
// shortcut specific to being both anchor and issuer here — and
// federation.WriteError for translating any of the above's
// *federation.Error into the correct wire response (or a generic 500
// for anything else) without reimplementing that unwrap-or-fallback
// dance at every handler. This is exactly the reference wiring
// federation/doc.go's own "Scope" section points at — this package
// deliberately never owns an http.Server itself (see that doc
// comment).
//
// /resolve's own outbound fetches (this Trust Anchor's own Entity
// Configuration/Fetch endpoint, and each subordinate's own Entity
// Configuration) cross container boundaries within docker-compose's own
// private network — fapihttp's default SSRF hardening blocks any
// private-range address unconditionally, so this binary explicitly
// allow-lists exactly its own host and every configured subordinate's
// own host (fapihttp.Config.AllowedPrivateHosts — see its own doc
// comment for why an explicit hostname list, not a CIDR one, is the
// right shape for a fixed, closed deployment like this one) rather than
// disabling that protection more broadly.
//
// Subordinates (the leaf entities this Trust Anchor vouches for) are
// configured via a JSON file — see subordinatesFile — since federation
// is a shared-key-per-entity concept, not something that fits this
// binary's own -cert/-key/-listen flag shape. This Trust Anchor's own
// signing key is generated fresh on every start (logged to stdout as a
// JWK Set) — unlike a subordinate's own key, nothing else needs to
// pin against it across restarts, since every Trust Chain always walks
// up to this Trust Anchor's own live Entity Configuration and only ever
// trusts whatever pre-configured key an operator feeds a Resolver
// out of band (the same "learn the Trust Anchor's key out of band,
// once" step a real deployment already requires).
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/fapihttp"
	"github.com/idfoundry/fapigo/federation"
	"github.com/idfoundry/fapigo/internal/jose"
)

// readHeaderTimeout bounds how long the server waits to receive a
// request's headers — see cmd/conformance-as/main.go's identical
// constant for why.
const readHeaderTimeout = 10 * time.Second

// entityConfigurationLifetime/subordinateStatementLifetime bound this
// Trust Anchor's own self-signed Entity Configuration and the
// Subordinate Statements it issues about each configured subordinate.
const (
	entityConfigurationLifetime  = 24 * time.Hour
	subordinateStatementLifetime = time.Hour
)

// resolveMaxPathLength/resolveMaxStatementLifetime/resolveMaxClockSkew/
// resolveHTTPTimeout bound this Trust Anchor's own federation.Resolver,
// used only to answer its own /resolve endpoint (OpenID Federation 1.0
// §8.3) — every subordinate configured here is an Immediate Subordinate
// one hop away, so these are generous, fixed values, matching
// cmd/conformance-as/wiring.go's identically-reasoned federation
// constants: this binary's own federation posture isn't a
// conformance-run dimension the way -entity-id/-subordinates are.
//
// resolveMaxStatementLifetime must exceed entityConfigurationLifetime
// (not just subordinateStatementLifetime): Resolve's own terminal check
// verifies this Trust Anchor's own Entity Configuration too — self-
// issued with entityConfigurationLifetime, not subordinateStatementLifetime
// — so a ceiling shorter than that rejects every resolution with "exp
// exceeds maximum allowed lifetime" against this binary's own
// statement, confirmed live before landing this value.
const (
	resolveMaxPathLength        = 5
	resolveMaxStatementLifetime = entityConfigurationLifetime + time.Hour
	resolveMaxClockSkew         = 5 * time.Second
	resolveHTTPTimeout          = 10 * time.Second
)

// subordinatesFile is the -subordinates flag's own JSON shape: every
// entity this Trust Anchor vouches for, and the federation signing key
// (JWK Set) each one publishes — captured out of band from that
// entity's own live /.well-known/openid-federation (its "jwks" claim),
// the same way a real deployment learns a subordinate's key before
// vouching for it.
type subordinatesFile struct {
	Subordinates []struct {
		EntityID string          `json:"entity_id"`
		JWKS     json.RawMessage `json:"jwks"`
	} `json:"subordinates"`
}

// mustHost extracts the hostname (no port) from rawURL — entity_id and
// every subordinate's own entity_id are always this binary's own
// operator-supplied config, never untrusted input, so a parse failure
// here means a misconfigured deployment, not a request to handle
// gracefully.
func mustHost(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		log.Fatalf("conformance-federation-trust-anchor: parse entity id %q: %v", rawURL, err)
	}
	return u.Hostname()
}

func main() {
	log.SetFlags(0)

	entityID := flag.String("entity-id", "", "this Trust Anchor's own Entity Identifier (required)")
	listenAddr := flag.String("listen", "", "listen address (required)")
	certFile := flag.String("cert", "", "TLS cert file (required)")
	keyFile := flag.String("key", "", "TLS key file (required)")
	subordinatesPath := flag.String("subordinates", "", "path to a JSON file listing subordinate entities this Trust Anchor vouches for (required) — see subordinatesFile")
	flag.Parse()

	if *entityID == "" || *listenAddr == "" || *certFile == "" || *keyFile == "" || *subordinatesPath == "" {
		log.Fatal("conformance-federation-trust-anchor: -entity-id, -listen, -cert, -key and -subordinates are all required")
	}

	raw, err := os.ReadFile(*subordinatesPath) // #nosec G304 -- operator's own -subordinates flag value, not untrusted input
	if err != nil {
		log.Fatalf("conformance-federation-trust-anchor: read subordinates file: %v", err)
	}
	var subs subordinatesFile
	if err := json.Unmarshal(raw, &subs); err != nil {
		log.Fatalf("conformance-federation-trust-anchor: parse subordinates file: %v", err)
	}
	subordinateJWKS := make(map[string]json.RawMessage, len(subs.Subordinates))
	for _, s := range subs.Subordinates {
		subordinateJWKS[s.EntityID] = s.JWKS
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("conformance-federation-trust-anchor: generate key: %v", err)
	}
	jwk, err := jose.NewJWK(&priv.PublicKey, fapi.ES256)
	if err != nil {
		log.Fatalf("conformance-federation-trust-anchor: build jwk: %v", err)
	}
	jwkJSON, err := jwk.WithKeyID("ta-key1").MarshalJSON()
	if err != nil {
		log.Fatalf("conformance-federation-trust-anchor: marshal jwk: %v", err)
	}
	ownJWKS := json.RawMessage(`{"keys":[` + string(jwkJSON) + `]}`)
	log.Printf("conformance-federation-trust-anchor: entity_id %s\nown public jwks (paste into a Resolver/plan config's trust anchor jwks field):\n%s", *entityID, ownJWKS)

	fetchEndpoint := *entityID + "/fetch"
	listEndpoint := *entityID + "/list"
	resolveEndpoint := *entityID + "/resolve"
	federationEntityMetadata, err := json.Marshal(map[string]string{
		"federation_fetch_endpoint":   fetchEndpoint,
		"federation_list_endpoint":    listEndpoint,
		"federation_resolve_endpoint": resolveEndpoint,
	})
	if err != nil {
		log.Fatalf("conformance-federation-trust-anchor: marshal federation_entity metadata: %v", err)
	}
	subordinateEntityIDs := make([]string, 0, len(subordinateJWKS))
	for id := range subordinateJWKS {
		subordinateEntityIDs = append(subordinateEntityIDs, id)
	}

	// allowedPrivateHosts is every host /resolve's own federation.Resolver
	// may legitimately need to fetch from: this Trust Anchor's own host
	// (its own Entity Configuration and /fetch endpoint, both fetched as
	// part of resolving any subordinate) plus each configured
	// subordinate's own host. This whole binary only ever runs inside a
	// closed docker-compose network of known, fixed, operator-configured
	// peer hostnames — see fapihttp.Config.AllowedPrivateHosts' own doc
	// comment for why an explicit hostname allow-list, not a CIDR one, is
	// the right shape for exactly this kind of deployment (a peer
	// service's own resolved IP is dynamic and outside this binary's
	// control).
	allowedPrivateHosts := []string{mustHost(*entityID)}
	for _, id := range subordinateEntityIDs {
		allowedPrivateHosts = append(allowedPrivateHosts, mustHost(id))
	}

	// peerCertPool trusts exactly *certFile — the one throwaway
	// self-signed cert this whole docker-compose setup shares across
	// every conformance service (see generate-server-cert.sh's own doc
	// comment) — for /resolve's own outbound calls to its peers. Not
	// InsecureSkipVerify: that would accept literally any certificate
	// any host on the network presents; pinning this specific cert as
	// the only trusted root still rejects an imposter while accepting
	// the real peers this binary is actually configured to talk to.
	// This is necessary in addition to AllowedPrivateHosts above, not
	// instead of it — that lifts the SSRF address check, this satisfies
	// ordinary TLS certificate verification, which a self-signed cert
	// fails against the system root pool regardless of SSRF policy.
	certPEM, err := os.ReadFile(*certFile) // #nosec G304 -- operator's own -cert flag value, not untrusted input
	if err != nil {
		log.Fatalf("conformance-federation-trust-anchor: read cert file for peer trust pool: %v", err)
	}
	peerCertPool := x509.NewCertPool()
	if !peerCertPool.AppendCertsFromPEM(certPEM) {
		log.Fatalf("conformance-federation-trust-anchor: no certificates found in %s", *certFile)
	}
	peerHTTPClient := &http.Client{
		Timeout:   resolveHTTPTimeout,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: peerCertPool, MinVersion: tls.VersionTLS12}},
	}
	fetcher, err := fapihttp.New(peerHTTPClient, fapihttp.Config{
		MaxResponseBytes:    1 << 20,
		RequestTimeout:      resolveHTTPTimeout,
		MaxRedirects:        2,
		AllowedPrivateHosts: allowedPrivateHosts,
	})
	if err != nil {
		log.Fatalf("conformance-federation-trust-anchor: build fetcher: %v", err)
	}
	resolver, err := federation.NewResolver(federation.Config{
		TrustAnchors: []federation.TrustAnchor{{EntityID: *entityID, JWKS: ownJWKS}},
		Limits: federation.Limits{
			MaxPathLength: resolveMaxPathLength, MaxStatementLifetime: resolveMaxStatementLifetime, MaxClockSkew: resolveMaxClockSkew,
		},
	}, federation.Dependencies{HTTP: fetcher, Clock: federation.SystemClock{}})
	if err != nil {
		log.Fatalf("conformance-federation-trust-anchor: build resolver: %v", err)
	}
	resolveIssuer, err := federation.NewResolveIssuer(federation.ResolveIssueConfig{EntityID: *entityID}, federation.ResolveIssueDependencies{
		Signer: priv, Algorithm: fapi.ES256, KeyID: "ta-key1", Clock: federation.SystemClock{},
	})
	if err != nil {
		log.Fatalf("conformance-federation-trust-anchor: build resolve issuer: %v", err)
	}

	selfIssuer, err := federation.NewSelfIssuer(federation.SelfIssueConfig{
		EntityID: *entityID, Lifetime: entityConfigurationLifetime,
	}, federation.SelfIssueDependencies{
		Signer: priv, Algorithm: fapi.ES256, KeyID: "ta-key1", JWKS: ownJWKS, Clock: federation.SystemClock{},
	})
	if err != nil {
		log.Fatalf("conformance-federation-trust-anchor: build self issuer: %v", err)
	}
	subordinateIssuer, err := federation.NewSubordinateIssuer(federation.SubordinateIssueConfig{
		EntityID: *entityID, Lifetime: subordinateStatementLifetime,
	}, federation.SubordinateIssueDependencies{
		Signer: priv, Algorithm: fapi.ES256, KeyID: "ta-key1", Clock: federation.SystemClock{},
	})
	if err != nil {
		log.Fatalf("conformance-federation-trust-anchor: build subordinate issuer: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-federation", func(w http.ResponseWriter, r *http.Request) {
		token, err := selfIssuer.EntityConfiguration(map[string]json.RawMessage{"federation_entity": federationEntityMetadata})
		if err != nil {
			log.Printf("conformance-federation-trust-anchor: self-issue entity configuration: %v", err)
			http.Error(w, "server_error", http.StatusInternalServerError)
			return
		}
		federation.WriteEntityStatement(w, token)
	})
	mux.HandleFunc("GET /fetch", func(w http.ResponseWriter, r *http.Request) {
		sub, err := federation.SubjectFromFetchRequest(r)
		if err != nil {
			federation.WriteError(w, err)
			return
		}
		jwks, ok := subordinateJWKS[sub]
		if !ok {
			federation.NewError(federation.ErrorNotFound, http.StatusNotFound, "no such subordinate").WriteJSON(w)
			return
		}
		token, err := subordinateIssuer.SubordinateStatement(federation.SubordinateStatementParams{
			Subject: sub, JWKS: jwks, SourceEndpoint: fetchEndpoint,
		})
		if err != nil {
			log.Printf("conformance-federation-trust-anchor: issue subordinate statement for %q: %v", sub, err) // #nosec G706 -- %q Go-quotes sub, escaping newlines/control characters, so a malicious "sub" cannot forge a fake log line
			federation.WriteError(w, err)
			return
		}
		federation.WriteEntityStatement(w, token)
	})

	mux.HandleFunc("GET /list", func(w http.ResponseWriter, r *http.Request) {
		if err := federation.RejectUnsupportedListingFilters(r); err != nil {
			federation.WriteError(w, err)
			return
		}
		body, err := json.Marshal(subordinateEntityIDs)
		if err != nil {
			http.Error(w, "server_error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	})

	mux.HandleFunc("GET /resolve", func(w http.ResponseWriter, r *http.Request) {
		subject, trustAnchors, entityTypes, err := federation.ResolveRequestFromHTTP(r)
		if err != nil {
			federation.WriteError(w, err)
			return
		}
		resolved, err := resolver.Resolve(r.Context(), subject)
		if err != nil {
			log.Printf("conformance-federation-trust-anchor: resolve %q: %v", subject, err) // #nosec G706 -- %q Go-quotes subject, escaping newlines/control characters, so a malicious "sub" cannot forge a fake log line
			federation.NewError(federation.ErrorNotFound, http.StatusNotFound, "could not resolve subject").WriteJSON(w)
			return
		}
		token, err := resolveIssuer.Response(resolved, trustAnchors, entityTypes, nil)
		if err != nil {
			log.Printf("conformance-federation-trust-anchor: build resolve response for %q: %v", subject, err) // #nosec G706 -- see above
			federation.NewError(federation.ErrorInvalidRequest, http.StatusBadRequest, "could not build resolve response").WriteJSON(w)
			return
		}
		w.Header().Set("Content-Type", federation.ResolveResponseContentType)
		_, _ = w.Write([]byte(token)) // #nosec G705 -- token is a signed compact JWT (application/resolve-response+jwt), never rendered as HTML; reflected-XSS via taint analysis doesn't apply to this content type, the same as every other signed-JWT response this file already writes the identical way
	})

	httpServer := &http.Server{
		Addr:              *listenAddr,
		Handler:           mux,
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12},
		ReadHeaderTimeout: readHeaderTimeout,
	}
	log.Printf("conformance-federation-trust-anchor: listening on %s", *listenAddr)
	if err := httpServer.ListenAndServeTLS(*certFile, *keyFile); err != nil && err != http.ErrServerClosed {
		log.Fatalf("conformance-federation-trust-anchor: %v", err)
	}
}
