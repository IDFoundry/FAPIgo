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
// this repo's established precedent) — it calls internal/federation's
// Create directly (available since cmd/ is inside this module) rather
// than exposing any new public API for "act as a Trust Anchor", which
// federation/doc.go deliberately leaves out of this module's own public
// surface for now.
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
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"os"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/federation"
	intfed "github.com/idfoundry/fapigo/internal/federation"
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
	federationEntityMetadata, err := json.Marshal(map[string]string{
		"federation_fetch_endpoint": fetchEndpoint,
		"federation_list_endpoint":  listEndpoint,
	})
	if err != nil {
		log.Fatalf("conformance-federation-trust-anchor: marshal federation_entity metadata: %v", err)
	}
	subordinateEntityIDs := make([]string, 0, len(subordinateJWKS))
	for id := range subordinateJWKS {
		subordinateEntityIDs = append(subordinateEntityIDs, id)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-federation", func(w http.ResponseWriter, r *http.Request) {
		token, err := intfed.Create(intfed.CreateParams{
			Signer: priv, Algorithm: fapi.ES256, KeyID: "ta-key1",
			Issuer: *entityID, Subject: *entityID,
			Now: time.Now(), Lifetime: entityConfigurationLifetime, JWKS: ownJWKS,
			Metadata: map[string]json.RawMessage{"federation_entity": federationEntityMetadata},
		})
		if err != nil {
			log.Printf("conformance-federation-trust-anchor: create entity configuration: %v", err)
			http.Error(w, "server_error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", federation.EntityStatementContentType)
		_, _ = w.Write([]byte(token))
	})
	mux.HandleFunc("GET /fetch", func(w http.ResponseWriter, r *http.Request) {
		sub := r.URL.Query().Get("sub")
		jwks, ok := subordinateJWKS[sub]
		if !ok {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":"not_found"}`))
			return
		}
		token, err := intfed.Create(intfed.CreateParams{
			Signer: priv, Algorithm: fapi.ES256, KeyID: "ta-key1",
			Issuer: *entityID, Subject: sub,
			Now: time.Now(), Lifetime: subordinateStatementLifetime, JWKS: jwks,
		})
		if err != nil {
			log.Printf("conformance-federation-trust-anchor: create subordinate statement for %q: %v", sub, err) // #nosec G706 -- %q Go-quotes sub, escaping newlines/control characters, so a malicious "sub" cannot forge a fake log line
			http.Error(w, "server_error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", federation.EntityStatementContentType)
		_, _ = w.Write([]byte(token))
	})

	mux.HandleFunc("GET /list", func(w http.ResponseWriter, r *http.Request) {
		body, err := json.Marshal(subordinateEntityIDs)
		if err != nil {
			http.Error(w, "server_error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
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
