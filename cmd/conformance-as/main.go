package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/server"
)

// httpFetchTimeout bounds a single outbound client-JWKS fetch.
const httpFetchTimeout = 10 * time.Second

// readHeaderTimeout bounds how long the server waits to receive a
// request's headers — without it, a client that trickles headers one
// byte at a time can hold a connection (and its goroutine) open
// indefinitely (a Slowloris-style DoS).
const readHeaderTimeout = 10 * time.Second

// bcp195TLS12CipherSuites is the TLS 1.2 cipher suite allow-list FAPI 2.0
// requires (FAPI2-SP-FINAL-5.2.2, citing BCP195/RFC 7525): ECDHE key
// exchange (forward secrecy) with an AEAD cipher only — no CBC-mode
// suites, which Go's zero-value tls.Config still offers by default for
// broader interop. TLS 1.3 needs no equivalent list: crypto/tls ignores
// CipherSuites for 1.3 and always offers only its three built-in AEAD
// suites.
var bcp195TLS12CipherSuites = []uint16{
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
}

func main() {
	log.SetFlags(0)

	configPath := flag.String("config", "", "path to JSON config file (required)")
	listenOverride := flag.String("listen", "", "override listen_addr from the config file")
	certOverride := flag.String("cert", "", "override tls.cert_file from the config file")
	keyOverride := flag.String("key", "", "override tls.key_file from the config file")
	insecureHTTP := flag.Bool("insecure-http", false, "serve plaintext HTTP instead of TLS (loopback listen_addr only)")
	accessTokenFormat := flag.String("access-token-format", string(AccessTokenFormatJWT), "access token format to issue/verify: jwt or opaque")
	flag.Parse()

	if *configPath == "" {
		log.Fatal("conformance-as: -config is required")
	}

	rawCfg, err := LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("conformance-as: %v", err)
	}
	if *listenOverride != "" {
		rawCfg.ListenAddr = *listenOverride
	}
	if *certOverride != "" {
		rawCfg.TLS.CertFile = *certOverride
	}
	if *keyOverride != "" {
		rawCfg.TLS.KeyFile = *keyOverride
	}

	resolved, err := rawCfg.Resolve(*insecureHTTP, AccessTokenFormat(*accessTokenFormat))
	if err != nil {
		log.Fatalf("conformance-as: config: %v", err)
	}
	if *insecureHTTP && !isLoopbackAddr(resolved.ListenAddr) {
		log.Fatal("conformance-as: -insecure-http requires a loopback listen_addr (e.g. 127.0.0.1:8443)")
	}

	mux, err := newServerMux(resolved, *insecureHTTP)
	if err != nil {
		log.Fatalf("conformance-as: %v", err)
	}

	httpServer := &http.Server{
		Addr:              resolved.ListenAddr,
		Handler:           mux,
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12, CipherSuites: bcp195TLS12CipherSuites},
		ReadHeaderTimeout: readHeaderTimeout,
	}

	log.Printf("conformance-as: listening on %s (issuer %s)", resolved.ListenAddr, resolved.Issuer.String())
	if *insecureHTTP {
		err = httpServer.ListenAndServe()
	} else {
		err = httpServer.ListenAndServeTLS(resolved.TLSCertFile, resolved.TLSKeyFile)
	}
	if err != nil && err != http.ErrServerClosed {
		log.Fatalf("conformance-as: %v", err)
	}
}

// buildEndpoints derives this server's four endpoint URLs from issuer by
// appending fixed paths — the common convention of treating the issuer
// identifier as the deployment's own origin.
func buildEndpoints(issuer fapi.URL, allowLoopbackHTTP bool) (server.Endpoints, error) {
	var opts []fapi.URLOption
	if allowLoopbackHTTP {
		opts = append(opts, fapi.AllowLoopbackHTTP())
	}
	build := func(path string) (fapi.URL, error) {
		return fapi.ParseEndpointURL(issuer.String()+path, opts...)
	}
	authorization, err := build("/authorize")
	if err != nil {
		return server.Endpoints{}, fmt.Errorf("authorization endpoint: %w", err)
	}
	token, err := build("/token")
	if err != nil {
		return server.Endpoints{}, fmt.Errorf("token endpoint: %w", err)
	}
	par, err := build("/par")
	if err != nil {
		return server.Endpoints{}, fmt.Errorf("par endpoint: %w", err)
	}
	jwks, err := build("/jwks")
	if err != nil {
		return server.Endpoints{}, fmt.Errorf("jwks endpoint: %w", err)
	}
	return server.Endpoints{
		Authorization:              authorization,
		Token:                      token,
		PushedAuthorizationRequest: par,
		JWKS:                       jwks,
	}, nil
}

// buildResourceURL derives one of this binary's stand-in
// protected-resource endpoint URLs (path is e.g. "/accounts" or
// "/userinfo") from issuer, the same way buildEndpoints derives the
// four protocol endpoints. See resource.go's resourceHandler doc
// comment for why this exists.
func buildResourceURL(issuer fapi.URL, allowLoopbackHTTP bool, path string) (fapi.URL, error) {
	var opts []fapi.URLOption
	if allowLoopbackHTTP {
		opts = append(opts, fapi.AllowLoopbackHTTP())
	}
	return fapi.ParseEndpointURL(issuer.String()+path, opts...)
}

// isLoopbackAddr reports whether addr's host (net.Listen-style
// "host:port") is loopback-only. An empty host (":8443") is not
// loopback-only — it binds every interface — so -insecure-http must be
// refused for it.
func isLoopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "" {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
