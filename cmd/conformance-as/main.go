package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/server"
)

// httpFetchTimeout bounds a single outbound client-JWKS fetch.
const httpFetchTimeout = 10 * time.Second

// dpopNonceLifetime bounds how long a DPoP nonce issued under
// -dpop-nonce-challenge remains valid.
const dpopNonceLifetime = time.Minute

// backchannelAuthenticationRequestLifetime, maxBackchannelAuthenticationRequestLifetime
// and backchannelAuthenticationPollInterval configure CIBA under
// -ciba. The max must stay comfortably above 300s: the OIDF
// FAPI-CIBA-ID1 suite's own AddRequestedExp300SToAuthorizationEndpointRequest
// condition sends requested_expiry=300 on one of its modules, to check
// the server doesn't reject a fairly standard value.
const (
	backchannelAuthenticationRequestLifetime    = 5 * time.Minute
	maxBackchannelAuthenticationRequestLifetime = 10 * time.Minute
	backchannelAuthenticationPollInterval       = 2 * time.Second
)

// readHeaderTimeout bounds how long the server waits to receive a
// request's headers — without it, a client that trickles headers one
// byte at a time can hold a connection (and its goroutine) open
// indefinitely (a Slowloris-style DoS).
const readHeaderTimeout = 10 * time.Second

// fapiRWTLS12CipherSuites is the TLS 1.2 cipher suite allow-list this
// binary serves under: ECDHE key exchange (forward secrecy) with an
// AEAD cipher only — no CBC-mode suites, which Go's zero-value
// tls.Config still offers by default for broader interop. TLS 1.3
// needs no equivalent list: crypto/tls ignores CipherSuites for 1.3
// and always offers only its three built-in AEAD suites.
//
// This is the narrower FAPI-RW §8.5 list (AES-GCM only, both ECDSA and
// RSA), not the broader BCP195/RFC 7525 set FAPI2-SP-FINAL-5.2.2 cites
// (which also permits ChaCha20-Poly1305) — confirmed live: the OIDF
// suite's own FAPI-RW-8.5-1/8.5-2 conformance check, exercised by the
// fapi-ciba-id1-test-plan, hardcodes a TLS 1.2 probe against exactly
// this narrower list and flags ChaCha20-Poly1305 as "not permitted"
// even though BCP195 itself endorses it. Narrowed to this list so that
// check passes; a real BCP195-only deployment would be free to widen
// it back.
var fapiRWTLS12CipherSuites = []uint16{
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
}

func main() {
	log.SetFlags(0)

	configPath := flag.String("config", "", "path to JSON config file (required)")
	listenOverride := flag.String("listen", "", "override listen_addr from the config file")
	certOverride := flag.String("cert", "", "override tls.cert_file from the config file")
	keyOverride := flag.String("key", "", "override tls.key_file from the config file")
	insecureHTTP := flag.Bool("insecure-http", false, "serve plaintext HTTP instead of TLS (loopback listen_addr only)")
	accessTokenFormat := flag.String("access-token-format", string(AccessTokenFormatJWT), "access token format to issue/verify: jwt or opaque")
	dpopNonceChallenge := flag.Bool("dpop-nonce-challenge", false, "require and rotate a DPoP nonce on /par, /token and /userinfo (RFC 9449 §8/§9) — off by default, since the OIDF suite's own driver may not retry on the challenge")
	userinfoSigning := flag.Bool("userinfo-signing", false, "sign /userinfo responses as a JWS (OIDC Core §5.3.2), using the same algorithm as ID tokens — off by default; the FAPI 2.0 Security Profile doesn't require this")
	ciba := flag.Bool("ciba", false, "enable the CIBA backchannel authentication endpoint (poll and ping delivery) — off by default; not part of the FAPI 2.0 Security Profile itself")
	mtls := flag.Bool("mtls", false, "enable a second TLS listener (mtls_listen_addr in the config file, or -mtls-listen) that requests but does not require a client certificate, advertised via mtls_endpoint_aliases (RFC 8705 §5) for a client registered sender_constrain=mtls — off by default; requires real TLS, incompatible with -insecure-http")
	mtlsListenOverride := flag.String("mtls-listen", "", "override mtls_listen_addr from the config file")
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
	if *mtlsListenOverride != "" {
		rawCfg.MTLSListenAddr = *mtlsListenOverride
	}

	resolved, err := rawCfg.Resolve(*insecureHTTP, AccessTokenFormat(*accessTokenFormat))
	if err != nil {
		log.Fatalf("conformance-as: config: %v", err)
	}
	if *insecureHTTP && !isLoopbackAddr(resolved.ListenAddr) {
		log.Fatal("conformance-as: -insecure-http requires a loopback listen_addr (e.g. 127.0.0.1:8443)")
	}
	if *mtls {
		resolved.MTLSEndpoints, err = resolveMTLSEndpoints(*insecureHTTP, resolved, *ciba)
		if err != nil {
			log.Fatalf("conformance-as: %v", err)
		}
	}

	mux, err := newServerMux(resolved, *insecureHTTP, *dpopNonceChallenge, *userinfoSigning, *ciba)
	if err != nil {
		log.Fatalf("conformance-as: %v", err)
	}

	httpServer := &http.Server{
		Addr:              resolved.ListenAddr,
		Handler:           mux,
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12, CipherSuites: fapiRWTLS12CipherSuites},
		ReadHeaderTimeout: readHeaderTimeout,
	}

	if *mtls {
		mtlsServer, err := newMTLSServer(resolved, mux)
		if err != nil {
			log.Fatalf("conformance-as: mtls: %v", err)
		}
		go func() {
			log.Printf("conformance-as: mtls listener on %s", resolved.MTLSListenAddr)
			if err := mtlsServer.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
				log.Fatalf("conformance-as: mtls: %v", err)
			}
		}()
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

// resolveMTLSEndpoints validates the -mtls/-insecure-http/mtls_listen_addr
// combination and, if valid, derives the mtls_endpoint_aliases this
// run should advertise — split out from main so this validation is
// testable without invoking main itself (which calls log.Fatal/blocks
// on a real listener).
func resolveMTLSEndpoints(insecureHTTP bool, resolved ResolvedConfig, ciba bool) (server.MTLSEndpoints, error) {
	if insecureHTTP {
		return server.MTLSEndpoints{}, fmt.Errorf("-mtls cannot be combined with -insecure-http (a client certificate requires a real TLS connection)")
	}
	if resolved.MTLSListenAddr == "" {
		return server.MTLSEndpoints{}, fmt.Errorf("-mtls requires mtls_listen_addr in the config file, or -mtls-listen")
	}
	return buildMTLSEndpoints(resolved.Issuer, resolved.MTLSListenAddr, ciba)
}

// newMTLSServer builds the -mtls listener's *http.Server — same mux as
// the primary listener, same cipher list, but requesting
// (RequestClientCert, not RequireAndVerifyClientCert) a client
// certificate: this listener still serves non-mTLS clients too (same
// mux, same server.Server) — only a client actually registered
// storage.SenderConstrainMTLS is rejected for presenting none, and
// that check happens inside server/resource, not here. Split out from
// main so the TLS/cert-loading wiring is testable without actually
// serving.
func newMTLSServer(resolved ResolvedConfig, mux http.Handler) (*http.Server, error) {
	mtlsCert, err := tls.LoadX509KeyPair(resolved.TLSCertFile, resolved.TLSKeyFile)
	if err != nil {
		return nil, fmt.Errorf("load cert: %w", err)
	}
	return &http.Server{
		Addr:    resolved.MTLSListenAddr,
		Handler: mux,
		TLSConfig: &tls.Config{
			MinVersion:   tls.VersionTLS12,
			CipherSuites: fapiRWTLS12CipherSuites,
			Certificates: []tls.Certificate{mtlsCert},
			ClientAuth:   tls.RequestClientCert,
		},
		ReadHeaderTimeout: readHeaderTimeout,
	}, nil
}

// buildMTLSEndpoints derives the RFC 8705 §5 mtls_endpoint_aliases URLs
// from issuer and mtlsListenAddr: same host as issuer, mtlsListenAddr's
// own port. ciba gates whether a backchannel-authentication alias is
// included, mirroring buildEndpoints/newServerMux's own -ciba gating.
func buildMTLSEndpoints(issuer fapi.URL, mtlsListenAddr string, ciba bool) (server.MTLSEndpoints, error) {
	_, mtlsPort, err := net.SplitHostPort(mtlsListenAddr)
	if err != nil {
		return server.MTLSEndpoints{}, fmt.Errorf("mtls_listen_addr: %w", err)
	}
	parsedIssuer, err := url.Parse(issuer.String())
	if err != nil {
		return server.MTLSEndpoints{}, fmt.Errorf("issuer: %w", err)
	}
	base := *parsedIssuer
	base.Host = net.JoinHostPort(parsedIssuer.Hostname(), mtlsPort)

	build := func(path string) (fapi.URL, error) {
		return fapi.ParseEndpointURL(base.String() + path)
	}
	token, err := build("/token")
	if err != nil {
		return server.MTLSEndpoints{}, fmt.Errorf("mtls token endpoint: %w", err)
	}
	par, err := build("/par")
	if err != nil {
		return server.MTLSEndpoints{}, fmt.Errorf("mtls par endpoint: %w", err)
	}
	out := server.MTLSEndpoints{Token: token, PushedAuthorizationRequest: par}
	if ciba {
		backchannel, err := build("/backchannel-authenticate")
		if err != nil {
			return server.MTLSEndpoints{}, fmt.Errorf("mtls backchannel authentication endpoint: %w", err)
		}
		out.BackchannelAuthentication = backchannel
	}
	return out, nil
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

// buildUserinfoURL derives this binary's protected-resource endpoint
// URL ("/userinfo") from issuer, the same way buildEndpoints derives
// the four protocol endpoints. See resource.go's userinfoHandler doc
// comment for why this exists.
func buildUserinfoURL(issuer fapi.URL, allowLoopbackHTTP bool) (fapi.URL, error) {
	var opts []fapi.URLOption
	if allowLoopbackHTTP {
		opts = append(opts, fapi.AllowLoopbackHTTP())
	}
	return fapi.ParseEndpointURL(issuer.String()+"/userinfo", opts...)
}

// buildBackchannelAuthenticationURL derives this binary's CIBA
// backchannel authentication endpoint URL ("/backchannel-authenticate")
// from issuer, the same way buildUserinfoURL derives "/userinfo".
func buildBackchannelAuthenticationURL(issuer fapi.URL, allowLoopbackHTTP bool) (fapi.URL, error) {
	var opts []fapi.URLOption
	if allowLoopbackHTTP {
		opts = append(opts, fapi.AllowLoopbackHTTP())
	}
	return fapi.ParseEndpointURL(issuer.String()+"/backchannel-authenticate", opts...)
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
