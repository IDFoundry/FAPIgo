// This file adds -profile=federation's own live HTTP(S) listener —
// unlike every other profile this driver runs, which only ever makes
// outbound calls to the suite (the suite's own module code plays both
// the mock AS and, via followAuthorizationRedirect, intercepts the
// authorization redirect itself — see main.go's own package doc
// comment), the federation RP test plan's own suite module fetches our
// RP's Entity Configuration *from* us, live, during the authorization
// and PAR requests it handles (confirmed by reading
// AbstractOpenIDFederationClientTest/OpenIDFederationClientTest's own
// loadClientPublicJwksFromRPMetadata, which unconditionally calls the
// suite's own CallEntityStatementEndpointAndReturnFullResponse — no
// static-config shortcut exists for that particular fetch, unlike what
// the plan's own "server_metadata" variant name might suggest). This
// driver has never needed to accept an inbound connection before.
package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/idfoundry/fapigo/fapitest"
	"github.com/idfoundry/fapigo/federation"
)

// federationRPListenHost is the hostname this driver's own live
// endpoint advertises itself under, and listens for — Docker Desktop's
// well-known DNS name for reaching the host machine from inside a
// container, resolvable by the suite's own dockerized backend
// (conformance-suite-server-1) without this driver needing to join that
// docker-compose network itself. Unlike localhost.emobix.co.uk (this
// repo's other dev-mode convention — conformance/server's own
// scripts), this driver isn't a docker-compose service of its own, so
// there's no network alias to lean on; host.docker.internal is Docker
// Desktop's own built-in equivalent for exactly this direction.
const federationRPListenHost = "host.docker.internal"

// federationRPServer serves this driver's own Entity Configuration at
// federation.WellKnownPath — the one thing the suite's own RP test
// module needs to reach live.
type federationRPServer struct {
	server *http.Server
}

// newFederationRPListener starts listening (TLS already terminated
// here) on an OS-assigned free port on every interface — so the
// suite's own container, reaching in via federationRPListenHost, and
// this process's own later localhost calls both work — and returns it
// unstarted: the caller's own Entity Configuration embeds this port in
// its own entity_id (part of its signed claims), so the listener's
// port must be known *before* that JWT can be built, but nothing should
// accept a connection before the handler that will serve it is ready —
// see serveFederationRPServer, called only once that JWT exists.
func newFederationRPListener() (net.Listener, int, error) {
	cert, err := fapitest.SelfSignedServerCert(federationRPListenHost)
	if err != nil {
		return nil, 0, fmt.Errorf("generate server certificate: %w", err)
	}
	// G102: binding every interface, not just loopback, is deliberate —
	// this driver's own dev-only listener must be reachable from inside
	// the suite's docker-compose network via federationRPListenHost
	// (host.docker.internal), which a loopback-only bind would refuse.
	listener, err := tls.Listen("tcp", "0.0.0.0:0", &tls.Config{ //nolint:gosec
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
	})
	if err != nil {
		return nil, 0, fmt.Errorf("listen: %w", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	return listener, port, nil
}

// serveFederationRPServer starts serving entityConfigurationJWT at
// federation.WellKnownPath over listener (from newFederationRPListener)
// — fixed for the server's whole lifetime, since it's already signed
// with this exact port baked into its own entity_id claim.
func serveFederationRPServer(listener net.Listener, entityConfigurationJWT string) *federationRPServer {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+federation.WellKnownPath, func(w http.ResponseWriter, _ *http.Request) {
		federation.WriteEntityStatement(w, entityConfigurationJWT)
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = srv.Serve(listener) }()
	return &federationRPServer{server: srv}
}

func (s *federationRPServer) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return s.server.Shutdown(ctx)
}
