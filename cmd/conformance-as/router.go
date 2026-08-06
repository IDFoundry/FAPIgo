package main

import (
	"net/http"

	"github.com/osanderson/go-fapi/server"
)

// newRouter wires every endpoint server.Server exposes onto a plain
// net/http.ServeMux — no third-party router: this module has zero
// third-party dependencies today and a handful of fixed routes doesn't
// need one.
func newRouter(srv *server.Server, consent *consentHandler, advertisedScopes []string) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", metadataHandler(srv, advertisedScopes))
	mux.HandleFunc("GET /jwks", jwksHandler(srv))
	mux.HandleFunc("POST /par", parHandler(srv))
	mux.HandleFunc("GET /authorize", consent.handleBegin)
	mux.HandleFunc("POST /authorize/decision", consent.handleDecision)
	mux.HandleFunc("POST /token", tokenHandler(srv))
	return mux
}
