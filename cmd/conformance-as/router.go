package main

import (
	"net/http"
	"net/url"

	fapires "github.com/idfoundry/fapigo/resource"
	"github.com/idfoundry/fapigo/server"
)

// newRouter wires every endpoint server.Server exposes onto a plain
// net/http.ServeMux — no third-party router: this module has zero
// third-party dependencies today and a handful of fixed routes doesn't
// need one. /accounts and /userinfo are not part of server.Server's own
// surface — see resource.go's resourceHandler and userinfoHandler doc
// comments for why they're here.
//
// /accounts is registered without a method prefix (matches any method)
// rather than "GET /accounts": unlike this binary's protocol endpoints,
// it's a stand-in stub with no real API contract of its own, and an
// OIDF suite plan config's resource.resourceMethod is a free-form
// per-run choice — nothing here depends on which method the suite
// picks, so there is no correct single method to require. /userinfo is
// likewise left unprefixed: OIDC Core §5.3 permits both GET and POST.
func newRouter(srv *server.Server, consent *consentHandler, advertisedScopes []string, resourceVerifier *fapires.Verifier, resourceURL *url.URL, userinfoURL *url.URL, identityClaims staticIdentityClaims) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", metadataHandler(srv, advertisedScopes, userinfoURL))
	mux.HandleFunc("GET /jwks", jwksHandler(srv))
	mux.HandleFunc("POST /par", parHandler(srv))
	mux.HandleFunc("GET /authorize", consent.handleBegin)
	mux.HandleFunc("POST /authorize/decision", consent.handleDecision)
	mux.HandleFunc("POST /token", tokenHandler(srv))
	mux.HandleFunc("/accounts", resourceHandler(resourceVerifier, resourceURL))
	mux.HandleFunc("/userinfo", userinfoHandler(resourceVerifier, userinfoURL, identityClaims))
	return mux
}
