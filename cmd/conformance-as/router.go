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
// need one. /userinfo is not part of server.Server's own surface — see
// resource.go's userinfoHandler doc comment for why it's here (both as
// the OIDC UserInfo endpoint and as the generic protected resource an
// OIDF suite plan config's resource.resourceUrl points at).
//
// /userinfo is registered without a method prefix (matches any method)
// rather than "GET /userinfo": OIDC Core §5.3 permits both GET and
// POST, and an OIDF suite plan config's resource.resourceMethod is a
// free-form per-run choice for the generic-resource role this endpoint
// also plays — nothing here depends on which method the suite picks.
func newRouter(srv *server.Server, consent *consentHandler, advertisedScopes []string, resourceVerifier *fapires.Verifier, userinfoURL *url.URL, identityClaims staticIdentityClaims) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", metadataHandler(srv, advertisedScopes, userinfoURL))
	mux.HandleFunc("GET /jwks", jwksHandler(srv))
	mux.HandleFunc("POST /par", parHandler(srv))
	mux.HandleFunc("GET /authorize", consent.handleBegin)
	mux.HandleFunc("POST /authorize/decision", consent.handleDecision)
	mux.HandleFunc("POST /token", tokenHandler(srv))
	mux.HandleFunc("/userinfo", userinfoHandler(resourceVerifier, userinfoURL, identityClaims))
	return mux
}
