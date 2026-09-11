package main

import (
	"encoding/json"
	"net/http"
	"net/url"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/federation"
	"github.com/idfoundry/fapigo/server"
)

// federationOpenIDProviderMetadata is buildWireMetadata's own document
// (the same one served at /.well-known/openid-configuration), extended
// with client_registration_types_supported — required by OpenID
// Federation 1.0 §12.1 on any OP that supports Automatic Registration,
// and not otherwise part of OIDC Discovery, so it's added only here,
// never on the plain discovery document.
type federationOpenIDProviderMetadata struct {
	wireMetadata
	ClientRegistrationTypesSupported []string `json:"client_registration_types_supported"`
}

// wellKnownFederationHandler serves this AS's own self-issued Entity
// Configuration (OpenID Federation 1.0 §3.1/§9) at
// /.well-known/openid-federation — buildWireMetadata's own document,
// carried as this statement's "openid_provider" Entity Type metadata,
// signed with the federation identity key Config.Federation configures
// (see wiring.go's own federationSigningAlgorithm/keys.FederationEntitySigning).
// Only registered at all when Config.Federation is set (router.go).
func wellKnownFederationHandler(srv *server.Server, advertisedScopes []string, userinfoURL *url.URL, mtlsUserinfoURL *fapi.URL) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		doc := federationOpenIDProviderMetadata{
			wireMetadata:                     buildWireMetadata(srv, ctx, advertisedScopes, userinfoURL, mtlsUserinfoURL),
			ClientRegistrationTypesSupported: []string{"automatic"},
		}
		opMetadata, err := json.Marshal(doc)
		if err != nil {
			http.Error(w, "server_error", http.StatusInternalServerError)
			return
		}
		token, err := srv.EntityConfiguration(ctx, map[string]json.RawMessage{
			"openid_provider": opMetadata,
		})
		if err != nil {
			http.Error(w, "server_error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", federation.EntityStatementContentType)
		_, _ = w.Write([]byte(token))
	}
}
