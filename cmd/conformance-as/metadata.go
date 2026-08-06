package main

import (
	"encoding/json"
	"net/http"

	"github.com/osanderson/go-fapi/internal/metadata"
	"github.com/osanderson/go-fapi/server"
)

// wireMetadata is server.Metadata converted to internal/metadata.Document's
// wire shape (the same tested encoder fapitest relies on), extended with
// the fields server.Metadata doesn't produce: scopes_supported,
// claims_supported, and dpop_signing_alg_values_supported. DPoP proof
// verification (internal/dpop) checks a proof's own JWS header algorithm
// against this module's whole closed algorithm set, not a configured
// subset, so this is a fixed list, not sourced from Config.
type wireMetadata struct {
	metadata.Document
	ScopesSupported               []string `json:"scopes_supported,omitempty"`
	ClaimsSupported               []string `json:"claims_supported,omitempty"`
	DPoPSigningAlgValuesSupported []string `json:"dpop_signing_alg_values_supported,omitempty"`
}

var claimsSupported = []string{"sub", "aud", "exp", "iat", "iss", "nonce", "auth_time", "acr", "amr"}

var dpopSigningAlgValuesSupported = []string{"ES256", "PS256"}

func metadataHandler(srv *server.Server, advertisedScopes []string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		md := srv.Metadata(r.Context())
		doc := wireMetadata{
			Document: metadata.Document{
				Issuer:                                     md.Issuer.String(),
				AuthorizationEndpoint:                      md.AuthorizationEndpoint.String(),
				TokenEndpoint:                              md.TokenEndpoint.String(),
				PushedAuthorizationRequestEndpoint:         md.PushedAuthorizationRequestEndpoint.String(),
				JWKSURI:                                    md.JWKSURI.String(),
				ResponseTypesSupported:                     md.ResponseTypesSupported,
				ResponseModesSupported:                     md.ResponseModesSupported,
				GrantTypesSupported:                        md.GrantTypesSupported,
				SubjectTypesSupported:                      md.SubjectTypesSupported,
				CodeChallengeMethodsSupported:              md.CodeChallengeMethodsSupported,
				TokenEndpointAuthMethodsSupported:          md.TokenEndpointAuthMethodsSupported,
				TokenEndpointAuthSigningAlgValuesSupported: md.TokenEndpointAuthSigningAlgValuesSupported,
				RequestObjectSigningAlgValuesSupported:     md.RequestObjectSigningAlgValuesSupported,
				IDTokenSigningAlgValuesSupported:           md.IDTokenSigningAlgValuesSupported,
				AuthorizationSigningAlgValuesSupported:     md.AuthorizationSigningAlgValuesSupported,
				RequirePushedAuthorizationRequests:         md.RequirePushedAuthorizationRequests,
				RequireSignedRequestObject:                 md.RequireSignedRequestObject,
				AuthorizationResponseIssParameterSupported: md.AuthorizationResponseIssParameterSupported,
			},
			ScopesSupported:               advertisedScopes,
			ClaimsSupported:               claimsSupported,
			DPoPSigningAlgValuesSupported: dpopSigningAlgValuesSupported,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(doc)
	}
}
