package main

import (
	"encoding/json"
	"net/http"
	"net/url"

	"github.com/idfoundry/fapigo/internal/metadata"
	"github.com/idfoundry/fapigo/server"
)

// wireMetadata is server.Metadata converted to internal/metadata.Document's
// wire shape (the same tested encoder fapitest relies on), extended with
// the fields server.Metadata doesn't produce: scopes_supported,
// claims_supported, claims_parameter_supported, userinfo_endpoint, and
// dpop_signing_alg_values_supported. DPoP proof verification
// (internal/dpop) checks a proof's own JWS header algorithm against this
// module's whole closed algorithm set, not a configured subset, so that
// one is a fixed list, not sourced from Config.
type wireMetadata struct {
	metadata.Document
	ScopesSupported               []string `json:"scopes_supported,omitempty"`
	ClaimsSupported               []string `json:"claims_supported,omitempty"`
	ClaimsParameterSupported      bool     `json:"claims_parameter_supported,omitempty"`
	UserinfoEndpoint              string   `json:"userinfo_endpoint,omitempty"`
	DPoPSigningAlgValuesSupported []string `json:"dpop_signing_alg_values_supported,omitempty"`
}

// claimsSupported is the protocol claims every ID token carries
// (RFC 6749/OIDC Core mechanics), plus identityClaimNames — the OIDC
// Core §5.1 standard claims this binary actually has values for (see
// identity_claims.go's staticIdentityClaims). Advertising a name here
// without ResolveIdentityClaims returning a value for it would make
// fapi2-security-profile-final-test-claims-parameter-identity-claims
// warn that the claim went unreturned, so the two must stay in sync.
var claimsSupported = append(
	[]string{"sub", "aud", "exp", "iat", "iss", "nonce", "auth_time", "acr", "amr"},
	identityClaimNames...,
)

var dpopSigningAlgValuesSupported = []string{"ES256", "PS256"}

func metadataHandler(srv *server.Server, advertisedScopes []string, userinfoURL *url.URL) http.HandlerFunc {
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
				IDTokenEncryptionAlgValuesSupported:        md.IDTokenEncryptionAlgValuesSupported,
				IDTokenEncryptionEncValuesSupported:        md.IDTokenEncryptionEncValuesSupported,
				RequirePushedAuthorizationRequests:         md.RequirePushedAuthorizationRequests,
				RequireSignedRequestObject:                 md.RequireSignedRequestObject,
				AuthorizationResponseIssParameterSupported: md.AuthorizationResponseIssParameterSupported,
			},
			ScopesSupported:               advertisedScopes,
			ClaimsSupported:               claimsSupported,
			ClaimsParameterSupported:      true,
			UserinfoEndpoint:              userinfoURL.String(),
			DPoPSigningAlgValuesSupported: dpopSigningAlgValuesSupported,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(doc)
	}
}
