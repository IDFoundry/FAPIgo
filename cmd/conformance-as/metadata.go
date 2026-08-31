package main

import (
	"encoding/json"
	"net/http"
	"net/url"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/server"
)

// wireMetadata is server.Metadata (itself directly JSON-marshalable,
// using RFC 8414/OIDC Discovery's own field names) extended with the
// fields server.Metadata doesn't produce: scopes_supported,
// claims_supported, claims_parameter_supported, userinfo_endpoint, and
// dpop_signing_alg_values_supported. DPoP proof verification
// (internal/dpop) checks a proof's own JWS header algorithm against this
// module's whole closed algorithm set, not a configured subset, so that
// one is a fixed list, not sourced from Config.
type wireMetadata struct {
	server.Metadata
	// MTLSEndpointAliases, when set, shadows server.Metadata's own
	// embedded field of the same JSON name — encoding/json resolves a
	// same-named field at shallower struct-nesting depth in favor of a
	// promoted one at greater depth, so this only ever needs setting
	// when there's a userinfo alias to add (see buildMTLSUserinfoURL's
	// own doc comment for why userinfo_endpoint can't just live on
	// server.MTLSEndpoints itself).
	MTLSEndpointAliases           *wireMTLSEndpointAliases `json:"mtls_endpoint_aliases,omitempty"`
	ScopesSupported               []string                 `json:"scopes_supported,omitempty"`
	ClaimsSupported               []string                 `json:"claims_supported,omitempty"`
	ClaimsParameterSupported      bool                     `json:"claims_parameter_supported,omitempty"`
	UserinfoEndpoint              string                   `json:"userinfo_endpoint,omitempty"`
	DPoPSigningAlgValuesSupported []string                 `json:"dpop_signing_alg_values_supported,omitempty"`
}

// wireMTLSEndpointAliases is server.MTLSEndpoints's own advertised
// shape plus the one endpoint alias that package doesn't know about.
type wireMTLSEndpointAliases struct {
	server.MTLSEndpointAliases
	UserinfoEndpoint fapi.URL `json:"userinfo_endpoint,omitempty"`
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

// dpopSigningAlgValuesSupported names every algorithm
// fapi.SignatureAlgorithm's own closed set supports, via each
// constant's own String() rather than a hand-typed literal — Go has no
// way to enumerate iota-based constants at runtime, so this still needs
// updating by hand if that set ever grows, but can no longer silently
// drift from the wire spelling String() itself produces.
var dpopSigningAlgValuesSupported = []string{fapi.ES256.String(), fapi.PS256.String(), fapi.EdDSA.String()}

func metadataHandler(srv *server.Server, advertisedScopes []string, userinfoURL *url.URL, mtlsUserinfoURL *fapi.URL) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		md := srv.Metadata(r.Context())
		doc := wireMetadata{
			Metadata:                      md,
			ScopesSupported:               advertisedScopes,
			ClaimsSupported:               claimsSupported,
			ClaimsParameterSupported:      true,
			UserinfoEndpoint:              userinfoURL.String(),
			DPoPSigningAlgValuesSupported: dpopSigningAlgValuesSupported,
		}
		if md.MTLSEndpointAliases != nil && mtlsUserinfoURL != nil {
			doc.MTLSEndpointAliases = &wireMTLSEndpointAliases{
				MTLSEndpointAliases: *md.MTLSEndpointAliases,
				UserinfoEndpoint:    *mtlsUserinfoURL,
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(doc)
	}
}
