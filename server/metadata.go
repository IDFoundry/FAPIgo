package server

import (
	"context"

	fapi "github.com/idfoundry/fapigo"
)

// Metadata is this server's OAuth 2.0 Authorization Server Metadata
// (RFC 8414), extended with the OpenID Connect Discovery, PAR (RFC 9126)
// and JARM fields this module actually implements. Every field is
// derived from Config — nothing here is fetched or computed from
// external state — so Metadata never fails and needs no context beyond
// API consistency with this type's other methods.
type Metadata struct {
	Issuer                             fapi.URL
	AuthorizationEndpoint              fapi.URL
	TokenEndpoint                      fapi.URL
	PushedAuthorizationRequestEndpoint fapi.URL
	JWKSURI                            fapi.URL

	ResponseTypesSupported        []string
	ResponseModesSupported        []string
	GrantTypesSupported           []string
	SubjectTypesSupported         []string
	CodeChallengeMethodsSupported []string

	TokenEndpointAuthMethodsSupported          []string
	TokenEndpointAuthSigningAlgValuesSupported []string
	RequestObjectSigningAlgValuesSupported     []string
	IDTokenSigningAlgValuesSupported           []string

	// AuthorizationSigningAlgValuesSupported is set only under
	// ProfileFAPISecurityWithMessageSigning, since that's the only case
	// this server signs authorization responses (JARM) at all.
	AuthorizationSigningAlgValuesSupported []string

	// IDTokenEncryptionAlgValuesSupported/IDTokenEncryptionEncValuesSupported
	// are set only when Config.Algorithms.IDTokenEncryptionKeyManagement/
	// IDTokenEncryptionContentEncryption are non-empty — most servers
	// never encrypt ID tokens, and OIDC Discovery 1.0 §3 leaves both
	// fields optional/absent in that case.
	IDTokenEncryptionAlgValuesSupported []string
	IDTokenEncryptionEncValuesSupported []string

	// RequirePushedAuthorizationRequests is always true: BeginAuthorization
	// only ever accepts a request_uri, never raw authorization parameters.
	RequirePushedAuthorizationRequests bool

	// RequireSignedRequestObject is true only under
	// ProfileFAPISecurityWithMessageSigning; ProfileFAPISecurity accepts
	// a signed request object but does not require one.
	RequireSignedRequestObject bool

	// AuthorizationResponseIssParameterSupported is always true: every
	// non-JARM authorization response this server produces carries an
	// "iss" parameter (RFC 9207); a JARM response's own "iss" claim
	// serves the same purpose instead.
	AuthorizationResponseIssParameterSupported bool
}

// Metadata returns this server's metadata document.
func (s *Server) Metadata(_ context.Context) Metadata {
	md := Metadata{
		Issuer:                             s.cfg.Issuer,
		AuthorizationEndpoint:              s.cfg.Endpoints.Authorization,
		TokenEndpoint:                      s.cfg.Endpoints.Token,
		PushedAuthorizationRequestEndpoint: s.cfg.Endpoints.PushedAuthorizationRequest,
		JWKSURI:                            s.cfg.Endpoints.JWKS,

		ResponseTypesSupported:        []string{"code"},
		GrantTypesSupported:           []string{"authorization_code", "refresh_token"},
		SubjectTypesSupported:         []string{"public"},
		CodeChallengeMethodsSupported: []string{"S256"},

		TokenEndpointAuthMethodsSupported:          []string{"private_key_jwt"},
		TokenEndpointAuthSigningAlgValuesSupported: algorithmSetStrings(s.cfg.Algorithms.ClientAssertion),
		RequestObjectSigningAlgValuesSupported:     algorithmSetStrings(s.cfg.Algorithms.RequestObject),
		IDTokenSigningAlgValuesSupported:           []string{s.cfg.Algorithms.IDToken.String()},

		RequirePushedAuthorizationRequests:         true,
		AuthorizationResponseIssParameterSupported: true,
	}

	if s.cfg.Profile == ProfileFAPISecurityWithMessageSigning {
		md.ResponseModesSupported = []string{"jwt"}
		md.AuthorizationSigningAlgValuesSupported = []string{s.cfg.Algorithms.JARM.String()}
		md.RequireSignedRequestObject = true
	} else {
		md.ResponseModesSupported = []string{"query"}
	}

	if len(s.cfg.Algorithms.IDTokenEncryptionKeyManagement) > 0 {
		md.IDTokenEncryptionAlgValuesSupported = algorithmSetStrings(s.cfg.Algorithms.IDTokenEncryptionKeyManagement)
	}
	if len(s.cfg.Algorithms.IDTokenEncryptionContentEncryption) > 0 {
		md.IDTokenEncryptionEncValuesSupported = algorithmSetStrings(s.cfg.Algorithms.IDTokenEncryptionContentEncryption)
	}

	return md
}

// algorithmString is satisfied by any of this package's closed algorithm
// set element types.
type algorithmString interface {
	String() string
}

func algorithmSetStrings[T algorithmString, S ~[]T](set S) []string {
	out := make([]string, len(set))
	for i, a := range set {
		out[i] = a.String()
	}
	return out
}
