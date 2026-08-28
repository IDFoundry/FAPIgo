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
//
// Metadata is directly JSON-marshalable, using RFC 8414/OIDC Discovery's
// own snake_case field names. It deliberately doesn't cover every
// metadata field a real deployment may need to advertise (e.g.
// userinfo_endpoint, scopes_supported, claims_supported — this package
// doesn't implement a UserInfo endpoint or know an embedder's supported
// scopes/claims, see identity_claims.go), so an embedder that needs more
// should embed Metadata in its own struct and add those fields there;
// json.Marshal on the outer struct then produces one combined document.
type Metadata struct {
	Issuer                             fapi.URL `json:"issuer"`
	AuthorizationEndpoint              fapi.URL `json:"authorization_endpoint"`
	TokenEndpoint                      fapi.URL `json:"token_endpoint"`
	PushedAuthorizationRequestEndpoint fapi.URL `json:"pushed_authorization_request_endpoint"`
	JWKSURI                            fapi.URL `json:"jwks_uri"`

	ResponseTypesSupported        []string `json:"response_types_supported,omitempty"`
	ResponseModesSupported        []string `json:"response_modes_supported,omitempty"`
	GrantTypesSupported           []string `json:"grant_types_supported,omitempty"`
	SubjectTypesSupported         []string `json:"subject_types_supported,omitempty"`
	CodeChallengeMethodsSupported []string `json:"code_challenge_methods_supported,omitempty"`

	TokenEndpointAuthMethodsSupported          []string `json:"token_endpoint_auth_methods_supported,omitempty"`
	TokenEndpointAuthSigningAlgValuesSupported []string `json:"token_endpoint_auth_signing_alg_values_supported,omitempty"`
	RequestObjectSigningAlgValuesSupported     []string `json:"request_object_signing_alg_values_supported,omitempty"`
	IDTokenSigningAlgValuesSupported           []string `json:"id_token_signing_alg_values_supported,omitempty"`

	// AuthorizationSigningAlgValuesSupported is set only under
	// ProfileFAPISecurityWithMessageSigning, since that's the only case
	// this server signs authorization responses (JARM) at all.
	AuthorizationSigningAlgValuesSupported []string `json:"authorization_signing_alg_values_supported,omitempty"`

	// IDTokenEncryptionAlgValuesSupported/IDTokenEncryptionEncValuesSupported
	// are set only when Config.Algorithms.IDTokenEncryptionKeyManagement/
	// IDTokenEncryptionContentEncryption are non-empty — most servers
	// never encrypt ID tokens, and OIDC Discovery 1.0 §3 leaves both
	// fields optional/absent in that case.
	IDTokenEncryptionAlgValuesSupported []string `json:"id_token_encryption_alg_values_supported,omitempty"`
	IDTokenEncryptionEncValuesSupported []string `json:"id_token_encryption_enc_values_supported,omitempty"`

	// UserinfoSigningAlgValuesSupported/UserinfoEncryptionAlgValuesSupported/
	// UserinfoEncryptionEncValuesSupported mirror the ID-token triple
	// above, for the UserInfo response instead (OIDC Discovery 1.0 §3).
	// Set only when the corresponding Config.Algorithms.UserInfo* field
	// is configured — most servers never sign or encrypt UserInfo
	// responses, and OIDC Discovery leaves all three optional/absent in
	// that case. Unlike the URL of the UserInfo endpoint itself, these
	// are this server's own algorithm capabilities, so Metadata does
	// carry them even though it doesn't implement the endpoint.
	UserinfoSigningAlgValuesSupported    []string `json:"userinfo_signing_alg_values_supported,omitempty"`
	UserinfoEncryptionAlgValuesSupported []string `json:"userinfo_encryption_alg_values_supported,omitempty"`
	UserinfoEncryptionEncValuesSupported []string `json:"userinfo_encryption_enc_values_supported,omitempty"`

	// BackchannelAuthenticationEndpoint, BackchannelTokenDeliveryModesSupported
	// and BackchannelAuthenticationRequestSigningAlgValuesSupported are
	// set only when Config.Endpoints.BackchannelAuthentication is
	// configured — CIBA is an entirely optional capability. Unlike
	// userinfo_endpoint (omitted because this package never implements a
	// UserInfo handler), BackchannelAuthenticationEndpoint is a real
	// field here because this package does implement the backchannel
	// authentication endpoint itself (BeginBackchannelAuthentication).
	BackchannelAuthenticationEndpoint                         fapi.URL `json:"backchannel_authentication_endpoint,omitempty"`
	BackchannelTokenDeliveryModesSupported                    []string `json:"backchannel_token_delivery_modes_supported,omitempty"`
	BackchannelAuthenticationRequestSigningAlgValuesSupported []string `json:"backchannel_authentication_request_signing_alg_values_supported,omitempty"`

	// RequirePushedAuthorizationRequests is always true: BeginAuthorization
	// only ever accepts a request_uri, never raw authorization parameters.
	RequirePushedAuthorizationRequests bool `json:"require_pushed_authorization_requests,omitempty"`

	// RequireSignedRequestObject is true only under
	// ProfileFAPISecurityWithMessageSigning; ProfileFAPISecurity accepts
	// a signed request object but does not require one.
	RequireSignedRequestObject bool `json:"require_signed_request_object,omitempty"`

	// AuthorizationResponseIssParameterSupported is always true: every
	// non-JARM authorization response this server produces carries an
	// "iss" parameter (RFC 9207); a JARM response's own "iss" claim
	// serves the same purpose instead.
	AuthorizationResponseIssParameterSupported bool `json:"authorization_response_iss_parameter_supported,omitempty"`
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
	if s.cfg.Algorithms.UserInfo != 0 {
		md.UserinfoSigningAlgValuesSupported = []string{s.cfg.Algorithms.UserInfo.String()}
	}
	if len(s.cfg.Algorithms.UserInfoEncryptionKeyManagement) > 0 {
		md.UserinfoEncryptionAlgValuesSupported = algorithmSetStrings(s.cfg.Algorithms.UserInfoEncryptionKeyManagement)
	}
	if len(s.cfg.Algorithms.UserInfoEncryptionContentEncryption) > 0 {
		md.UserinfoEncryptionEncValuesSupported = algorithmSetStrings(s.cfg.Algorithms.UserInfoEncryptionContentEncryption)
	}
	if !s.cfg.Endpoints.BackchannelAuthentication.IsZero() {
		md.BackchannelAuthenticationEndpoint = s.cfg.Endpoints.BackchannelAuthentication
		// Poll only — ping mode's notification dispatch is a separate,
		// not-yet-implemented capability (see Dependencies doc comment).
		md.BackchannelTokenDeliveryModesSupported = []string{"poll"}
		md.BackchannelAuthenticationRequestSigningAlgValuesSupported = algorithmSetStrings(s.cfg.Algorithms.BackchannelAuthenticationRequest)
		md.GrantTypesSupported = append(md.GrantTypesSupported, CIBAGrantType)
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
