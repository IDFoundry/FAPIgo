package metadata

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// maxDocumentBytes bounds how large a metadata document this package
// will attempt to parse, so a fetch can't force unbounded parsing work
// before any check has run.
const maxDocumentBytes = 64 * 1024

// Document is an authorization-server metadata document (OAuth 2.0
// Authorization Server Metadata, RFC 8414, extended by OpenID Connect
// Discovery 1.0, PAR (RFC 9126) and JARM fields this module understands).
//
// Unlike a protocol message such as a DPoP proof or an access token,
// this is an IETF-registered *extensible* document — RFC 8414 §2
// explicitly allows additional metadata values — so parsing tolerates
// unrecognized top-level members instead of rejecting them.
type Document struct {
	Issuer                             string `json:"issuer"`
	AuthorizationEndpoint              string `json:"authorization_endpoint"`
	TokenEndpoint                      string `json:"token_endpoint"`
	PushedAuthorizationRequestEndpoint string `json:"pushed_authorization_request_endpoint"`
	JWKSURI                            string `json:"jwks_uri"`

	ResponseTypesSupported        []string `json:"response_types_supported,omitempty"`
	ResponseModesSupported        []string `json:"response_modes_supported,omitempty"`
	GrantTypesSupported           []string `json:"grant_types_supported,omitempty"`
	SubjectTypesSupported         []string `json:"subject_types_supported,omitempty"`
	CodeChallengeMethodsSupported []string `json:"code_challenge_methods_supported,omitempty"`

	TokenEndpointAuthMethodsSupported          []string `json:"token_endpoint_auth_methods_supported,omitempty"`
	TokenEndpointAuthSigningAlgValuesSupported []string `json:"token_endpoint_auth_signing_alg_values_supported,omitempty"`
	RequestObjectSigningAlgValuesSupported     []string `json:"request_object_signing_alg_values_supported,omitempty"`
	IDTokenSigningAlgValuesSupported           []string `json:"id_token_signing_alg_values_supported,omitempty"`

	// AuthorizationSigningAlgValuesSupported advertises which algorithms
	// the server signs JARM authorization responses with.
	AuthorizationSigningAlgValuesSupported []string `json:"authorization_signing_alg_values_supported,omitempty"`

	// IDTokenEncryptionAlgValuesSupported/IDTokenEncryptionEncValuesSupported
	// advertise which key-management ("alg") and content-encryption
	// ("enc") algorithms the server can encrypt an ID token with (OIDC
	// Core §10.2). Both empty means the server never encrypts ID
	// tokens — the common case, and this module's own default.
	IDTokenEncryptionAlgValuesSupported []string `json:"id_token_encryption_alg_values_supported,omitempty"`
	IDTokenEncryptionEncValuesSupported []string `json:"id_token_encryption_enc_values_supported,omitempty"`

	RequirePushedAuthorizationRequests         bool `json:"require_pushed_authorization_requests,omitempty"`
	RequireSignedRequestObject                 bool `json:"require_signed_request_object,omitempty"`
	AuthorizationResponseIssParameterSupported bool `json:"authorization_response_iss_parameter_supported,omitempty"`

	// UserinfoEndpoint is OPTIONAL per OpenID Connect Discovery 1.0 §3 —
	// client.Discover surfaces it as
	// DiscoveredMetadata.Endpoints.UserInfo, ready to use with
	// client.FetchUserInfo, rather than hand-fetching discovery a second
	// time just for this one field.
	UserinfoEndpoint string `json:"userinfo_endpoint,omitempty"`

	// UserinfoSigningAlgValuesSupported/UserinfoEncryptionAlgValuesSupported/
	// UserinfoEncryptionEncValuesSupported mirror the ID-token triple
	// above, for the UserInfo response instead (OIDC Discovery 1.0 §3).
	// All three are OPTIONAL — a server that only ever returns plain
	// JSON UserInfo responses advertises none of them.
	UserinfoSigningAlgValuesSupported    []string `json:"userinfo_signing_alg_values_supported,omitempty"`
	UserinfoEncryptionAlgValuesSupported []string `json:"userinfo_encryption_alg_values_supported,omitempty"`
	UserinfoEncryptionEncValuesSupported []string `json:"userinfo_encryption_enc_values_supported,omitempty"`

	// BackchannelAuthenticationEndpoint, BackchannelTokenDeliveryModesSupported
	// and BackchannelAuthenticationRequestSigningAlgValuesSupported
	// mirror UserinfoEndpoint's own optionality — OPTIONAL per CIBA §5,
	// absent entirely from a server that doesn't support it (most
	// servers). client.Discover surfaces the endpoint as
	// DiscoveredMetadata.Endpoints.BackchannelAuthentication and the
	// algorithm list as DiscoveredMetadata.BackchannelAuthenticationRequestAlgorithms.
	BackchannelAuthenticationEndpoint                         string   `json:"backchannel_authentication_endpoint,omitempty"`
	BackchannelTokenDeliveryModesSupported                    []string `json:"backchannel_token_delivery_modes_supported,omitempty"`
	BackchannelAuthenticationRequestSigningAlgValuesSupported []string `json:"backchannel_authentication_request_signing_alg_values_supported,omitempty"`

	// MTLSEndpointAliases (RFC 8705 §5) is OPTIONAL — absent entirely
	// from a server that never offers an mTLS-requiring alternate
	// listener, the common case. client.Discover surfaces it as
	// DiscoveredMetadata.MTLSEndpointAliases, for a caller building a
	// Config.SenderConstrain == SenderConstrainMTLS client to prefer
	// over the plain Endpoints URLs.
	MTLSEndpointAliases *MTLSEndpointAliases `json:"mtls_endpoint_aliases,omitempty"`
}

// MTLSEndpointAliases is the RFC 8705 §5 "mtls_endpoint_aliases"
// metadata value — the subset of it this module's own flows ever need
// to redirect to an mTLS-requiring alternate URL.
type MTLSEndpointAliases struct {
	TokenEndpoint                      string `json:"token_endpoint,omitempty"`
	PushedAuthorizationRequestEndpoint string `json:"pushed_authorization_request_endpoint,omitempty"`
	BackchannelAuthenticationEndpoint  string `json:"backchannel_authentication_endpoint,omitempty"`
}

// ParseAndValidate parses body as a Document and checks it against
// expectedIssuer: every field every flow this module supports needs
// (issuer, token_endpoint, jwks_uri) is present and non-empty.
// authorization_endpoint and pushed_authorization_request_endpoint are
// checked for presence together, not individually required: a
// CIBA-only authorization server (client.Config's own
// Endpoints.BackchannelAuthentication-only shape) has no browser
// endpoint to advertise at all, so requiring one unconditionally would
// make such a server's own, otherwise-valid document unusable. A
// document advertising only one of the pair is accepted here — client
// itself is where a caller's actual intended flow gets validated
// against what was configured (see client.Config's own
// "Authorization and PushedAuthorizationRequest must both be set, or
// both left zero" pairing rule). And — the check that
// stops a redirected, cached or otherwise substituted discovery response
// from being silently accepted for the wrong authorization server (RFC
// 8414 §3.3, OpenID Connect Discovery 1.0 §4.3) — the document's own
// issuer claim equals expectedIssuer exactly.
func ParseAndValidate(body []byte, expectedIssuer string) (Document, error) {
	if len(body) > maxDocumentBytes {
		return Document{}, ErrTooLarge
	}
	if expectedIssuer == "" {
		return Document{}, fmt.Errorf("metadata: expected issuer is empty")
	}

	dec := json.NewDecoder(bytes.NewReader(body))
	var doc Document
	if err := dec.Decode(&doc); err != nil {
		return Document{}, fmt.Errorf("%w: %v", ErrMalformed, err)
	}

	if doc.Issuer == "" {
		return Document{}, fmt.Errorf("%w: issuer", ErrMissingField)
	}
	if doc.Issuer != expectedIssuer {
		return Document{}, ErrIssuerMismatch
	}
	if doc.TokenEndpoint == "" {
		return Document{}, fmt.Errorf("%w: token_endpoint", ErrMissingField)
	}
	if doc.JWKSURI == "" {
		return Document{}, fmt.Errorf("%w: jwks_uri", ErrMissingField)
	}

	return doc, nil
}
