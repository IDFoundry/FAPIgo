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
}

// ParseAndValidate parses body as a Document and checks it against
// expectedIssuer: every field this module requires (issuer,
// authorization_endpoint, token_endpoint, pushed_authorization_request_endpoint,
// jwks_uri — this module only ever drives a PAR-based flow, so a
// document missing a PAR endpoint is not usable regardless of what RFC
// 8414 itself requires) is present and non-empty, and — the check that
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
	if doc.AuthorizationEndpoint == "" {
		return Document{}, fmt.Errorf("%w: authorization_endpoint", ErrMissingField)
	}
	if doc.TokenEndpoint == "" {
		return Document{}, fmt.Errorf("%w: token_endpoint", ErrMissingField)
	}
	if doc.PushedAuthorizationRequestEndpoint == "" {
		return Document{}, fmt.Errorf("%w: pushed_authorization_request_endpoint", ErrMissingField)
	}
	if doc.JWKSURI == "" {
		return Document{}, fmt.Errorf("%w: jwks_uri", ErrMissingField)
	}

	return doc, nil
}
