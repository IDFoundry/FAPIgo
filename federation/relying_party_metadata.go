package federation

import "encoding/json"

// OpenIDRelyingPartyMetadata is the "openid_relying_party" Entity Type's
// metadata (OpenID Federation 1.0 §5.2: every parameter defined by
// OpenID Connect Dynamic Client Registration 1.0 §2 is applicable, plus
// this spec's own client_registration_types) — a caller's own declared
// client metadata, ready to embed under that key in
// SelfIssuer.EntityConfiguration's own metadata map.
//
// A plain, caller-filled struct: unlike server.Metadata (entirely
// derived from server.Config by Server.Metadata), this package has no
// owning type to auto-derive it from — an RP's own redirect_uris,
// response_types, and client_registration_types are business decisions
// this package has no way to infer. What this type buys a caller is
// still real: field names and JSON tags that can't be misspelled or
// silently mismatched against the spec, in a codebase where getting
// this exact metadata wrong has already caused one confirmed,
// hard-to-diagnose interoperability failure — the OIDF conformance
// suite's own structurally identical RP-metadata builder
// (AddOpenIDRelyingPartyMetadataToEntityConfiguration.java) never sets
// TokenEndpointAuthMethod at all, which FAPIgo's own PAR endpoint
// correctly refuses to auto-register a client without (no implicit
// client_secret_basic default — FAPI 2.0's own prohibition; see PR
// #319/#320's own investigation).
//
// Every field is optional (omitempty) — this type performs no
// validation of its own, matching a spec where most of these fields are
// RECOMMENDED or OPTIONAL rather than REQUIRED, and where "required for
// my deployment" varies by which registration type, client
// authentication method, and signing algorithms a specific RP actually
// uses. JWKS and JWKSURI are mutually exclusive, like every other
// jwks/jwks_uri pair this module models (server.Metadata's own
// JWKSURI, intfed's own subordinate/entity statement "jwks" claim): set
// at most one.
//
// An OP built on AutomaticClientRepository needs more than "optional"
// suggests, though: RedirectURIs; at least one client authentication
// method, via TokenEndpointAuthMethod and/or
// TokenEndpointAuthMethodsSupported (OpenID Federation 1.0 §12.1.4 — a
// FAPIgo OP accepts any of them the RP then uses); exactly one of JWKS
// or JWKSURI (SignedJWKSURI alone isn't read); and whatever each method
// depends on — an "x5c" certificate in the key set for
// self_signed_tls_client_auth, the matching tls_client_auth_* parameter
// for tls_client_auth and its SAN variants (not modelled here; add it to
// the metadata JSON directly), and for private_key_jwt either a signing
// algorithm or an OP that defaults to its own (a FAPIgo OP does). A
// method only listed that its metadata can't support is skipped; if none
// is usable, automatic registration fails — the RP only ever sees
// invalid_client, and the OP's operator sees the reason through
// AutomaticRegistrationConfig.OnResolutionFailure.
type OpenIDRelyingPartyMetadata struct {
	// ClientRegistrationTypes is RECOMMENDED (OpenID Federation 1.0
	// §5.2) — "automatic" and/or "explicit", or a federation-specific
	// extension value. Declare "automatic" to register automatically
	// (§12.1); AutomaticClientRepository doesn't itself check it.
	ClientRegistrationTypes []string `json:"client_registration_types,omitempty"`

	RedirectURIs  []string `json:"redirect_uris,omitempty"`
	ResponseTypes []string `json:"response_types,omitempty"`
	GrantTypes    []string `json:"grant_types,omitempty"`

	// ApplicationType is OpenID Connect Dynamic Client Registration
	// 1.0 §2's own "web" or "native" — OPTIONAL, "web" if omitted.
	// Automatic registration doesn't act on it: an RP's own claim to be a
	// native app, which would admit private-use and loopback redirect
	// URIs, isn't one to take from its self-published metadata, so every
	// automatically registered client is storage.ApplicationTypeWeb.
	ApplicationType string `json:"application_type,omitempty"`

	// TokenEndpointAuthMethod is this RP's own declared client
	// authentication method at the token endpoint (and PAR, where
	// applicable) — see this type's own doc comment for why leaving it
	// unset is a real, previously-confirmed interoperability failure,
	// not just an incomplete declaration.
	TokenEndpointAuthMethod string `json:"token_endpoint_auth_method,omitempty"`

	// TokenEndpointAuthSigningAlg is the JWS algorithm this RP signs its
	// private_key_jwt client assertions with (e.g. fapi.ES256.String()).
	// When set, it's the only one an OP accepts from this RP. Optional:
	// Dynamic Client Registration's default is any algorithm the OP and
	// RP both support (a FAPIgo OP uses its own allowed set).
	TokenEndpointAuthSigningAlg string `json:"token_endpoint_auth_signing_alg,omitempty"`

	// TokenEndpointAuthMethodsSupported and
	// TokenEndpointAuthSigningAlgValuesSupported are OpenID Connect RP
	// Metadata Choices 1.0's lists of every client authentication method
	// and assertion signing algorithm this RP supports — an OP may then
	// accept any of them. TokenEndpointAuthMethod and
	// TokenEndpointAuthSigningAlg, when also set, must be among them.
	TokenEndpointAuthMethodsSupported          []string `json:"token_endpoint_auth_methods_supported,omitempty"`
	TokenEndpointAuthSigningAlgValuesSupported []string `json:"token_endpoint_auth_signing_alg_values_supported,omitempty"`

	// JWKS is this RP's own operational key set (client authentication,
	// request-object signing, ...) — set directly, or via JWKSURI
	// below, never both.
	JWKS    json.RawMessage `json:"jwks,omitempty"`
	JWKSURI string          `json:"jwks_uri,omitempty"`

	// SignedJWKSURI is OpenID Federation 1.0's own extension (common
	// across every role's metadata) — a JWKS served as a signed JWT
	// instead of plain JSON, for a caller whose deployment already has
	// a federation signing key it would rather reuse for this too.
	SignedJWKSURI string `json:"signed_jwks_uri,omitempty"`

	IDTokenSignedResponseAlg string `json:"id_token_signed_response_alg,omitempty"`
	RequestObjectSigningAlg  string `json:"request_object_signing_alg,omitempty"`

	// ClientName, LogoURI, PolicyURI and TOSURI are what an OP's
	// consent screen shows about this RP (storage.ClientDisplay). Keep
	// ClientName to storage.MaxClientNameBytes with no control
	// characters, and the URIs https: AutomaticClientRepository refuses
	// the registration otherwise.
	OrganizationName string   `json:"organization_name,omitempty"`
	ClientName       string   `json:"client_name,omitempty"`
	LogoURI          string   `json:"logo_uri,omitempty"`
	PolicyURI        string   `json:"policy_uri,omitempty"`
	TOSURI           string   `json:"tos_uri,omitempty"`
	Contacts         []string `json:"contacts,omitempty"`
}
