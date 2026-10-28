package client

import (
	"errors"
	"fmt"
	"net/url"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/federation"
	"github.com/idfoundry/fapigo/internal/depcheck"
	"github.com/idfoundry/fapigo/internal/nofollow"
	"github.com/idfoundry/fapigo/storage"
)

// Client is a FAPI 2.0 relying-party engine. It is entirely unexported —
// construct one with New.
type Client struct {
	cfg  Config
	deps Dependencies

	// challenge is the most recent attestation Challenge the
	// authorization server provided (see ChallengeSource).
	challenge *latestChallenge
}

// New validates cfg and deps and returns a Client. Construction fails
// unless every configuration value and dependency cfg requires — for
// its Profile, the flows its Endpoints enable, its ClientAuthMethod and
// SenderConstrain, and its Assurance level — is present and valid.
//
// New also resolves each key of the client's own cfg calls for — the
// client authentication, attestation PoP, DPoP, request object, CIBA
// request and federation signing keys from deps.Keys, and the ID token
// and UserInfo decryption keys from deps.Decryption — so a missing
// purpose or a key that doesn't suit the configured algorithm fails
// here rather than at the first request needing it. A KeyManager or
// Decrypter backed by a remote KMS is asked over the network: New
// allows that 10 seconds.
func New(cfg Config, deps Dependencies) (*Client, error) {
	if err := validateConfig(cfg); err != nil {
		return nil, err
	}
	if err := validateDependencies(cfg, deps); err != nil {
		return nil, err
	}
	if err := checkOwnKeys(cfg, deps); err != nil {
		return nil, err
	}
	deps.HTTP = nofollow.Client(deps.HTTP)
	if deps.DPoPNonceCache == nil {
		// RFC 9449 §8.2: the client "MUST use the new nonce value
		// supplied for the next token request".
		deps.DPoPNonceCache = NewInMemoryDPoPNonceCache()
	}
	return &Client{cfg: cfg, deps: deps, challenge: &latestChallenge{}}, nil
}

// NewFromDiscovery is New, with cfg completed and cross-checked from
// discovered:
//
//  1. cfg.Issuer, if zero, is set to discovered.Issuer(); if set, it
//     must equal it. A client pairing one issuer's metadata with another
//     issuer's identifier would send its requests to one server while
//     validating tokens as if from the other — easy to do by accident in
//     a relying party talking to several issuers.
//  2. cfg.Endpoints, if entirely zero, is set to discovered.Endpoints —
//     without the authorization and pushed authorization request
//     endpoints when cfg.RedirectURI is empty, since a client with no
//     redirect URI (one using only CIBA or client credentials) never
//     uses the redirect-based flow. A client that does mutual TLS gets
//     the server's mtls_endpoint_aliases (RFC 8705 §5) where it does:
//     discovered.MTLSEndpointAliases.ApplyForClientAuth when it
//     authenticates with its certificate, ApplyForSenderConstrain when
//     its tokens are only bound to it. Set Endpoints yourself instead
//     when you need to adjust it first, and it's left as given.
//  3. It checks that the issuer advertises support for every algorithm
//     cfg declares (discovered.SupportsAlgorithms), turning a
//     declared-but-unadvertised algorithm into a startup error rather
//     than a signature or JWE failure at first use.
//  4. It sets cfg.AuthorizationResponseIssPolicy to
//     RequireAuthorizationResponseIss when
//     discovered.AuthorizationResponseIssSupported is — RFC 9207 §2.4
//     MUST-rejects a callback missing "iss" once the issuer is known to
//     always send one. It only ever raises the enforcement bar, never
//     lowers a value the caller explicitly set; plain New still requires
//     the caller to set this field, since there is no default.
//
// A DiscoveredMetadata assembled by hand (Issuer() zero) skips step 1:
// cfg.Issuer must then be set, exactly as for New.
func NewFromDiscovery(discovered DiscoveredMetadata, cfg Config, deps Dependencies) (*Client, error) {
	if iss := discovered.Issuer(); !iss.IsZero() {
		switch {
		case cfg.Issuer.IsZero():
			cfg.Issuer = iss
		case cfg.Issuer.String() != iss.String():
			return nil, fmt.Errorf("client: config: issuer %q doesn't match the discovered issuer %q", cfg.Issuer.String(), iss.String())
		}
	}
	if cfg.Endpoints.isZero() {
		cfg.Endpoints = discovered.Endpoints
		if cfg.RedirectURI == "" {
			cfg.Endpoints.Authorization, cfg.Endpoints.PushedAuthorizationRequest = fapi.URL{}, fapi.URL{}
		}
		switch {
		case authenticatesWithCertificate(cfg.ClientAuthMethod):
			discovered.MTLSEndpointAliases.ApplyForClientAuth(&cfg.Endpoints)
		case cfg.SenderConstrain == storage.SenderConstrainMTLS:
			discovered.MTLSEndpointAliases.ApplyForSenderConstrain(&cfg.Endpoints)
		}
		if cfg.RedirectURI == "" {
			cfg.Endpoints.PushedAuthorizationRequest = fapi.URL{}
		}
	}
	if err := discovered.SupportsAlgorithms(cfg.Algorithms); err != nil {
		return nil, err
	}
	if discovered.AuthorizationResponseIssSupported {
		cfg.AuthorizationResponseIssPolicy = RequireAuthorizationResponseIss
	}
	return New(cfg, deps)
}

// validateConfig checks cfg as a whole. Each thematic group of checks
// is split into its own function purely to keep this dispatcher's own
// cognitive complexity manageable — the checks, their order and their
// error messages are unchanged.
func validateConfig(cfg Config) error {
	// Authorization and PushedAuthorizationRequest declare browser-flow
	// support as one coherent capability — required together, not
	// independently optional, mirroring the
	// IDTokenKeyManagement/IDTokenContentEncryption pairing below. A
	// CIBA-only client (Endpoints.BackchannelAuthentication set
	// instead) has no browser flow at all, so leaving both zero is
	// valid — and so is a client_credentials-only client with neither
	// the browser flow nor CIBA configured (RequestClientCredentialsToken
	// needs nothing beyond Endpoints.Token, already required above), so
	// unlike an earlier version of this check, there is no longer a
	// blanket "at least one flow must be configured" requirement here.
	authorizationFlowConfigured := !cfg.Endpoints.Authorization.IsZero()
	parConfigured := !cfg.Endpoints.PushedAuthorizationRequest.IsZero()
	cibaConfigured := !cfg.Endpoints.BackchannelAuthentication.IsZero()

	if err := validateRequiredConfig(cfg); err != nil {
		return err
	}
	if err := validateProductionURLs(cfg); err != nil {
		return err
	}
	if authorizationFlowConfigured != parConfigured {
		return fmt.Errorf("client: config: endpoints.authorization and endpoints.pushed_authorization_request must both be set, or both left zero")
	}
	// RedirectURI only means anything to the browser flow — BeginAuthorization
	// is the only place this module ever sends it.
	if authorizationFlowConfigured && cfg.RedirectURI == "" {
		return fmt.Errorf("client: config: redirect_uri is required when endpoints.authorization is set")
	}
	if err := validateRedirectURI(cfg); err != nil {
		return err
	}
	if err := validateEnumFields(cfg); err != nil {
		return err
	}
	if err := validateAuthMethodAlgorithms(cfg); err != nil {
		return err
	}
	// Only the browser flow and CIBA can ever return an ID token —
	// RequestClientCredentialsToken never does (RFC 6749 §4.4 has no end
	// user), so a client_credentials-only config has no use for this
	// algorithm at all and shouldn't be forced to set one.
	if idTokensPossible(cfg) && !cfg.Algorithms.IDToken.IsValid() {
		return fmt.Errorf("client: config: algorithms.id_token is required when endpoints.authorization or endpoints.backchannel_authentication is set, unless oauth_only is set")
	}
	if cfg.OAuthOnly && (cfg.Algorithms.IDTokenKeyManagement != 0 || cfg.Algorithms.IDTokenContentEncryption != 0) {
		return fmt.Errorf("client: config: algorithms.id_token_key_management/id_token_content_encryption must not be set when oauth_only is set")
	}
	if err := validateIDTokenEncryptionFields(cfg); err != nil {
		return err
	}
	if err := validateUserInfoConfig(cfg); err != nil {
		return err
	}
	if err := validateClientLimits(cfg); err != nil {
		return err
	}
	if err := validateMessageSigningProfile(cfg); err != nil {
		return err
	}
	if err := validateCIBAConfig(cfg, cibaConfigured); err != nil {
		return err
	}
	return validateFederationConfig(cfg)
}

func validateRequiredConfig(cfg Config) error {
	if cfg.Issuer.IsZero() {
		return fmt.Errorf("client: config: issuer is required")
	}
	if cfg.ClientID == "" {
		return fmt.Errorf("client: config: client ID is required")
	}
	if cfg.Endpoints.Token.IsZero() {
		return fmt.Errorf("client: config: endpoints.token is required")
	}
	if cfg.Assurance != AssuranceDevelopment && cfg.Assurance != AssuranceProduction {
		return fmt.Errorf("client: config: assurance is invalid")
	}
	return nil
}

// validateProductionURLs refuses, under AssuranceProduction, an issuer
// or endpoint parsed with fapi.AllowLoopbackHTTP: see
// checkProductionScheme. RedirectURI is not checked: a native app's
// loopback redirect (RFC 8252 §7.3) is http by definition and
// legitimate in production.
func validateProductionURLs(cfg Config) error {
	urls := []struct {
		name string
		u    fapi.URL
	}{
		{"issuer", cfg.Issuer},
		{"endpoints.authorization", cfg.Endpoints.Authorization},
		{"endpoints.token", cfg.Endpoints.Token},
		{"endpoints.pushed_authorization_request", cfg.Endpoints.PushedAuthorizationRequest},
		{"endpoints.userinfo", cfg.Endpoints.UserInfo},
		{"endpoints.backchannel_authentication", cfg.Endpoints.BackchannelAuthentication},
		{"endpoints.revocation", cfg.Endpoints.Revocation},
	}
	for _, e := range urls {
		if err := checkProductionScheme(cfg.Assurance, "config: "+e.name, e.u.URL()); err != nil {
			return err
		}
	}
	return nil
}

// checkProductionScheme is this client's rule for plain http, which
// fapi.AllowLoopbackHTTP permits only to a loopback host: a development
// convenience, refused under AssuranceProduction, the same rule
// server.New applies to its own issuer and endpoints. name identifies
// the URL in the error. An unset URL has no scheme and passes.
func checkProductionScheme(assurance AssuranceLevel, name string, u url.URL) error {
	if assurance == AssuranceProduction && u.Scheme == "http" {
		return fmt.Errorf("client: %s was parsed with fapi.AllowLoopbackHTTP, which is not permitted under AssuranceProduction", name)
	}
	return nil
}

func validateEnumFields(cfg Config) error {
	if cfg.Profile != ProfileFAPISecurity && cfg.Profile != ProfileFAPISecurityWithMessageSigning {
		return fmt.Errorf("client: config: profile is invalid")
	}
	if cfg.PARDPoPBinding != PARDPoPBindingProof && cfg.PARDPoPBinding != PARDPoPBindingJKT {
		return fmt.Errorf("client: config: par_dpop_binding is invalid")
	}
	if cfg.PushedRequestEncoding != PushedRequestEncodingProfileDefault && cfg.PushedRequestEncoding != PushedRequestEncodingRequestObject {
		return fmt.Errorf("client: config: pushed_request_encoding is invalid")
	}
	if cfg.AuthorizationResponseIssPolicy != RequireAuthorizationResponseIss && cfg.AuthorizationResponseIssPolicy != TolerateAbsentAuthorizationResponseIss {
		return fmt.Errorf("client: config: authorization_response_iss_policy is required (RequireAuthorizationResponseIss or TolerateAbsentAuthorizationResponseIss)")
	}
	if cfg.Assurance == AssuranceProduction && cfg.AuthorizationResponseIssPolicy == TolerateAbsentAuthorizationResponseIss {
		// FAPI 2.0 Security Profile §5.3.2.2 item 7 has the
		// authorization server send iss (RFC 9207), and §5.3.3.2 item 5
		// has the client check it: its absence is the mix-up attack's
		// signature, not a server quirk to tolerate.
		return fmt.Errorf("client: config: authorization_response_iss_policy TolerateAbsentAuthorizationResponseIss is refused under AssuranceProduction: FAPI 2.0 requires iss in the authorization response (RFC 9207)")
	}
	if cfg.SenderConstrain != storage.SenderConstrainDPoP && cfg.SenderConstrain != storage.SenderConstrainMTLS {
		return fmt.Errorf("client: config: sender_constrain is invalid")
	}
	switch cfg.ClientAuthMethod {
	case storage.ClientAuthMethodPrivateKeyJWT, storage.ClientAuthMethodSelfSignedTLSClientAuth,
		storage.ClientAuthMethodTLSClientAuth, storage.ClientAuthMethodTLSClientAuthSANDNS,
		storage.ClientAuthMethodTLSClientAuthSANURI, storage.ClientAuthMethodTLSClientAuthSANIP,
		storage.ClientAuthMethodTLSClientAuthSANEmail, storage.ClientAuthMethodAttestation:
	default:
		return fmt.Errorf("client: config: client_auth_method is invalid")
	}
	if cfg.BackchannelTokenDeliveryMode != storage.BackchannelTokenDeliveryModePoll &&
		cfg.BackchannelTokenDeliveryMode != storage.BackchannelTokenDeliveryModePing {
		return fmt.Errorf("client: config: backchannel_token_delivery_mode is invalid")
	}
	return nil
}

// validateAuthMethodAlgorithms checks the algorithm(s) each
// ClientAuthMethod/SenderConstrain choice requires — split out of
// validateConfig for the same reason validateEnumFields is.
func validateAuthMethodAlgorithms(cfg Config) error {
	// Algorithms.ClientAuthentication and Limits.ClientAssertionLifetime
	// are required only under ClientAuthMethodPrivateKeyJWT — every
	// other RFC 8705 mTLS method sends no client_assertion at all, so
	// neither a signing algorithm nor an assertion lifetime means
	// anything for them.
	if cfg.ClientAuthMethod == storage.ClientAuthMethodPrivateKeyJWT {
		if !cfg.Algorithms.ClientAuthentication.IsValid() {
			return fmt.Errorf("client: config: algorithms.client_authentication is required when client_auth_method is ClientAuthMethodPrivateKeyJWT")
		}
	}
	// Algorithms.ClientAttestationPoP is required only under
	// ClientAuthMethodAttestation — see its own doc comment for why
	// this method needs no accompanying lifetime field the way
	// ClientAuthMethodPrivateKeyJWT does.
	if cfg.ClientAuthMethod == storage.ClientAuthMethodAttestation && !cfg.Algorithms.ClientAttestationPoP.IsValid() {
		return fmt.Errorf("client: config: algorithms.client_attestation_pop is required when client_auth_method is ClientAuthMethodAttestation")
	}
	// Algorithms.DPoP is required only under SenderConstrainDPoP (the
	// default) — an mTLS-sender-constrained client never builds a DPoP
	// proof at all, so it never needs a DPoP signing algorithm.
	if !cfg.CallbackBinding.IsValid() {
		return fmt.Errorf("client: config: callback_binding %d is not a CallbackBinding", cfg.CallbackBinding)
	}
	if cfg.SenderConstrain == storage.SenderConstrainDPoP && !cfg.Algorithms.DPoP.IsValid() {
		return fmt.Errorf("client: config: algorithms.dpop is required when sender_constrain is SenderConstrainDPoP")
	}
	return nil
}

// validateIDTokenEncryptionFields checks that
// IDTokenKeyManagement/IDTokenContentEncryption declare encrypted ID
// token support as one coherent capability — required together, not
// independently optional, so a config can't end up in a state that
// only half-describes what to expect. Split out of validateConfig for
// the same reason validateEnumFields is.
func validateIDTokenEncryptionFields(cfg Config) error {
	keyManagementSet := cfg.Algorithms.IDTokenKeyManagement != 0
	contentEncryptionSet := cfg.Algorithms.IDTokenContentEncryption != 0
	if keyManagementSet != contentEncryptionSet {
		return fmt.Errorf("client: config: algorithms.id_token_key_management and algorithms.id_token_content_encryption must both be set, or both left zero")
	}
	if !keyManagementSet {
		return nil
	}
	if !cfg.Algorithms.IDTokenKeyManagement.IsValid() {
		return fmt.Errorf("client: config: algorithms.id_token_key_management is invalid")
	}
	if !cfg.Algorithms.IDTokenContentEncryption.IsValid() {
		return fmt.Errorf("client: config: algorithms.id_token_content_encryption is invalid")
	}
	return nil
}

// validateUserInfoConfig mirrors validateIDTokenEncryptionFields for
// the UserInfo encryption pair, plus the endpoint check that pair (or
// a plain Algorithms.UserInfo) implies.
func validateUserInfoConfig(cfg Config) error {
	// UserInfoKeyManagement/UserInfoContentEncryption mirror
	// IDTokenKeyManagement/IDTokenContentEncryption's own coherent-pair
	// requirement, for the same reason.
	userInfoKeyManagementSet := cfg.Algorithms.UserInfoKeyManagement != 0
	userInfoContentEncryptionSet := cfg.Algorithms.UserInfoContentEncryption != 0
	if userInfoKeyManagementSet != userInfoContentEncryptionSet {
		return fmt.Errorf("client: config: algorithms.userinfo_key_management and algorithms.userinfo_content_encryption must both be set, or both left zero")
	}
	if userInfoKeyManagementSet {
		if !cfg.Algorithms.UserInfoKeyManagement.IsValid() {
			return fmt.Errorf("client: config: algorithms.userinfo_key_management is invalid")
		}
		if !cfg.Algorithms.UserInfoContentEncryption.IsValid() {
			return fmt.Errorf("client: config: algorithms.userinfo_content_encryption is invalid")
		}
	}
	// A UserInfo algorithm only ever matters to FetchUserInfo/VerifyIssuerJWS,
	// both of which need Endpoints.UserInfo — catching a declared
	// algorithm with no endpoint here, rather than at the first
	// FetchUserInfo call, turns a first-user-login failure into a
	// startup one. Unlike ClientAuthentication/DPoP/IDToken above, this
	// checks the declared-vs-configured direction rather than
	// endpoint-vs-required, since Algorithms.UserInfo has no other
	// field whose presence already implies it.
	if cfg.RequireSignedUserInfo && cfg.Algorithms.UserInfo == 0 {
		return fmt.Errorf("client: config: algorithms.userinfo is required when require_signed_userinfo is set")
	}
	if (cfg.Algorithms.UserInfo != 0 || userInfoKeyManagementSet) && cfg.Endpoints.UserInfo.IsZero() {
		return fmt.Errorf("client: config: endpoints.userinfo is required when algorithms.userinfo or algorithms.userinfo_key_management is set")
	}
	return nil
}

func validateClientLimits(cfg Config) error {
	if cfg.ClientAuthMethod == storage.ClientAuthMethodPrivateKeyJWT && cfg.Limits.ClientAssertionLifetime <= 0 {
		return fmt.Errorf("client: config: limits.client_assertion_lifetime must be positive when client_auth_method is ClientAuthMethodPrivateKeyJWT")
	}
	if cfg.Limits.SessionLifetime <= 0 {
		return fmt.Errorf("client: config: limits.session_lifetime must be positive")
	}
	if idTokensPossible(cfg) && cfg.Limits.MaxIDTokenLifetime <= 0 {
		return fmt.Errorf("client: config: limits.max_id_token_lifetime must be positive when endpoints.authorization or endpoints.backchannel_authentication is set, unless oauth_only is set")
	}
	if cfg.Limits.MaxClockSkew < 0 {
		return fmt.Errorf("client: config: limits.max_clock_skew must not be negative")
	}
	if cfg.Limits.HTTPTimeout <= 0 {
		return fmt.Errorf("client: config: limits.http_timeout must be positive")
	}
	if cfg.Limits.MaxHTTPResponseBytes <= 0 {
		return fmt.Errorf("client: config: limits.max_http_response_bytes must be positive")
	}
	if cfg.Limits.MaxJOSECompactBytes <= 0 {
		return fmt.Errorf("client: config: limits.max_jose_compact_bytes must be positive")
	}
	if cfg.Assurance == AssuranceProduction {
		return errors.Join(productionLimitErrors(cfg.Limits)...)
	}
	return nil
}

// The bounds AssuranceProduction holds Limits to.
const (
	// FAPI 2.0 Security Profile §5.3.2.1 item 13's window, as server.New
	// and resource.NewVerifier require: it's this client's tolerance for
	// a server's iat and nbf, and how long past exp it still accepts an
	// ID token or JARM response.
	productionMinClockSkew = 10 * time.Second
	productionMaxClockSkew = 60 * time.Second
	// How long a user has to sign in and consent, as
	// server.Limits.InteractionLifetime is bounded.
	productionMaxSessionLifetime = time.Hour
	// A client assertion is used once, straight away.
	productionMaxClientAssertionLifetime = 5 * time.Minute
	// No spec bounds an ID token's lifetime, and widely used OpenID
	// Providers issue them for an hour, some for 10 hours by default: a
	// day refuses none of those, while refusing the "valid for a year"
	// misconfiguration that would let a stale ID token be accepted.
	productionMaxIDTokenLifetime = 24 * time.Hour
	// JARM §2.1: "a maximum JWT lifetime of 10 minutes is RECOMMENDED".
	// A server issuing exactly that still passes, since MaxClockSkew is
	// allowed on top.
	productionMaxJARMResponseLifetime = 10 * time.Minute
)

// productionLimitErrors checks l against AssuranceProduction's bounds,
// reporting every one exceeded.
func productionLimitErrors(l Limits) []error {
	var errs []error
	if l.MaxClockSkew < productionMinClockSkew || l.MaxClockSkew > productionMaxClockSkew {
		errs = append(errs, fmt.Errorf("client: config: limits.max_clock_skew must be between %v and %v under AssuranceProduction (FAPI 2.0 §5.3.2.1)", productionMinClockSkew, productionMaxClockSkew))
	}
	for _, bound := range []struct {
		name         string
		value, limit time.Duration
	}{
		{"session_lifetime", l.SessionLifetime, productionMaxSessionLifetime},
		{"client_assertion_lifetime", l.ClientAssertionLifetime, productionMaxClientAssertionLifetime},
		{"max_id_token_lifetime", l.MaxIDTokenLifetime, productionMaxIDTokenLifetime},
		{"max_jarm_response_lifetime", l.MaxJARMResponseLifetime, productionMaxJARMResponseLifetime},
	} {
		if bound.value > bound.limit {
			errs = append(errs, fmt.Errorf("client: config: limits.%s must be at most %v under AssuranceProduction", bound.name, bound.limit))
		}
	}
	return errs
}

func validateMessageSigningProfile(cfg Config) error {
	if cfg.Profile != ProfileFAPISecurityWithMessageSigning {
		return validateRequestObjectEncoding(cfg)
	}
	if !cfg.Algorithms.RequestObject.IsValid() {
		return fmt.Errorf("client: config: algorithms.request_object is required under ProfileFAPISecurityWithMessageSigning")
	}
	if !cfg.Algorithms.JARM.IsValid() {
		return fmt.Errorf("client: config: algorithms.jarm is required under ProfileFAPISecurityWithMessageSigning")
	}
	if cfg.Limits.RequestObjectLifetime <= 0 {
		return fmt.Errorf("client: config: limits.request_object_lifetime must be positive under ProfileFAPISecurityWithMessageSigning")
	}
	if cfg.Limits.RequestObjectLifetime > maxRequestObjectLifetime {
		return fmt.Errorf("client: config: limits.request_object_lifetime must be at most 60 minutes (FAPI 2.0 Message Signing §5.3.2 item 4)")
	}
	if cfg.Limits.MaxJARMResponseLifetime <= 0 {
		return fmt.Errorf("client: config: limits.max_jarm_response_lifetime must be positive under ProfileFAPISecurityWithMessageSigning")
	}
	return nil
}

// maxRequestObjectLifetime is FAPI 2.0 Message Signing §5.3.2 item 4's
// bound: a client "shall send an exp claim in the request object that
// has a lifetime of no longer than 60 minutes". A server following
// §5.3.1 item 4 refuses a longer one.
const maxRequestObjectLifetime = 60 * time.Minute

// validateRequestObjectEncoding checks the fields
// PushedRequestEncodingRequestObject needs under ProfileFAPISecurity —
// the request-object half of validateMessageSigningProfile's checks,
// without JARM's.
func validateRequestObjectEncoding(cfg Config) error {
	if cfg.PushedRequestEncoding != PushedRequestEncodingRequestObject {
		return nil
	}
	if !cfg.Algorithms.RequestObject.IsValid() {
		return fmt.Errorf("client: config: algorithms.request_object is required under PushedRequestEncodingRequestObject")
	}
	if cfg.Limits.RequestObjectLifetime <= 0 {
		return fmt.Errorf("client: config: limits.request_object_lifetime must be positive under PushedRequestEncodingRequestObject")
	}
	if cfg.Limits.RequestObjectLifetime > maxRequestObjectLifetime {
		return fmt.Errorf("client: config: limits.request_object_lifetime must be at most 60 minutes (FAPI 2.0 Message Signing §5.3.2 item 4)")
	}
	return nil
}

func validateCIBAConfig(cfg Config, cibaConfigured bool) error {
	if !cibaConfigured {
		return nil
	}
	if !cfg.Algorithms.BackchannelAuthenticationRequest.IsValid() {
		return fmt.Errorf("client: config: algorithms.backchannel_authentication_request is required when endpoints.backchannel_authentication is set")
	}
	if cfg.Limits.BackchannelAuthenticationRequestLifetime <= 0 {
		return fmt.Errorf("client: config: limits.backchannel_authentication_request_lifetime must be positive when endpoints.backchannel_authentication is set")
	}
	return nil
}

func validateFederationConfig(cfg Config) error {
	if cfg.Federation.EntityID == "" {
		return nil
	}
	if err := federation.ValidEntityID(cfg.Federation.EntityID); err != nil {
		return fmt.Errorf("client: config: federation.entity_id: %w", err)
	}
	if cfg.Federation.Lifetime <= 0 {
		return fmt.Errorf("client: config: federation.lifetime must be positive when federation.entity_id is set")
	}
	if !cfg.Federation.Algorithm.IsValid() {
		return fmt.Errorf("client: config: federation.algorithm is required when federation.entity_id is set")
	}
	return nil
}

func validateDependencies(cfg Config, deps Dependencies) error {
	// A typed nil (a nil *memstore.SessionStore, say) isn't == nil, so it
	// would pass every check below and fail only on first use.
	if found, ok := depcheck.FindTypedNil(deps, map[string]string{"DPoPNonceCache": "dpop_nonce_cache"}); ok {
		return fmt.Errorf("client: dependencies: %s is a nil %s", found.Name, found.Type)
	}
	if err := validateSessionsDependency(cfg, deps); err != nil {
		return err
	}
	if err := validateKeysDependency(cfg, deps); err != nil {
		return err
	}
	if err := validateIssuerKeysDependency(cfg, deps); err != nil {
		return err
	}
	if deps.HTTP == nil {
		return fmt.Errorf("client: dependencies: http is required")
	}
	if deps.Clock == nil {
		return fmt.Errorf("client: dependencies: clock is required")
	}
	if deps.Random == nil {
		return fmt.Errorf("client: dependencies: random is required")
	}
	if err := validateConfigDrivenDependencies(cfg, deps); err != nil {
		return err
	}
	if cfg.Assurance == AssuranceProduction {
		return validateProductionDependencies(cfg, deps)
	}
	return nil
}

// validateProductionDependencies applies AssuranceProduction's checks to
// deps: the sessions store's capabilities (and, under
// CallbackBindingDeviceLocalStore, that the client is a native app and
// the store isn't shared), crypto/rand as the random
// source, the custody of the keys deps.Keys and deps.Decryption hold, the
// issuer key source's hardening, and deps.HTTP's. It reports every one that falls
// short, joined (errors.Join), rather than only the first, so a
// deployment moving to production sees the whole list in one restart.
func validateProductionDependencies(cfg Config, deps Dependencies) error {
	var errs []error
	if deps.Sessions != nil {
		errs = append(errs, checkStoreAssurance("sessions", deps.Sessions))
		errs = append(errs, checkDeviceLocalSessions(cfg, deps.Sessions))
	}
	errs = append(errs, checkRandom(deps.Random), checkClock(deps.Clock, cfg.Limits.MaxClockSkew))
	if deps.Keys != nil {
		errs = append(errs, checkKeyCustody("keys", deps.Keys))
	}
	if deps.Decryption != nil {
		errs = append(errs, checkKeyCustody("decryption", deps.Decryption))
	}
	if deps.IssuerKeys != nil {
		errs = append(errs, checkKeySourceAssurance("issuer_keys", deps.IssuerKeys))
	}
	errs = append(errs, checkHTTPHardening(deps.HTTP))
	return errors.Join(errs...)
}

// validateSessionsDependency checks deps.Sessions. It is only ever
// touched by the browser flow (Create in BeginAuthorization, Consume in
// HandleAuthorizationResponse) — CIBA correlates its own poll/ping state
// through BackchannelAuthenticationSession instead, and
// RequestClientCredentialsToken has no session concept at all, so
// neither needs this dependency wired up.
func validateSessionsDependency(cfg Config, deps Dependencies) error {
	if !cfg.Endpoints.Authorization.IsZero() && deps.Sessions == nil {
		return fmt.Errorf("client: dependencies: sessions is required when endpoints.authorization is set")
	}
	return nil
}

// validateKeysDependency checks deps.Keys is set when cfg has this
// client sign anything.
func validateKeysDependency(cfg Config, deps Dependencies) error {
	if deps.Keys == nil && keysNeeded(cfg) {
		return fmt.Errorf("client: dependencies: keys is required (it may be left nil only when this client signs nothing: certificate-based client authentication, mTLS-bound tokens, no request objects, no CIBA and no federation)")
	}
	return nil
}

// keysNeeded reports whether cfg has this client sign anything with
// Dependencies.Keys — see Dependencies.Keys.
func keysNeeded(cfg Config) bool {
	return cfg.ClientAuthMethod == storage.ClientAuthMethodPrivateKeyJWT ||
		cfg.ClientAuthMethod == storage.ClientAuthMethodAttestation ||
		cfg.SenderConstrain == storage.SenderConstrainDPoP ||
		cfg.Profile == ProfileFAPISecurityWithMessageSigning ||
		cfg.PushedRequestEncoding == PushedRequestEncodingRequestObject ||
		!cfg.Endpoints.BackchannelAuthentication.IsZero() ||
		cfg.Federation.EntityID != ""
}

// validateIssuerKeysDependency checks deps.IssuerKeys.
func validateIssuerKeysDependency(cfg Config, deps Dependencies) error {
	if deps.IssuerKeys == nil && issuerKeysNeeded(cfg) {
		return fmt.Errorf("client: dependencies: issuer keys is required (it may be left nil only when oauth_only is set and neither a JARM response nor a signed UserInfo response is verified)")
	}
	return nil
}

// validateConfigDrivenDependencies checks the dependencies only some
// Config settings require — split out of validateDependencies purely to
// keep that function's own cognitive complexity manageable.
func validateConfigDrivenDependencies(cfg Config, deps Dependencies) error {
	if cfg.Algorithms.IDTokenKeyManagement != 0 && deps.Decryption == nil {
		return fmt.Errorf("client: dependencies: decryption is required when algorithms.id_token_key_management is set")
	}
	if cfg.Algorithms.UserInfoKeyManagement != 0 && deps.Decryption == nil {
		return fmt.Errorf("client: dependencies: decryption is required when algorithms.userinfo_key_management is set")
	}
	if cfg.ClientAuthMethod == storage.ClientAuthMethodAttestation && deps.Attestation == nil {
		return fmt.Errorf("client: dependencies: attestation is required when client_auth_method is ClientAuthMethodAttestation")
	}
	return nil
}

// issuerKeysNeeded reports whether cfg verifies anything the
// authorization server signs — see Config.OAuthOnly for when it
// doesn't.
func issuerKeysNeeded(cfg Config) bool {
	return !cfg.OAuthOnly || cfg.Profile == ProfileFAPISecurityWithMessageSigning || cfg.Algorithms.UserInfo != 0
}

// checkScope refuses a Scope element that isn't one scope-token
// (checkScopeTokens), and "openid" in an OAuthOnly client's requested
// scope — see Config.OAuthOnly.
func (c *Client) checkScope(scope []string) *Error {
	if err := checkScopeTokens(scope); err != nil {
		return err
	}
	if !c.cfg.OAuthOnly {
		return nil
	}
	for _, s := range scope {
		if s == "openid" {
			return newError(ErrorInvalidRequest, `"openid" cannot be requested by an oauth_only client`, nil)
		}
	}
	return nil
}

// authenticatesWithCertificate reports whether method is RFC 8705 §2's
// mutual-TLS client authentication, PKI or self-signed.
func authenticatesWithCertificate(method storage.ClientAuthMethod) bool {
	switch method {
	case storage.ClientAuthMethodSelfSignedTLSClientAuth, storage.ClientAuthMethodTLSClientAuth,
		storage.ClientAuthMethodTLSClientAuthSANDNS, storage.ClientAuthMethodTLSClientAuthSANURI,
		storage.ClientAuthMethodTLSClientAuthSANIP, storage.ClientAuthMethodTLSClientAuthSANEmail:
		return true
	}
	return false
}

// checkDeviceLocalSessions refuses CallbackBindingDeviceLocalStore
// anywhere but a native app: one whose Config.RedirectURI is loopback
// http to an IP literal (RFC 8252 §7.3) or a private-use URI scheme
// (§7.1), and whose sessions store doesn't declare
// CrossInstanceConsistent, which only a store shared between instances
// needs. A web client's https redirect means a server-side store holding
// many user agents' sessions, single-instance or not, where finding a
// session by the callback's state alone brings login CSRF back (RFC 9700
// §4.7).
func checkDeviceLocalSessions(cfg Config, sessions any) error {
	if cfg.CallbackBinding != CallbackBindingDeviceLocalStore {
		return nil
	}
	if !isNativeAppRedirectURI(cfg.RedirectURI) {
		return fmt.Errorf("client: config: callback binding CallbackBindingDeviceLocalStore is for a native app, whose redirect URI is loopback http (http://127.0.0.1/… or http://[::1]/…) or a private-use URI scheme, but redirect_uri is neither: a web client binds each callback to its browser with CallbackBindingSessionHandle (client/sessioncookie)")
	}
	if asserter, ok := sessions.(storage.StoreAssurance); ok && asserter.Capabilities().CrossInstanceConsistent {
		return fmt.Errorf("client: config: callback binding CallbackBindingDeviceLocalStore is for a native app's own on-device sessions store, but sessions declares CrossInstanceConsistent, which only a store shared between instances needs: use CallbackBindingSessionHandle")
	}
	return nil
}

// isNativeAppRedirectURI reports whether redirectURI is one only a native
// app receives: loopback http to the IP literal 127.0.0.1 or [::1] (RFC
// 8252 §7.3), or a private-use URI scheme (§7.1) — neither http nor
// https. validateRedirectURI has already parsed it.
func isNativeAppRedirectURI(redirectURI string) bool {
	u, err := url.Parse(redirectURI)
	if err != nil || redirectURI == "" {
		return false
	}
	switch u.Scheme {
	case "https":
		return false
	case "http":
		return u.Hostname() == "127.0.0.1" || u.Hostname() == "::1"
	}
	return true
}

// checkScopeTokens refuses a Scope element that isn't one scope-token
// (RFC 6749 §3.3: 1*( %x21 / %x23-5B / %x5D-7E )). Elements are joined
// with spaces on the wire, so one holding a space would send scopes
// this client never sees in Scope: "profile openid" asks for openid
// while every check for "openid" in Scope finds none, and the ID token
// it then requires goes unrequired.
func checkScopeTokens(scope []string) *Error {
	for _, s := range scope {
		if s == "" {
			return newError(ErrorInvalidRequest, "a Scope element is empty", nil)
		}
		for i := 0; i < len(s); i++ {
			if c := s[i]; c < 0x21 || c > 0x7e || c == '"' || c == '\\' {
				return newError(ErrorInvalidRequest, fmt.Sprintf("Scope element %q isn't one scope-token (RFC 6749 §3.3): pass each scope as its own element", s), nil)
			}
		}
	}
	return nil
}

// idTokensPossible reports whether cfg can ever receive an ID token:
// only the browser flow and CIBA return one, and never under
// Config.OAuthOnly. Every ID-token-only requirement (Algorithms.IDToken,
// Limits.MaxIDTokenLifetime) is conditioned on it, so none is demanded
// of a client that can't use it.
func idTokensPossible(cfg Config) bool {
	return !cfg.OAuthOnly && (!cfg.Endpoints.Authorization.IsZero() || !cfg.Endpoints.BackchannelAuthentication.IsZero())
}

// validateRedirectURI refuses a Config.RedirectURI no authorization
// server following FAPI 2.0 §5.3.2.2 would accept, so the mistake shows
// at New rather than as an invalid_request from the server's pushed
// authorization endpoint: it must be https, a native app's loopback http
// (RFC 8252 §7.3) or a private-use scheme (§7.1), with no fragment or
// credentials. This client doesn't know whether it's a native app, so
// all three forms pass; under AssuranceProduction a loopback redirect
// must name the IP literal 127.0.0.1 or [::1], not localhost, as RFC
// 8252 §8.3 recommends and a server's native client registration
// requires.
func validateRedirectURI(cfg Config) error {
	if cfg.RedirectURI == "" {
		return nil
	}
	if _, err := fapi.ParseRedirectURL(cfg.RedirectURI, fapi.AllowLoopbackHTTP(), fapi.AllowPrivateUseScheme()); err != nil {
		return fmt.Errorf("client: config: redirect_uri: %w", err)
	}
	if cfg.Assurance != AssuranceProduction {
		return nil
	}
	if u, err := url.Parse(cfg.RedirectURI); err == nil && u.Scheme == "http" && u.Hostname() != "127.0.0.1" && u.Hostname() != "::1" {
		return fmt.Errorf("client: config: redirect_uri: a loopback redirect URI uses the IP literal 127.0.0.1 or [::1], not a name, under AssuranceProduction (RFC 8252 §8.3)")
	}
	return nil
}
