package server

import (
	"fmt"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/extension"
	"github.com/idfoundry/fapigo/federation"
)

// Server is a FAPI 2.0 authorization-server engine. It is entirely
// unexported — construct one with New.
type Server struct {
	cfg  Config
	deps Dependencies
}

// New validates cfg and deps and returns a Server. Construction fails
// unless every security-critical configuration value and dependency is
// present and valid; see Config, Limits and Dependencies for what "no
// implicit fallback" means for each field.
func New(cfg Config, deps Dependencies) (*Server, error) {
	if err := validateConfig(cfg); err != nil {
		return nil, err
	}
	if err := validateDependencies(cfg, deps); err != nil {
		return nil, err
	}
	if cfg.Extensions == nil {
		// No implicit permissive fallback: an unconfigured registry
		// rejects every custom parameter, it does not accept anything —
		// see Config.Extensions.
		empty, err := extension.NewRegistry()
		if err != nil {
			return nil, fmt.Errorf("server: config: failed to build default empty extension registry: %w", err)
		}
		cfg.Extensions = empty
	}
	if len(cfg.AutomaticRegistration.TrustAnchors) > 0 {
		// Wraps deps.Clients/ClientKeys transparently — every other
		// internal (PAR, the token endpoint, CIBA) keeps calling those
		// same Dependencies fields exactly as before, unaware an
		// automatically-registered client is now also possible. The
		// original deps.Clients/ClientKeys (statically registered
		// clients) are passed in as Underlying, so they always take
		// priority — see AutomaticRegistrationConfig's own doc comment.
		resolver, err := federation.NewResolver(federation.Config{
			TrustAnchors: cfg.AutomaticRegistration.TrustAnchors,
			Limits: federation.Limits{
				MaxPathLength:        cfg.AutomaticRegistration.MaxPathLength,
				MaxStatementLifetime: cfg.AutomaticRegistration.MaxStatementLifetime,
				MaxClockSkew:         cfg.AutomaticRegistration.MaxClockSkew,
			},
		}, federation.Dependencies{HTTP: deps.FederationHTTP, Clock: deps.Clock})
		if err != nil {
			return nil, fmt.Errorf("server: config: automatic_registration: %w", err)
		}
		automaticClients, err := federation.NewAutomaticClientRepository(deps.Clients, resolver, deps.FederationHTTP, federation.AutomaticRegistrationConfig{
			AllowedScopes:                cfg.AutomaticRegistration.AllowedScopes,
			MaxCacheAge:                  cfg.AutomaticRegistration.MaxCacheAge,
			AllowsClientCredentialsGrant: cfg.AutomaticRegistration.AllowsClientCredentialsGrant,
			AllowsCIBA:                   cfg.AutomaticRegistration.AllowsCIBA,
		}, deps.Clock)
		if err != nil {
			return nil, fmt.Errorf("server: config: automatic_registration: %w", err)
		}
		automaticClientKeys, err := federation.NewAutomaticClientKeySource(deps.ClientKeys, automaticClients)
		if err != nil {
			return nil, fmt.Errorf("server: config: automatic_registration: %w", err)
		}
		deps.Clients = automaticClients
		deps.ClientKeys = automaticClientKeys
	}
	return &Server{cfg: cfg, deps: deps}, nil
}

// validateConfig checks cfg as a whole. Each thematic group of checks
// (required endpoints, algorithms, limits, ...) is split into its own
// function purely to keep this dispatcher's own cognitive complexity
// manageable — the checks themselves, their order, and their error
// messages are unchanged, so which specific error a given invalid cfg
// produces is unaffected by this split.
func validateConfig(cfg Config) error {
	cibaEnabled := !cfg.Endpoints.BackchannelAuthentication.IsZero()

	if err := validateRequiredEndpoints(cfg); err != nil {
		return err
	}
	if err := validateAlgorithms(cfg); err != nil {
		return err
	}
	if err := validateCIBAAlgorithms(cfg, cibaEnabled); err != nil {
		return err
	}
	if err := validateAttestationAlgorithms(cfg); err != nil {
		return err
	}
	if err := validateLimits(cfg, cibaEnabled); err != nil {
		return err
	}
	if err := validateAssurance(cfg, cibaEnabled); err != nil {
		return err
	}
	if err := validateMessageSigningProfile(cfg); err != nil {
		return err
	}
	if err := validateFederationConfig(cfg); err != nil {
		return err
	}
	return validateAutomaticRegistration(cfg)
}

func validateRequiredEndpoints(cfg Config) error {
	if cfg.Issuer.IsZero() {
		return fmt.Errorf("server: config: issuer is required")
	}
	if cfg.Endpoints.Token.IsZero() {
		return fmt.Errorf("server: config: endpoints.token is required")
	}
	if cfg.Endpoints.Authorization.IsZero() {
		return fmt.Errorf("server: config: endpoints.authorization is required")
	}
	if cfg.Endpoints.PushedAuthorizationRequest.IsZero() {
		return fmt.Errorf("server: config: endpoints.pushed_authorization_request is required")
	}
	if cfg.Endpoints.JWKS.IsZero() {
		return fmt.Errorf("server: config: endpoints.jwks is required")
	}
	if cfg.Profile != ProfileFAPISecurity && cfg.Profile != ProfileFAPISecurityWithMessageSigning {
		return fmt.Errorf("server: config: profile is invalid")
	}
	return nil
}

func validateAlgorithms(cfg Config) error {
	if err := validateAlgorithmSet("client_assertion", cfg.Algorithms.ClientAssertion); err != nil {
		return err
	}
	if err := validateAlgorithmSet("request_object", cfg.Algorithms.RequestObject); err != nil {
		return err
	}
	if !cfg.OAuthOnly && !cfg.Algorithms.IDToken.IsValid() {
		return fmt.Errorf("server: config: algorithms.id_token is required unless oauth_only is set")
	}
	if err := validateEncryptionAlgorithmPair(
		"id_token_encryption_key_management", cfg.Algorithms.IDTokenEncryptionKeyManagement,
		"id_token_encryption_content_encryption", cfg.Algorithms.IDTokenEncryptionContentEncryption,
	); err != nil {
		return err
	}
	if cfg.Algorithms.UserInfo != 0 && !cfg.Algorithms.UserInfo.IsValid() {
		return fmt.Errorf("server: config: algorithms.user_info contains an invalid algorithm")
	}
	return validateEncryptionAlgorithmPair(
		"user_info_encryption_key_management", cfg.Algorithms.UserInfoEncryptionKeyManagement,
		"user_info_encryption_content_encryption", cfg.Algorithms.UserInfoEncryptionContentEncryption,
	)
}

// validateAlgorithmSet checks that algs is non-empty and every element
// is valid, naming fieldName (e.g. "client_assertion") in its error
// message — shared by every AlgorithmPolicy field that is a plain
// required, non-empty algorithm list (unlike
// BackchannelAuthenticationRequest/ClientAttestation/
// ClientAttestationPoP, whose own empty-set error additionally names
// the condition that made them required, so those stay inline).
func validateAlgorithmSet(fieldName string, algs AlgorithmSet) error {
	if len(algs) == 0 {
		return fmt.Errorf("server: config: algorithms.%s must not be empty", fieldName)
	}
	for _, a := range algs {
		if !a.IsValid() {
			return fmt.Errorf("server: config: algorithms.%s contains an invalid algorithm", fieldName)
		}
	}
	return nil
}

// validateEncryptionAlgorithmPair checks that keyMgmt/contentEnc are
// both set or both empty, and that every element of each is valid —
// shared by the IDToken and UserInfo encryption allow-list pairs,
// which are otherwise identical. keyMgmtField/contentEncField name the
// two AlgorithmPolicy fields (e.g. "id_token_encryption_key_management"),
// for error messages.
func validateEncryptionAlgorithmPair(keyMgmtField string, keyMgmt KeyManagementAlgorithmSet, contentEncField string, contentEnc ContentEncryptionAlgorithmSet) error {
	if (len(keyMgmt) > 0) != (len(contentEnc) > 0) {
		return fmt.Errorf("server: config: algorithms.%s and algorithms.%s must both be set, or neither", keyMgmtField, contentEncField)
	}
	for _, a := range keyMgmt {
		if !a.IsValid() {
			return fmt.Errorf("server: config: algorithms.%s contains an invalid algorithm", keyMgmtField)
		}
	}
	for _, a := range contentEnc {
		if !a.IsValid() {
			return fmt.Errorf("server: config: algorithms.%s contains an invalid algorithm", contentEncField)
		}
	}
	return nil
}

func validateCIBAAlgorithms(cfg Config, cibaEnabled bool) error {
	if !cibaEnabled {
		return nil
	}
	if len(cfg.Algorithms.BackchannelAuthenticationRequest) == 0 {
		return fmt.Errorf("server: config: algorithms.backchannel_authentication_request must not be empty when endpoints.backchannel_authentication is set")
	}
	for _, a := range cfg.Algorithms.BackchannelAuthenticationRequest {
		if !a.IsValid() {
			return fmt.Errorf("server: config: algorithms.backchannel_authentication_request contains an invalid algorithm")
		}
	}
	return nil
}

func validateAttestationAlgorithms(cfg Config) error {
	if !cfg.AttestationBasedClientAuthentication {
		return nil
	}
	if len(cfg.Algorithms.ClientAttestation) == 0 {
		return fmt.Errorf("server: config: algorithms.client_attestation must not be empty when attestation_based_client_authentication is set")
	}
	for _, a := range cfg.Algorithms.ClientAttestation {
		if !a.IsValid() {
			return fmt.Errorf("server: config: algorithms.client_attestation contains an invalid algorithm")
		}
	}
	if len(cfg.Algorithms.ClientAttestationPoP) == 0 {
		return fmt.Errorf("server: config: algorithms.client_attestation_pop must not be empty when attestation_based_client_authentication is set")
	}
	for _, a := range cfg.Algorithms.ClientAttestationPoP {
		if !a.IsValid() {
			return fmt.Errorf("server: config: algorithms.client_attestation_pop contains an invalid algorithm")
		}
	}
	return nil
}

func validateLimits(cfg Config, cibaEnabled bool) error {
	if cfg.Limits.PushedRequestLifetime <= 0 {
		return fmt.Errorf("server: config: limits.pushed_request_lifetime must be positive")
	}
	if cfg.Limits.MaxClientAssertionLifetime <= 0 {
		return fmt.Errorf("server: config: limits.max_client_assertion_lifetime must be positive")
	}
	if cfg.Limits.MaxRequestObjectLifetime <= 0 {
		return fmt.Errorf("server: config: limits.max_request_object_lifetime must be positive")
	}
	if cfg.Limits.InteractionLifetime <= 0 {
		return fmt.Errorf("server: config: limits.interaction_lifetime must be positive")
	}
	if cfg.Limits.AuthorizationCodeLifetime <= 0 {
		return fmt.Errorf("server: config: limits.authorization_code_lifetime must be positive")
	}
	if cfg.Limits.AccessTokenLifetime <= 0 {
		return fmt.Errorf("server: config: limits.access_token_lifetime must be positive")
	}
	if !cfg.OAuthOnly && cfg.Limits.IDTokenLifetime <= 0 {
		return fmt.Errorf("server: config: limits.id_token_lifetime must be positive unless oauth_only is set")
	}
	if cfg.Limits.RefreshTokenLifetime <= 0 {
		return fmt.Errorf("server: config: limits.refresh_token_lifetime must be positive")
	}
	if cfg.Limits.MaxDPoPProofAge <= 0 {
		return fmt.Errorf("server: config: limits.max_dpop_proof_age must be positive")
	}
	if cfg.Limits.MaxClockSkew < 0 {
		return fmt.Errorf("server: config: limits.max_clock_skew must not be negative")
	}
	if err := validateCIBALimits(cfg, cibaEnabled); err != nil {
		return err
	}
	if err := validateAttestationLimits(cfg); err != nil {
		return err
	}
	return nil
}

func validateCIBALimits(cfg Config, cibaEnabled bool) error {
	if !cibaEnabled {
		return nil
	}
	if cfg.Limits.BackchannelAuthenticationRequestLifetime <= 0 {
		return fmt.Errorf("server: config: limits.backchannel_authentication_request_lifetime must be positive when endpoints.backchannel_authentication is set")
	}
	if cfg.Limits.MaxBackchannelAuthenticationRequestLifetime <= 0 {
		return fmt.Errorf("server: config: limits.max_backchannel_authentication_request_lifetime must be positive when endpoints.backchannel_authentication is set")
	}
	if cfg.Limits.BackchannelAuthenticationPollInterval <= 0 {
		return fmt.Errorf("server: config: limits.backchannel_authentication_poll_interval must be positive when endpoints.backchannel_authentication is set")
	}
	return nil
}

func validateAttestationLimits(cfg Config) error {
	if !cfg.AttestationBasedClientAuthentication {
		return nil
	}
	if cfg.Limits.MaxClientAttestationLifetime <= 0 {
		return fmt.Errorf("server: config: limits.max_client_attestation_lifetime must be positive when attestation_based_client_authentication is set")
	}
	if cfg.Limits.MaxClientAttestationPoPAge <= 0 {
		return fmt.Errorf("server: config: limits.max_client_attestation_pop_age must be positive when attestation_based_client_authentication is set")
	}
	return nil
}

func validateAssurance(cfg Config, cibaEnabled bool) error {
	if cfg.Assurance != AssuranceDevelopment && cfg.Assurance != AssuranceProduction {
		return fmt.Errorf("server: config: assurance level is invalid")
	}
	if cfg.Assurance != AssuranceProduction {
		return nil
	}
	if err := rejectLoopbackURL("issuer", cfg.Issuer); err != nil {
		return err
	}
	if err := rejectLoopbackURL("endpoints.authorization", cfg.Endpoints.Authorization); err != nil {
		return err
	}
	if err := rejectLoopbackURL("endpoints.token", cfg.Endpoints.Token); err != nil {
		return err
	}
	if err := rejectLoopbackURL("endpoints.pushed_authorization_request", cfg.Endpoints.PushedAuthorizationRequest); err != nil {
		return err
	}
	if err := rejectLoopbackURL("endpoints.jwks", cfg.Endpoints.JWKS); err != nil {
		return err
	}
	if cibaEnabled {
		if err := rejectLoopbackURL("endpoints.backchannel_authentication", cfg.Endpoints.BackchannelAuthentication); err != nil {
			return err
		}
	}
	return nil
}

func validateMessageSigningProfile(cfg Config) error {
	if cfg.Profile != ProfileFAPISecurityWithMessageSigning {
		return nil
	}
	if !cfg.Algorithms.JARM.IsValid() {
		return fmt.Errorf("server: config: algorithms.jarm is required under ProfileFAPISecurityWithMessageSigning")
	}
	if cfg.Limits.JARMResponseLifetime <= 0 {
		return fmt.Errorf("server: config: limits.jarm_response_lifetime must be positive under ProfileFAPISecurityWithMessageSigning")
	}
	return nil
}

func validateFederationConfig(cfg Config) error {
	if cfg.Federation.EntityID == "" {
		return nil
	}
	if err := federation.ValidEntityID(cfg.Federation.EntityID); err != nil {
		return fmt.Errorf("server: config: federation.entity_id: %w", err)
	}
	if cfg.Federation.Lifetime <= 0 {
		return fmt.Errorf("server: config: federation.lifetime must be positive when federation.entity_id is set")
	}
	if !cfg.Federation.Algorithm.IsValid() {
		return fmt.Errorf("server: config: federation.algorithm is required when federation.entity_id is set")
	}
	return nil
}

// validateAutomaticRegistration checks the fields
// federation.NewResolver doesn't itself own — TrustAnchors/
// MaxPathLength/MaxStatementLifetime/MaxClockSkew are validated when
// federation.NewResolver actually constructs a Resolver from them in
// New(), the same "nested validating constructor invoked directly in
// New(), not re-validated here" precedent Config.Extensions already
// follows.
func validateAutomaticRegistration(cfg Config) error {
	if len(cfg.AutomaticRegistration.TrustAnchors) == 0 {
		return nil
	}
	if len(cfg.AutomaticRegistration.AllowedScopes) == 0 {
		return fmt.Errorf("server: config: automatic_registration.allowed_scopes is required when automatic_registration.trust_anchors is set")
	}
	if cfg.AutomaticRegistration.MaxCacheAge <= 0 {
		return fmt.Errorf("server: config: automatic_registration.max_cache_age must be positive when automatic_registration.trust_anchors is set")
	}
	return nil
}

// rejectLoopbackURL returns an error if u has an http scheme — which,
// per fapi.ParseIssuerURL/ParseEndpointURL, can only happen if
// fapi.AllowLoopbackHTTP() was passed when parsing it. That option
// exists for local development only (see its own doc comment); under
// AssuranceProduction it must not have been carried into a
// configuration that could reach a real deployment.
func rejectLoopbackURL(name string, u fapi.URL) error {
	if u.URL().Scheme == "http" {
		return fmt.Errorf("server: config: %s was parsed with fapi.AllowLoopbackHTTP, which is not permitted under AssuranceProduction", name)
	}
	return nil
}

// validateDependencies checks deps as a whole. Split into thematic
// groups for the same reason validateConfig is — the checks, their
// order and their error messages are unchanged.
func validateDependencies(cfg Config, deps Dependencies) error {
	if err := validateRequiredDependencies(deps); err != nil {
		return err
	}
	if err := validateConditionalDependencies(cfg, deps); err != nil {
		return err
	}
	cibaEnabled := !cfg.Endpoints.BackchannelAuthentication.IsZero()
	if cfg.Assurance != AssuranceProduction {
		return nil
	}
	return validateProductionStoreAssurance(cfg, deps, cibaEnabled)
}

func validateRequiredDependencies(deps Dependencies) error {
	if deps.Clients == nil {
		return fmt.Errorf("server: dependencies: clients is required")
	}
	if deps.Transactions == nil {
		return fmt.Errorf("server: dependencies: transactions is required")
	}
	if deps.Grants == nil {
		return fmt.Errorf("server: dependencies: grants is required")
	}
	if deps.Replay == nil {
		return fmt.Errorf("server: dependencies: replay is required")
	}
	if deps.ClientKeys == nil {
		return fmt.Errorf("server: dependencies: client keys is required")
	}
	if deps.Keys == nil {
		return fmt.Errorf("server: dependencies: keys is required")
	}
	if deps.Clock == nil {
		return fmt.Errorf("server: dependencies: clock is required")
	}
	if deps.Random == nil {
		return fmt.Errorf("server: dependencies: random is required")
	}
	if deps.Revocation == nil {
		return fmt.Errorf("server: dependencies: revocation is required (pass NoRevocation{} to explicitly decline)")
	}
	if deps.ClientCertificateTrust == nil {
		return fmt.Errorf("server: dependencies: client certificate trust is required (pass TrustedClientCAs{...} or NoClientCertificateChainTrust{} to explicitly decline this package's own chain check)")
	}
	if deps.AccessTokens == nil {
		return fmt.Errorf("server: dependencies: access tokens is required (pass JWTAccessTokens{...} or OpaqueAccessTokens{...})")
	}
	return nil
}

func validateConditionalDependencies(cfg Config, deps Dependencies) error {
	idTokenEncEnabled := len(cfg.Algorithms.IDTokenEncryptionKeyManagement) > 0 || len(cfg.Algorithms.IDTokenEncryptionContentEncryption) > 0
	if idTokenEncEnabled && deps.ClientEncryptionKeys == nil {
		return fmt.Errorf("server: dependencies: client encryption keys is required when algorithms.id_token_encryption_key_management/content_encryption are configured")
	}
	userInfoEncEnabled := len(cfg.Algorithms.UserInfoEncryptionKeyManagement) > 0 || len(cfg.Algorithms.UserInfoEncryptionContentEncryption) > 0
	if userInfoEncEnabled && deps.ClientEncryptionKeys == nil {
		return fmt.Errorf("server: dependencies: client encryption keys is required when algorithms.user_info_encryption_key_management/content_encryption are configured")
	}
	if deps.Nonces != nil && cfg.Limits.DPoPNonceLifetime <= 0 {
		return fmt.Errorf("server: config: limits.dpop_nonce_lifetime must be positive when dependencies.nonces is set")
	}
	cibaEnabled := !cfg.Endpoints.BackchannelAuthentication.IsZero()
	if cibaEnabled && deps.Backchannel == nil {
		return fmt.Errorf("server: dependencies: backchannel is required when endpoints.backchannel_authentication is set")
	}
	if cibaEnabled && deps.BackchannelNotifier == nil {
		return fmt.Errorf("server: dependencies: backchannel notifier is required when endpoints.backchannel_authentication is set")
	}
	if len(cfg.AutomaticRegistration.TrustAnchors) > 0 && deps.FederationHTTP == nil {
		return fmt.Errorf("server: dependencies: federation_http is required when automatic_registration.trust_anchors is set")
	}
	return nil
}

// validateProductionStoreAssurance applies StoreAssurance to every
// dependency AssuranceProduction requires it of — split out of
// validateDependencies purely to keep that function's own cognitive
// complexity manageable. Only ever called once cfg.Assurance is
// already known to be AssuranceProduction.
func validateProductionStoreAssurance(cfg Config, deps Dependencies, cibaEnabled bool) error {
	if deps.Audit == nil {
		return fmt.Errorf("server: dependencies: audit is required under AssuranceProduction")
	}
	scaled := cfg.HorizontallyScaled
	if err := checkStoreAssurance("clients", deps.Clients, false, scaled); err != nil {
		return err
	}
	if err := checkStoreAssurance("transactions", deps.Transactions, true, scaled); err != nil {
		return err
	}
	if err := checkStoreAssurance("grants", deps.Grants, true, scaled); err != nil {
		return err
	}
	if err := checkStoreAssurance("replay", deps.Replay, true, scaled); err != nil {
		return err
	}
	if cibaEnabled {
		if err := checkStoreAssurance("backchannel", deps.Backchannel, true, scaled); err != nil {
			return err
		}
	}
	if deps.Nonces != nil {
		if err := checkStoreAssurance("nonces", deps.Nonces, true, scaled); err != nil {
			return err
		}
	}
	if opaque, ok := deps.AccessTokens.(OpaqueAccessTokens); ok {
		if err := checkStoreAssurance("access_tokens", opaque.Store, false, scaled); err != nil {
			return err
		}
	}
	if _, declinedRevocation := deps.Revocation.(NoRevocation); !declinedRevocation {
		if err := checkStoreAssurance("revocation", deps.Revocation, false, scaled); err != nil {
			return err
		}
	}
	return nil
}
