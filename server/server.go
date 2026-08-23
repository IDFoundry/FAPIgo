package server

import (
	"fmt"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/extension"
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
	return &Server{cfg: cfg, deps: deps}, nil
}

func validateConfig(cfg Config) error {
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

	if len(cfg.Algorithms.ClientAssertion) == 0 {
		return fmt.Errorf("server: config: algorithms.client_assertion must not be empty")
	}
	for _, a := range cfg.Algorithms.ClientAssertion {
		if !a.IsValid() {
			return fmt.Errorf("server: config: algorithms.client_assertion contains an invalid algorithm")
		}
	}
	if len(cfg.Algorithms.RequestObject) == 0 {
		return fmt.Errorf("server: config: algorithms.request_object must not be empty")
	}
	for _, a := range cfg.Algorithms.RequestObject {
		if !a.IsValid() {
			return fmt.Errorf("server: config: algorithms.request_object contains an invalid algorithm")
		}
	}
	if !cfg.Algorithms.IDToken.IsValid() {
		return fmt.Errorf("server: config: algorithms.id_token is required")
	}
	idTokenEncKeyMgmtSet := len(cfg.Algorithms.IDTokenEncryptionKeyManagement) > 0
	idTokenEncContentEncSet := len(cfg.Algorithms.IDTokenEncryptionContentEncryption) > 0
	if idTokenEncKeyMgmtSet != idTokenEncContentEncSet {
		return fmt.Errorf("server: config: algorithms.id_token_encryption_key_management and algorithms.id_token_encryption_content_encryption must both be set, or neither")
	}
	for _, a := range cfg.Algorithms.IDTokenEncryptionKeyManagement {
		if !a.IsValid() {
			return fmt.Errorf("server: config: algorithms.id_token_encryption_key_management contains an invalid algorithm")
		}
	}
	for _, a := range cfg.Algorithms.IDTokenEncryptionContentEncryption {
		if !a.IsValid() {
			return fmt.Errorf("server: config: algorithms.id_token_encryption_content_encryption contains an invalid algorithm")
		}
	}

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
	if cfg.Limits.IDTokenLifetime <= 0 {
		return fmt.Errorf("server: config: limits.id_token_lifetime must be positive")
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

	if cfg.Assurance != AssuranceDevelopment && cfg.Assurance != AssuranceProduction {
		return fmt.Errorf("server: config: assurance level is invalid")
	}
	if cfg.Assurance == AssuranceProduction {
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
	}

	if cfg.Profile == ProfileFAPISecurityWithMessageSigning {
		if !cfg.Algorithms.JARM.IsValid() {
			return fmt.Errorf("server: config: algorithms.jarm is required under ProfileFAPISecurityWithMessageSigning")
		}
		if cfg.Limits.JARMResponseLifetime <= 0 {
			return fmt.Errorf("server: config: limits.jarm_response_lifetime must be positive under ProfileFAPISecurityWithMessageSigning")
		}
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

func validateDependencies(cfg Config, deps Dependencies) error {
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
	if deps.AccessTokens == nil {
		return fmt.Errorf("server: dependencies: access tokens is required (pass JWTAccessTokens{...} or OpaqueAccessTokens{...})")
	}
	idTokenEncEnabled := len(cfg.Algorithms.IDTokenEncryptionKeyManagement) > 0 || len(cfg.Algorithms.IDTokenEncryptionContentEncryption) > 0
	if idTokenEncEnabled && deps.ClientEncryptionKeys == nil {
		return fmt.Errorf("server: dependencies: client encryption keys is required when algorithms.id_token_encryption_key_management/content_encryption are configured")
	}
	if cfg.Assurance == AssuranceProduction {
		if deps.Audit == nil {
			return fmt.Errorf("server: dependencies: audit is required under AssuranceProduction")
		}
		if err := checkStoreAssurance("clients", deps.Clients, false); err != nil {
			return err
		}
		if err := checkStoreAssurance("transactions", deps.Transactions, true); err != nil {
			return err
		}
		if err := checkStoreAssurance("grants", deps.Grants, true); err != nil {
			return err
		}
		if err := checkStoreAssurance("replay", deps.Replay, true); err != nil {
			return err
		}
	}
	return nil
}
