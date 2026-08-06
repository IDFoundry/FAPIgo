package client

import "fmt"

// Client is a FAPI 2.0 relying-party engine. It is entirely unexported —
// construct one with New.
type Client struct {
	cfg  Config
	deps Dependencies
}

// New validates cfg and deps and returns a Client. Construction fails
// unless every configuration value and dependency Config.Profile
// requires is present and valid.
func New(cfg Config, deps Dependencies) (*Client, error) {
	if err := validateConfig(cfg); err != nil {
		return nil, err
	}
	if err := validateDependencies(deps); err != nil {
		return nil, err
	}
	return &Client{cfg: cfg, deps: deps}, nil
}

func validateConfig(cfg Config) error {
	if cfg.Issuer.IsZero() {
		return fmt.Errorf("client: config: issuer is required")
	}
	if cfg.ClientID == "" {
		return fmt.Errorf("client: config: client ID is required")
	}
	if cfg.RedirectURI == "" {
		return fmt.Errorf("client: config: redirect URI is required")
	}
	if cfg.Endpoints.Authorization.IsZero() {
		return fmt.Errorf("client: config: endpoints.authorization is required")
	}
	if cfg.Endpoints.Token.IsZero() {
		return fmt.Errorf("client: config: endpoints.token is required")
	}
	if cfg.Endpoints.PushedAuthorizationRequest.IsZero() {
		return fmt.Errorf("client: config: endpoints.pushed_authorization_request is required")
	}
	if cfg.Profile != ProfileFAPISecurity && cfg.Profile != ProfileFAPISecurityWithMessageSigning {
		return fmt.Errorf("client: config: profile is invalid")
	}

	if !cfg.Algorithms.ClientAuthentication.IsValid() {
		return fmt.Errorf("client: config: algorithms.client_authentication is required")
	}
	if !cfg.Algorithms.DPoP.IsValid() {
		return fmt.Errorf("client: config: algorithms.dpop is required")
	}
	if !cfg.Algorithms.IDToken.IsValid() {
		return fmt.Errorf("client: config: algorithms.id_token is required")
	}

	if cfg.Limits.ClientAssertionLifetime <= 0 {
		return fmt.Errorf("client: config: limits.client_assertion_lifetime must be positive")
	}
	if cfg.Limits.SessionLifetime <= 0 {
		return fmt.Errorf("client: config: limits.session_lifetime must be positive")
	}
	if cfg.Limits.MaxIDTokenLifetime <= 0 {
		return fmt.Errorf("client: config: limits.max_id_token_lifetime must be positive")
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

	if cfg.Profile == ProfileFAPISecurityWithMessageSigning {
		if !cfg.Algorithms.RequestObject.IsValid() {
			return fmt.Errorf("client: config: algorithms.request_object is required under ProfileFAPISecurityWithMessageSigning")
		}
		if !cfg.Algorithms.JARM.IsValid() {
			return fmt.Errorf("client: config: algorithms.jarm is required under ProfileFAPISecurityWithMessageSigning")
		}
		if cfg.Limits.RequestObjectLifetime <= 0 {
			return fmt.Errorf("client: config: limits.request_object_lifetime must be positive under ProfileFAPISecurityWithMessageSigning")
		}
		if cfg.Limits.MaxJARMResponseLifetime <= 0 {
			return fmt.Errorf("client: config: limits.max_jarm_response_lifetime must be positive under ProfileFAPISecurityWithMessageSigning")
		}
	}
	return nil
}

func validateDependencies(deps Dependencies) error {
	if deps.Sessions == nil {
		return fmt.Errorf("client: dependencies: sessions is required")
	}
	if deps.Keys == nil {
		return fmt.Errorf("client: dependencies: keys is required")
	}
	if deps.IssuerKeys == nil {
		return fmt.Errorf("client: dependencies: issuer keys is required")
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
	return nil
}
