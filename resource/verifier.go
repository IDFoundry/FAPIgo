package resource

import "fmt"

// Verifier is a FAPI 2.0 resource-server engine: it verifies incoming
// access tokens and their DPoP sender-constraint proofs. It is entirely
// unexported — construct one with NewVerifier.
type Verifier struct {
	cfg  Config
	deps Dependencies
}

// NewVerifier validates cfg and deps and returns a Verifier.
// Construction fails unless every configuration value and dependency is
// present and valid — see Config, Limits and Dependencies for what "no
// implicit fallback" means for each field.
func NewVerifier(cfg Config, deps Dependencies) (*Verifier, error) {
	if err := validateConfig(cfg); err != nil {
		return nil, err
	}
	if err := validateDependencies(deps); err != nil {
		return nil, err
	}
	return &Verifier{cfg: cfg, deps: deps}, nil
}

func validateConfig(cfg Config) error {
	if cfg.Issuer.IsZero() {
		return fmt.Errorf("resource: config: issuer is required")
	}
	if cfg.Audience == "" {
		return fmt.Errorf("resource: config: audience is required")
	}
	if !cfg.Algorithm.IsValid() {
		return fmt.Errorf("resource: config: algorithm is required")
	}
	if cfg.Limits.MaxTokenLifetime <= 0 {
		return fmt.Errorf("resource: config: limits.max_token_lifetime must be positive")
	}
	if cfg.Limits.MaxDPoPProofAge <= 0 {
		return fmt.Errorf("resource: config: limits.max_dpop_proof_age must be positive")
	}
	if cfg.Limits.MaxClockSkew < 0 {
		return fmt.Errorf("resource: config: limits.max_clock_skew must not be negative")
	}
	return nil
}

func validateDependencies(deps Dependencies) error {
	if deps.IssuerKeys == nil {
		return fmt.Errorf("resource: dependencies: issuer keys is required")
	}
	if deps.Replay == nil {
		return fmt.Errorf("resource: dependencies: replay is required")
	}
	if deps.Clock == nil {
		return fmt.Errorf("resource: dependencies: clock is required")
	}
	return nil
}
