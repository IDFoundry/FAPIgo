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
	if err := validateConfig(cfg, deps); err != nil {
		return nil, err
	}
	if err := validateDependencies(deps); err != nil {
		return nil, err
	}
	if err := validateAssurance(cfg, deps); err != nil {
		return nil, err
	}
	return &Verifier{cfg: cfg, deps: deps}, nil
}

func validateConfig(cfg Config, deps Dependencies) error {
	if cfg.Limits.MaxDPoPProofAge <= 0 {
		return fmt.Errorf("resource: config: limits.max_dpop_proof_age must be positive")
	}
	if cfg.Limits.MaxClockSkew < 0 {
		return fmt.Errorf("resource: config: limits.max_clock_skew must not be negative")
	}
	if deps.Nonces != nil && cfg.Limits.DPoPNonceLifetime <= 0 {
		return fmt.Errorf("resource: config: limits.dpop_nonce_lifetime must be positive when dependencies.nonces is set")
	}
	return nil
}

func validateDependencies(deps Dependencies) error {
	if deps.AccessTokens == nil {
		return fmt.Errorf("resource: dependencies: access tokens is required (pass JWTAccessTokens{...} or OpaqueAccessTokens{...})")
	}
	if err := validateBundledResolver(deps.AccessTokens); err != nil {
		return err
	}
	if deps.Replay == nil {
		return fmt.Errorf("resource: dependencies: replay is required")
	}
	if deps.Revocation == nil {
		return fmt.Errorf("resource: dependencies: revocation is required (pass NoRevocation{} to explicitly decline)")
	}
	if deps.Clock == nil {
		return fmt.Errorf("resource: dependencies: clock is required")
	}
	if deps.Nonces != nil && deps.Random == nil {
		return fmt.Errorf("resource: dependencies: random is required when nonces is set")
	}
	return nil
}

// validateBundledResolver checks a JWTAccessTokens or OpaqueAccessTokens
// (or a pointer to one) the way its constructor does, so a literal
// missing a field is refused here rather than failing — or, for a nil
// key source or store, panicking — on every request. Any other
// AccessTokenResolver is the application's own to validate.
func validateBundledResolver(r AccessTokenResolver) error {
	var name string
	var err error
	switch t := r.(type) {
	case JWTAccessTokens:
		name, err = "JWTAccessTokens", t.validate()
	case *JWTAccessTokens:
		if t == nil {
			return fmt.Errorf("resource: dependencies: access_tokens is a nil *JWTAccessTokens")
		}
		name, err = "JWTAccessTokens", t.validate()
	case OpaqueAccessTokens:
		name, err = "OpaqueAccessTokens", t.validate()
	case *OpaqueAccessTokens:
		if t == nil {
			return fmt.Errorf("resource: dependencies: access_tokens is a nil *OpaqueAccessTokens")
		}
		name, err = "OpaqueAccessTokens", t.validate()
	}
	if err != nil {
		return fmt.Errorf("resource: dependencies: access_tokens (%s): %w", name, err)
	}
	return nil
}
