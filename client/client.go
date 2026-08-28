package client

import (
	"fmt"

	"github.com/idfoundry/fapigo/storage"
)

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
	if err := validateDependencies(cfg, deps); err != nil {
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
	if cfg.Endpoints.Token.IsZero() {
		return fmt.Errorf("client: config: endpoints.token is required")
	}
	// Authorization and PushedAuthorizationRequest declare browser-flow
	// support as one coherent capability — required together, not
	// independently optional, mirroring the
	// IDTokenKeyManagement/IDTokenContentEncryption pairing below. A
	// CIBA-only client (Endpoints.BackchannelAuthentication set
	// instead) has no browser flow at all, so leaving both zero is
	// valid — but a client must configure at least one flow, checked
	// just below.
	authorizationFlowConfigured := !cfg.Endpoints.Authorization.IsZero()
	parConfigured := !cfg.Endpoints.PushedAuthorizationRequest.IsZero()
	if authorizationFlowConfigured != parConfigured {
		return fmt.Errorf("client: config: endpoints.authorization and endpoints.pushed_authorization_request must both be set, or both left zero")
	}
	if !authorizationFlowConfigured && cfg.Endpoints.BackchannelAuthentication.IsZero() {
		return fmt.Errorf("client: config: at least one flow must be configured: endpoints.authorization (with endpoints.pushed_authorization_request), or endpoints.backchannel_authentication")
	}
	// RedirectURI only means anything to the browser flow — BeginAuthorization
	// is the only place this module ever sends it.
	if authorizationFlowConfigured && cfg.RedirectURI == "" {
		return fmt.Errorf("client: config: redirect_uri is required when endpoints.authorization is set")
	}
	if cfg.Profile != ProfileFAPISecurity && cfg.Profile != ProfileFAPISecurityWithMessageSigning {
		return fmt.Errorf("client: config: profile is invalid")
	}
	if cfg.PARDPoPBinding != PARDPoPBindingProof && cfg.PARDPoPBinding != PARDPoPBindingJKT {
		return fmt.Errorf("client: config: par_dpop_binding is invalid")
	}
	if cfg.SenderConstrain != storage.SenderConstrainDPoP && cfg.SenderConstrain != storage.SenderConstrainMTLS {
		return fmt.Errorf("client: config: sender_constrain is invalid")
	}

	if !cfg.Algorithms.ClientAuthentication.IsValid() {
		return fmt.Errorf("client: config: algorithms.client_authentication is required")
	}
	// Algorithms.DPoP is required only under SenderConstrainDPoP (the
	// default) — an mTLS-sender-constrained client never builds a DPoP
	// proof at all, so it never needs a DPoP signing algorithm.
	if cfg.SenderConstrain == storage.SenderConstrainDPoP && !cfg.Algorithms.DPoP.IsValid() {
		return fmt.Errorf("client: config: algorithms.dpop is required when sender_constrain is SenderConstrainDPoP")
	}
	if !cfg.Algorithms.IDToken.IsValid() {
		return fmt.Errorf("client: config: algorithms.id_token is required")
	}
	// IDTokenKeyManagement/IDTokenContentEncryption declare encrypted
	// ID token support as one coherent capability — required together,
	// not independently optional, so a config can't end up in a state
	// that only half-describes what to expect.
	keyManagementSet := cfg.Algorithms.IDTokenKeyManagement != 0
	contentEncryptionSet := cfg.Algorithms.IDTokenContentEncryption != 0
	if keyManagementSet != contentEncryptionSet {
		return fmt.Errorf("client: config: algorithms.id_token_key_management and algorithms.id_token_content_encryption must both be set, or both left zero")
	}
	if keyManagementSet {
		if !cfg.Algorithms.IDTokenKeyManagement.IsValid() {
			return fmt.Errorf("client: config: algorithms.id_token_key_management is invalid")
		}
		if !cfg.Algorithms.IDTokenContentEncryption.IsValid() {
			return fmt.Errorf("client: config: algorithms.id_token_content_encryption is invalid")
		}
	}

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
	if cfg.Limits.MaxJOSECompactBytes <= 0 {
		return fmt.Errorf("client: config: limits.max_jose_compact_bytes must be positive")
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

	if !cfg.Endpoints.BackchannelAuthentication.IsZero() {
		if !cfg.Algorithms.BackchannelAuthenticationRequest.IsValid() {
			return fmt.Errorf("client: config: algorithms.backchannel_authentication_request is required when endpoints.backchannel_authentication is set")
		}
		if cfg.Limits.BackchannelAuthenticationRequestLifetime <= 0 {
			return fmt.Errorf("client: config: limits.backchannel_authentication_request_lifetime must be positive when endpoints.backchannel_authentication is set")
		}
	}
	return nil
}

func validateDependencies(cfg Config, deps Dependencies) error {
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
	if cfg.Algorithms.IDTokenKeyManagement != 0 && deps.Decryption == nil {
		return fmt.Errorf("client: dependencies: decryption is required when algorithms.id_token_key_management is set")
	}
	if cfg.Algorithms.UserInfoKeyManagement != 0 && deps.Decryption == nil {
		return fmt.Errorf("client: dependencies: decryption is required when algorithms.userinfo_key_management is set")
	}
	return nil
}
