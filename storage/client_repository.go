package storage

import (
	"context"
	"fmt"

	fapi "github.com/idfoundry/fapigo"
)

// SenderConstrain is the closed set of mechanisms a registered
// client's access (and refresh) tokens are sender-constrained with.
type SenderConstrain uint8

const (
	// SenderConstrainDPoP binds a client's tokens to a DPoP proof key
	// (RFC 9449) — the zero value, so every registered client that
	// predates this field keeps behaving exactly as it did before.
	SenderConstrainDPoP SenderConstrain = iota

	// SenderConstrainMTLS binds a client's tokens to the TLS client
	// certificate presented on the connection that requested them
	// (RFC 8705 §3's "cnf.x5t#S256"), instead of a DPoP proof. Like
	// DPoP, this needs no client registration or CA trust store of its
	// own — sender-constraining only compares thumbprints, it never
	// authenticates the client by its certificate.
	SenderConstrainMTLS
)

// RegisteredClient is the exact, validated configuration of one
// registered OAuth client. It is immutable and can only be constructed
// through NewRegisteredClient — a caller cannot return arbitrary
// discovery or registration JSON in its place.
type RegisteredClient struct {
	id                       fapi.ClientID
	redirectURIs             []fapi.RegisteredRedirectURI
	clientAssertionAlgorithm fapi.SignatureAlgorithm
	requestObjectAlgorithm   fapi.SignatureAlgorithm
	senderConstrain          SenderConstrain
	allowedScopes            map[string]struct{}

	idTokenEncryptionKeyManagement     fapi.KeyManagementAlgorithm
	idTokenEncryptionContentEncryption fapi.ContentEncryptionAlgorithm

	userInfoEncryptionKeyManagement     fapi.KeyManagementAlgorithm
	userInfoEncryptionContentEncryption fapi.ContentEncryptionAlgorithm

	backchannelAuthenticationRequestAlgorithm fapi.SignatureAlgorithm
}

// RegisteredClientConfig is the input to NewRegisteredClient.
type RegisteredClientConfig struct {
	ID           fapi.ClientID
	RedirectURIs []fapi.RegisteredRedirectURI

	// ClientAssertionAlgorithm is the only algorithm this client's
	// private_key_jwt client assertions are accepted under. It is never
	// inferred from an assertion's own header.
	ClientAssertionAlgorithm fapi.SignatureAlgorithm

	// RequestObjectAlgorithm is the only algorithm this client's signed
	// request objects are accepted under. Leave zero if the client is
	// not permitted to submit request objects at all.
	RequestObjectAlgorithm fapi.SignatureAlgorithm

	// SenderConstrain selects how this client's tokens are
	// sender-constrained — SenderConstrainDPoP (the zero value) or
	// SenderConstrainMTLS. Every existing client config that never sets
	// this field keeps using DPoP, unchanged.
	SenderConstrain SenderConstrain

	// IDTokenEncryptionKeyManagement/IDTokenEncryptionContentEncryption,
	// if set (together — both zero, or both set), mean every ID token
	// issued to this client is encrypted (OIDC Core §2) using these
	// algorithms — the local record of this client's own
	// id_token_encrypted_response_alg/enc registration. Leave both zero
	// if the client did not register for encrypted ID tokens. Checked
	// against server.Config.Algorithms' own allow-list at issuance time,
	// not here: this type validates internal consistency only, not
	// server-wide policy, the same way ClientAssertionAlgorithm/
	// RequestObjectAlgorithm are validated for shape here and checked
	// against server-wide policy elsewhere.
	IDTokenEncryptionKeyManagement     fapi.KeyManagementAlgorithm
	IDTokenEncryptionContentEncryption fapi.ContentEncryptionAlgorithm

	// UserInfoEncryptionKeyManagement/UserInfoEncryptionContentEncryption
	// mirror IDTokenEncryptionKeyManagement/ContentEncryption exactly,
	// but for this client's own, independent
	// userinfo_encrypted_response_alg/enc registration (OIDC Core
	// §5.3.2) — a client may register for one without the other. Leave
	// both zero if the client did not register for encrypted UserInfo
	// responses.
	UserInfoEncryptionKeyManagement     fapi.KeyManagementAlgorithm
	UserInfoEncryptionContentEncryption fapi.ContentEncryptionAlgorithm

	// BackchannelAuthenticationRequestAlgorithm is the only algorithm
	// this client's signed CIBA backchannel authentication requests are
	// accepted under. Leave zero if the client is not permitted to use
	// CIBA at all — since FAPI-CIBA always requires a signed request
	// (unlike RequestObjectAlgorithm, whose signing is profile-dependent
	// for PAR), this single field doubles as this client's CIBA opt-in
	// flag.
	BackchannelAuthenticationRequestAlgorithm fapi.SignatureAlgorithm

	AllowedScopes []string
}

// NewRegisteredClient validates cfg and returns an immutable
// RegisteredClient.
func NewRegisteredClient(cfg RegisteredClientConfig) (RegisteredClient, error) {
	if cfg.ID == "" {
		return RegisteredClient{}, fmt.Errorf("storage: client ID is empty")
	}
	if len(cfg.RedirectURIs) == 0 {
		return RegisteredClient{}, fmt.Errorf("storage: client %q has no registered redirect URIs", cfg.ID)
	}
	if !cfg.ClientAssertionAlgorithm.IsValid() {
		return RegisteredClient{}, fmt.Errorf("storage: client %q has no valid client assertion algorithm", cfg.ID)
	}
	if cfg.RequestObjectAlgorithm != 0 && !cfg.RequestObjectAlgorithm.IsValid() {
		return RegisteredClient{}, fmt.Errorf("storage: client %q has an invalid request object algorithm", cfg.ID)
	}
	if cfg.SenderConstrain != SenderConstrainDPoP && cfg.SenderConstrain != SenderConstrainMTLS {
		return RegisteredClient{}, fmt.Errorf("storage: client %q has an invalid sender_constrain value", cfg.ID)
	}
	if cfg.BackchannelAuthenticationRequestAlgorithm != 0 && !cfg.BackchannelAuthenticationRequestAlgorithm.IsValid() {
		return RegisteredClient{}, fmt.Errorf("storage: client %q has an invalid backchannel authentication request algorithm", cfg.ID)
	}
	idTokenEncKeyMgmtSet := cfg.IDTokenEncryptionKeyManagement != 0
	idTokenEncContentEncSet := cfg.IDTokenEncryptionContentEncryption != 0
	if idTokenEncKeyMgmtSet != idTokenEncContentEncSet {
		return RegisteredClient{}, fmt.Errorf("storage: client %q must set both IDTokenEncryptionKeyManagement and IDTokenEncryptionContentEncryption, or neither", cfg.ID)
	}
	if idTokenEncKeyMgmtSet {
		if !cfg.IDTokenEncryptionKeyManagement.IsValid() {
			return RegisteredClient{}, fmt.Errorf("storage: client %q has an invalid ID token encryption key management algorithm", cfg.ID)
		}
		if !cfg.IDTokenEncryptionContentEncryption.IsValid() {
			return RegisteredClient{}, fmt.Errorf("storage: client %q has an invalid ID token encryption content encryption algorithm", cfg.ID)
		}
	}
	userInfoEncKeyMgmtSet := cfg.UserInfoEncryptionKeyManagement != 0
	userInfoEncContentEncSet := cfg.UserInfoEncryptionContentEncryption != 0
	if userInfoEncKeyMgmtSet != userInfoEncContentEncSet {
		return RegisteredClient{}, fmt.Errorf("storage: client %q must set both UserInfoEncryptionKeyManagement and UserInfoEncryptionContentEncryption, or neither", cfg.ID)
	}
	if userInfoEncKeyMgmtSet {
		if !cfg.UserInfoEncryptionKeyManagement.IsValid() {
			return RegisteredClient{}, fmt.Errorf("storage: client %q has an invalid UserInfo encryption key management algorithm", cfg.ID)
		}
		if !cfg.UserInfoEncryptionContentEncryption.IsValid() {
			return RegisteredClient{}, fmt.Errorf("storage: client %q has an invalid UserInfo encryption content encryption algorithm", cfg.ID)
		}
	}

	scopes := make(map[string]struct{}, len(cfg.AllowedScopes))
	for _, s := range cfg.AllowedScopes {
		if s == "" {
			return RegisteredClient{}, fmt.Errorf("storage: client %q has an empty allowed scope", cfg.ID)
		}
		scopes[s] = struct{}{}
	}

	redirectURIs := make([]fapi.RegisteredRedirectURI, len(cfg.RedirectURIs))
	copy(redirectURIs, cfg.RedirectURIs)

	return RegisteredClient{
		id:                                        cfg.ID,
		redirectURIs:                              redirectURIs,
		clientAssertionAlgorithm:                  cfg.ClientAssertionAlgorithm,
		requestObjectAlgorithm:                    cfg.RequestObjectAlgorithm,
		senderConstrain:                           cfg.SenderConstrain,
		allowedScopes:                             scopes,
		idTokenEncryptionKeyManagement:            cfg.IDTokenEncryptionKeyManagement,
		idTokenEncryptionContentEncryption:        cfg.IDTokenEncryptionContentEncryption,
		userInfoEncryptionKeyManagement:           cfg.UserInfoEncryptionKeyManagement,
		userInfoEncryptionContentEncryption:       cfg.UserInfoEncryptionContentEncryption,
		backchannelAuthenticationRequestAlgorithm: cfg.BackchannelAuthenticationRequestAlgorithm,
	}, nil
}

// ID returns the client's ID.
func (c RegisteredClient) ID() fapi.ClientID { return c.id }

// HasRedirectURI reports whether candidate is exactly one of this
// client's registered redirect URIs (RegisteredRedirectURI.Equal
// semantics — exact match, no normalization).
func (c RegisteredClient) HasRedirectURI(candidate string) bool {
	for _, u := range c.redirectURIs {
		if u.Equal(candidate) {
			return true
		}
	}
	return false
}

// ClientAssertionAlgorithm returns the algorithm this client's client
// assertions must be signed with.
func (c RegisteredClient) ClientAssertionAlgorithm() fapi.SignatureAlgorithm {
	return c.clientAssertionAlgorithm
}

// RequestObjectAlgorithm returns the algorithm this client's request
// objects must be signed with, and whether the client is permitted to
// submit request objects at all.
func (c RegisteredClient) RequestObjectAlgorithm() (algorithm fapi.SignatureAlgorithm, permitted bool) {
	return c.requestObjectAlgorithm, c.requestObjectAlgorithm != 0
}

// SenderConstrain returns how this client's tokens are
// sender-constrained.
func (c RegisteredClient) SenderConstrain() SenderConstrain {
	return c.senderConstrain
}

// IDTokenEncryption returns the algorithms this client's ID tokens must
// be encrypted with, and whether the client registered for encrypted ID
// tokens at all.
func (c RegisteredClient) IDTokenEncryption() (keyManagement fapi.KeyManagementAlgorithm, contentEncryption fapi.ContentEncryptionAlgorithm, enabled bool) {
	return c.idTokenEncryptionKeyManagement, c.idTokenEncryptionContentEncryption, c.idTokenEncryptionKeyManagement != 0
}

// UserInfoEncryption returns the algorithms this client's UserInfo
// responses must be encrypted with, and whether the client registered
// for encrypted UserInfo responses at all.
func (c RegisteredClient) UserInfoEncryption() (keyManagement fapi.KeyManagementAlgorithm, contentEncryption fapi.ContentEncryptionAlgorithm, enabled bool) {
	return c.userInfoEncryptionKeyManagement, c.userInfoEncryptionContentEncryption, c.userInfoEncryptionKeyManagement != 0
}

// BackchannelAuthenticationRequestAlgorithm returns the algorithm this
// client's signed CIBA backchannel authentication requests must be
// signed with, and whether the client is permitted to use CIBA at all.
func (c RegisteredClient) BackchannelAuthenticationRequestAlgorithm() (algorithm fapi.SignatureAlgorithm, permitted bool) {
	return c.backchannelAuthenticationRequestAlgorithm, c.backchannelAuthenticationRequestAlgorithm != 0
}

// AllowsScope reports whether scope is in this client's registered set
// of allowed scopes.
func (c RegisteredClient) AllowsScope(scope string) bool {
	_, ok := c.allowedScopes[scope]
	return ok
}

// ClientRepository resolves a registered client by ID.
type ClientRepository interface {
	ResolveClient(ctx context.Context, id fapi.ClientID) (RegisteredClient, error)
}
