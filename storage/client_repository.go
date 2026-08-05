package storage

import (
	"context"
	"fmt"

	fapi "github.com/osanderson/go-fapi"
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
	allowedScopes            map[string]struct{}
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
		id:                       cfg.ID,
		redirectURIs:             redirectURIs,
		clientAssertionAlgorithm: cfg.ClientAssertionAlgorithm,
		requestObjectAlgorithm:   cfg.RequestObjectAlgorithm,
		allowedScopes:            scopes,
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
