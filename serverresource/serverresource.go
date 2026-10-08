// Package serverresource builds a resource.Verifier for protected
// endpoints hosted in the same process as a server.Server — a UserInfo
// endpoint, or a Credential Issuer's Credential Endpoint — from the
// Config and Dependencies that server was built with.
//
// Wiring such a verifier by hand has one mistake nothing reports: the
// verifier must check revocation against the same store the server
// revokes into (on authorization code reuse, RFC 6749 §4.1.2, and on
// Server.RevokeGrant), or a revoked access token keeps working at the
// protected endpoints.
// NewVerifier takes that store, the access-token format, the replay
// store, the clock and the DPoP limits from the server's own, so they
// always match.
//
// It is only for a verifier sharing the server's process and stores. A
// resource server deployed separately builds its resource.Verifier
// directly, against backends shared with the authorization server.
//
// For a UserInfo endpoint, UserInfoClaims narrows the identity claims to
// those the access token's client requested and was granted, and
// SignUserInfoResponse signs them (encrypting them for a client that
// registered for it) for the client the access token was issued to, and
// for its subject only.
//
// server and resource never import each other (ARCHITECTURE.md design
// rule 14); this package imports both, so neither has to.
package serverresource

import (
	"errors"
	"fmt"
	"reflect"
	"time"

	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/resource"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
)

// maxKeyCandidates bounds the signing keys a JWT access token is checked
// against. The server's own tokens always name their key, so this is one
// key; the bound only limits a token naming none, and the candidates are
// the server's own current keys (keys.LocalIssuerKeys), never a fetched
// key set.
const maxKeyCandidates = 8

// Options are the verifier's own settings, which have no counterpart in
// the server's configuration.
type Options struct {
	// Nonces enables DPoP nonce challenges at the protected endpoints
	// (RFC 9449 §9); nil leaves them disabled. It must not be the
	// server's own Dependencies.Nonces: nonce stores are keyed by nonce
	// value alone, so a shared store would let a nonce issued by one
	// role be consumed by the other. The verifier draws nonces from the
	// server's Dependencies.Random.
	Nonces storage.NonceStore

	// NonceLifetime bounds how long an issued nonce remains valid.
	// Required when Nonces is set.
	NonceLifetime time.Duration
}

// NewVerifier returns a resource.Verifier accepting the access tokens a
// server built from cfg and deps issues, and rejecting those it revokes:
//
//   - server.JWTAccessTokens: verified against the server's own signing
//     keys (keys.LocalIssuerKeys) and algorithm, with cfg.Issuer as both
//     issuer and audience, and cfg.Limits.AccessTokenLifetime as the
//     longest lifetime accepted.
//   - server.OpaqueAccessTokens: looked up in the same Store.
//   - Revocation: deps.Revocation, which must also implement
//     resource.RevocationChecker (as memstore.RevocationStore does);
//     server.NoRevocation becomes resource.NoRevocation.
//   - deps.Replay, deps.Clock, and cfg.Limits.MaxDPoPProofAge and
//     MaxClockSkew, as they are.
//   - cfg.Assurance and cfg.Deployment, as the verifier's own
//     resource.Config.Assurance and Deployment: a production
//     server gets a production verifier, which also checks
//     Options.Nonces.
//
// Any other access-token issuer or revocation sink is an error rather
// than a guess: build the resource.Verifier directly for those.
func NewVerifier(cfg server.Config, deps server.Dependencies, opts Options) (*resource.Verifier, error) {
	accessTokens, err := accessTokenResolver(cfg, deps.AccessTokens)
	if err != nil {
		return nil, err
	}
	revocation, err := revocationChecker(deps.Revocation)
	if err != nil {
		return nil, err
	}

	assurance, err := resourceAssurance(cfg.Assurance)
	if err != nil {
		return nil, err
	}
	deployment, err := resourceDeployment(cfg.Deployment)
	if err != nil {
		return nil, err
	}
	rcfg := resource.Config{
		Limits: resource.Limits{
			MaxDPoPProofAge: cfg.Limits.MaxDPoPProofAge,
			MaxClockSkew:    cfg.Limits.MaxClockSkew,
		},
		Assurance:  assurance,
		Deployment: deployment,
	}
	rdeps := resource.Dependencies{
		AccessTokens: accessTokens,
		Replay:       deps.Replay,
		Revocation:   revocation,
		Clock:        deps.Clock,
	}
	if opts.Nonces != nil {
		if sameValue(opts.Nonces, deps.Nonces) {
			return nil, errors.New("serverresource: Options.Nonces must not be the server's own Dependencies.Nonces")
		}
		rcfg.Limits.DPoPNonceLifetime = opts.NonceLifetime
		rdeps.Nonces = opts.Nonces
		rdeps.Random = deps.Random
	}
	v, err := resource.NewVerifier(rcfg, rdeps)
	if err != nil {
		return nil, fmt.Errorf("serverresource: %w", err)
	}
	return v, nil
}

// resourceAssurance maps the server's assurance level to the
// verifier's.
func resourceAssurance(level server.AssuranceLevel) (resource.AssuranceLevel, error) {
	switch level {
	case server.AssuranceDevelopment:
		return resource.AssuranceDevelopment, nil
	case server.AssuranceProduction:
		return resource.AssuranceProduction, nil
	}
	return 0, errors.New("serverresource: the server's assurance level is invalid")
}

func accessTokenResolver(cfg server.Config, issuer server.AccessTokenIssuer) (resource.AccessTokenResolver, error) {
	switch t := issuer.(type) {
	case server.JWTAccessTokens:
		return jwtAccessTokens(cfg, t)
	case *server.JWTAccessTokens:
		if t != nil {
			return jwtAccessTokens(cfg, *t)
		}
	case server.OpaqueAccessTokens:
		return opaqueAccessTokens(t)
	case *server.OpaqueAccessTokens:
		if t != nil {
			return opaqueAccessTokens(*t)
		}
	}
	return nil, fmt.Errorf("serverresource: access token issuer %T is not server.JWTAccessTokens or server.OpaqueAccessTokens", issuer)
}

func jwtAccessTokens(cfg server.Config, t server.JWTAccessTokens) (resource.AccessTokenResolver, error) {
	issuerKeys, err := keys.NewLocalIssuerKeys(cfg.Issuer, t.Keys)
	if err != nil {
		return nil, fmt.Errorf("serverresource: %w", err)
	}
	// The audience is the issuer: every grant issues access tokens with
	// aud set to cfg.Issuer.
	resolver, err := resource.NewJWTAccessTokens(issuerKeys, cfg.Issuer, cfg.Issuer.String(), t.Algorithm, cfg.Limits.AccessTokenLifetime, maxKeyCandidates)
	if err != nil {
		return nil, fmt.Errorf("serverresource: %w", err)
	}
	return resolver, nil
}

func opaqueAccessTokens(t server.OpaqueAccessTokens) (resource.AccessTokenResolver, error) {
	resolver, err := resource.NewOpaqueAccessTokens(t.Store)
	if err != nil {
		return nil, fmt.Errorf("serverresource: %w", err)
	}
	return resolver, nil
}

func revocationChecker(sink server.RevocationSink) (resource.RevocationChecker, error) {
	switch sink.(type) {
	case server.NoRevocation, *server.NoRevocation:
		return resource.NoRevocation{}, nil
	}
	checker, ok := sink.(resource.RevocationChecker)
	if !ok {
		return nil, fmt.Errorf("serverresource: revocation sink %T does not implement resource.RevocationChecker, so the verifier can't see what the server revokes", sink)
	}
	return checker, nil
}

// sameValue reports whether a and b hold the same comparable value. A
// type can be comparable yet hold an uncomparable value in an interface
// field, where == panics; such values are reported as different.
func sameValue(a, b any) (same bool) {
	if a == nil || b == nil || reflect.TypeOf(a) != reflect.TypeOf(b) || !reflect.TypeOf(a).Comparable() {
		return false
	}
	defer func() {
		if recover() != nil {
			same = false
		}
	}()
	return a == b
}

// resourceDeployment maps the server's Deployment to the verifier's.
// The zero value maps to zero, which resource.NewVerifier refuses under
// AssuranceProduction as server.New does.
func resourceDeployment(d server.Deployment) (resource.Deployment, error) {
	switch d {
	case 0:
		return 0, nil
	case server.DeploymentSingleInstance:
		return resource.DeploymentSingleInstance, nil
	case server.DeploymentHorizontallyScaled:
		return resource.DeploymentHorizontallyScaled, nil
	}
	return 0, errors.New("serverresource: the server's deployment is invalid")
}
