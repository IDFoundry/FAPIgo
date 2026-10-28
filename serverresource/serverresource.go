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
// For a server issuing pairwise subjects, NewVerifier also takes the
// server's means of mapping a pairwise sub back (a reversible deriver
// with the server's prefix, or a declared resolver), so the verifier's
// AuthorizationContext.InternalSubject is the user's internal subject
// and ClientSubject the sub the client knows.
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

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/resourceindicator"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/pairwise"
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
	// ResourceURLs are the protected endpoints' own external URLs, as
	// the verifier's resource.Config.ResourceURLs: each an origin,
	// optionally with a path prefix, that a DPoP proof's htu must name
	// ("https://as.example/userinfo", say). Required: the server's
	// configuration names no protected endpoint of its own, and the
	// request's Host header is the client's to choose.
	ResourceURLs []fapi.URL

	// Nonces enables DPoP nonce challenges at the protected endpoints
	// (RFC 9449 §9); nil leaves them disabled. It must not be the
	// server's own Dependencies.Nonces: nonce stores are keyed by nonce
	// value alone, so a shared store would let a nonce issued by one
	// role be accepted by the other. The verifier draws nonces from the
	// server's Dependencies.Random.
	Nonces storage.NonceStore

	// NonceLifetime bounds how long an issued nonce remains valid.
	// Required when Nonces is set.
	NonceLifetime time.Duration

	// Resource is the RFC 8707 resource indicator identifying the
	// protected endpoints this verifier guards — a Credential Issuer's
	// identifier, say — as clients name it in "resource" (and as it
	// appears in the server's Config.Resources, or is accepted by its
	// ResourcePolicy). A token is then accepted only when it was issued
	// for it, so a token issued for another resource server can't be
	// replayed here. One issued for several resources, this among them,
	// is accepted here too (see the resource package's doc). Empty, the
	// verifier accepts tokens addressed to the server's issuer
	// identifier: those issued without a resource indicator, as for a
	// UserInfo endpoint.
	Resource string

	// AcceptIssuerAudience, with Resource set, also accepts tokens
	// addressed to the server's issuer identifier: those whose client
	// named no resource. Use it while clients move to sending
	// "resource", then turn it off — until then any token issued without
	// a resource indicator is accepted here too. (A client confined by
	// storage.RegisteredClientConfig.AllowedResources is never issued
	// one, so it can't reach this resource server that way.)
	AcceptIssuerAudience bool
}

// NewVerifier returns a resource.Verifier accepting the access tokens a
// server built from cfg and deps issues, and rejecting those it revokes:
//
//   - server.JWTAccessTokens: verified against the server's own signing
//     keys (keys.LocalIssuerKeys) and algorithm, with cfg.Issuer as
//     issuer, Options.Resource (or cfg.Issuer without one) as audience,
//     and cfg.Limits.AccessTokenLifetime as the longest lifetime
//     accepted.
//   - server.OpaqueAccessTokens: looked up in the same Store, with
//     cfg.Issuer and the same audience checked against the ones the
//     server recorded.
//   - Revocation: deps.Revocation, which must also implement
//     resource.RevocationChecker (as memstore.RevocationStore does);
//     server.NoRevocation becomes resource.NoRevocationUntilExpiry with
//     cfg.Limits.AccessTokenLifetime as its MaxTokenLifetime, so a
//     production server declining revocation needs an
//     AccessTokenLifetime of at most 15 minutes to build a verifier.
//   - deps.Replay, deps.Clock, and cfg.Limits.MaxDPoPProofAge and
//     MaxClockSkew, as they are.
//   - Options.ResourceURLs, as the verifier's
//     resource.Config.ResourceURLs.
//   - cfg.Assurance and cfg.Deployment, as the verifier's own
//     resource.Config.Assurance and Deployment: a production
//     server gets a production verifier, which also checks
//     Options.Nonces.
//   - Pairwise subjects: with a reversible deriver (deps.PairwiseSubjects
//     implements pairwise.Lookup), it and cfg.Subjects.Prefix, as the
//     verifier's Dependencies.PairwiseSubjects and Config.PairwisePrefix,
//     so AuthorizationContext.InternalSubject is the end user's internal
//     subject and ClientSubject the client's pairwise one. With a one-way
//     deriver, deps.PairwiseSubjectResolver when set, as the verifier's
//     Dependencies.PairwiseSubjectResolver; without one the server issues
//     only OpaqueAccessTokens, whose records already keep the internal
//     subject.
//
// Any other access-token issuer or revocation sink is an error rather
// than a guess: build the resource.Verifier directly for those.
func NewVerifier(cfg server.Config, deps server.Dependencies, opts Options) (*resource.Verifier, error) {
	audience, err := verifierAudience(cfg, opts)
	if err != nil {
		return nil, err
	}
	accessTokens, err := accessTokenResolver(cfg, deps.AccessTokens, audience)
	if err != nil {
		return nil, err
	}
	revocation, err := revocationChecker(deps.Revocation, cfg.Limits.AccessTokenLifetime)
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
		Assurance:    assurance,
		Deployment:   deployment,
		ResourceURLs: opts.ResourceURLs,
	}
	rdeps := resource.Dependencies{
		AccessTokens: accessTokens,
		Replay:       deps.Replay,
		Revocation:   revocation,
		Clock:        deps.Clock,
	}
	if lookup, ok := deps.PairwiseSubjects.(pairwise.Lookup); ok {
		rdeps.PairwiseSubjects = lookup
		rcfg.PairwisePrefix = cfg.Subjects.Prefix
	}
	rdeps.PairwiseSubjectResolver = deps.PairwiseSubjectResolver
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

// audience is the access-token audience a verifier accepts: its own
// identifier, and any further ones it also accepts.
type audience struct {
	primary    string
	additional []string
}

// verifierAudience is the audience opts give a verifier for a server
// built from cfg: Options.Resource (with the issuer too under
// AcceptIssuerAudience), or the issuer without one.
func verifierAudience(cfg server.Config, opts Options) (audience, error) {
	issuer := cfg.Issuer.String()
	switch {
	case opts.Resource == "":
		if opts.AcceptIssuerAudience {
			return audience{}, errors.New("serverresource: Options.AcceptIssuerAudience requires Options.Resource")
		}
		return audience{primary: issuer}, nil
	case resourceindicator.Check(opts.Resource) != nil:
		return audience{}, fmt.Errorf("serverresource: Options.Resource: %w", resourceindicator.Check(opts.Resource))
	case opts.AcceptIssuerAudience:
		return audience{primary: opts.Resource, additional: []string{issuer}}, nil
	}
	return audience{primary: opts.Resource}, nil
}

func accessTokenResolver(cfg server.Config, issuer server.AccessTokenIssuer, aud audience) (resource.AccessTokenResolver, error) {
	switch t := issuer.(type) {
	case server.JWTAccessTokens:
		return jwtAccessTokens(cfg, t, aud)
	case *server.JWTAccessTokens:
		if t != nil {
			return jwtAccessTokens(cfg, *t, aud)
		}
	case server.OpaqueAccessTokens:
		return opaqueAccessTokens(cfg, t, aud)
	case *server.OpaqueAccessTokens:
		if t != nil {
			return opaqueAccessTokens(cfg, *t, aud)
		}
	}
	return nil, fmt.Errorf("serverresource: access token issuer %T is not server.JWTAccessTokens or server.OpaqueAccessTokens", issuer)
}

func jwtAccessTokens(cfg server.Config, t server.JWTAccessTokens, aud audience) (resource.AccessTokenResolver, error) {
	issuerKeys, err := keys.NewLocalIssuerKeys(cfg.Issuer, t.Keys)
	if err != nil {
		return nil, fmt.Errorf("serverresource: %w", err)
	}
	resolver, err := resource.NewJWTAccessTokens(issuerKeys, cfg.Issuer, aud.primary, t.Algorithm, cfg.Limits.AccessTokenLifetime, maxKeyCandidates)
	if err != nil {
		return nil, fmt.Errorf("serverresource: %w", err)
	}
	resolver.AdditionalAudiences = aud.additional
	// Accept every token the server issues: it refuses to issue one
	// over this.
	resolver.MaxTokenBytes = cfg.Limits.MaxAccessTokenBytes()
	return resolver, nil
}

func opaqueAccessTokens(cfg server.Config, t server.OpaqueAccessTokens, aud audience) (resource.AccessTokenResolver, error) {
	resolver, err := resource.NewOpaqueAccessTokens(t.Store, cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("serverresource: %w", err)
	}
	resolver.Audience = aud.primary
	resolver.AdditionalAudiences = aud.additional
	return resolver, nil
}

func revocationChecker(sink server.RevocationSink, accessTokenLifetime time.Duration) (resource.RevocationChecker, error) {
	switch sink.(type) {
	case server.NoRevocation, *server.NoRevocation:
		return resource.NoRevocationUntilExpiry{MaxTokenLifetime: accessTokenLifetime}, nil
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
