package federation

import (
	"crypto"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"

	fapi "github.com/idfoundry/fapigo"
	intfed "github.com/idfoundry/fapigo/internal/federation"
)

// ResolveIssueConfig configures a ResolveIssuer's own Entity Identifier.
type ResolveIssueConfig struct {
	// EntityID is this entity's own Entity Identifier — the "iss" every
	// Resolve Response it signs carries: the entity operating the
	// resolve endpoint, not necessarily (though commonly) a Trust
	// Anchor — OpenID Federation 1.0 §8.7's own "Any Federation Entity
	// MAY publish a federation_resolve_endpoint" applies identically
	// here (§8.3). Required.
	EntityID string
}

// ResolveIssueDependencies are a ResolveIssuer's injected collaborators.
// NewResolveIssuer rejects a nil/zero value for every field — there is
// no implicit default signer or clock.
type ResolveIssueDependencies struct {
	// Signer produces every Resolve Response's signature — this
	// entity's own federation key.
	Signer crypto.Signer

	// Algorithm Signer signs with.
	Algorithm fapi.SignatureAlgorithm

	// KeyID identifies Signer's key within this entity's own published
	// jwks — recorded in every Resolve Response's "kid" header. Required
	// — OpenID Federation 1.0 §8.3.2: "The resolve response JWT MUST
	// include the kid (Key ID) header parameter."
	KeyID string

	Clock Clock
}

// ResolveIssuer signs Resolve Responses (OpenID Federation 1.0 §8.3.2)
// for an entity serving a federation_resolve_endpoint. Construct one
// with NewResolveIssuer.
//
// Unlike SelfIssuer/SubordinateIssuer/TrustMarkIssuer, ResolveIssuer
// does not itself perform any Trust Chain resolution — Response takes
// an already-resolved ResolvedEntity (a caller's own *Resolver.Resolve
// result) and signs a response reporting it, rather than owning a
// *Resolver of its own: the resolution work is identical to what
// Resolve already does for any other caller, so there is no separate
// "resolve, but for serving a response" code path to own.
//
// Trust Mark inclusion (§8.3's own "and Trust Marks for an Entity",
// the response's OPTIONAL "trust_marks" claim) is not implemented in
// this version — Response never sets it. See doc.go.
type ResolveIssuer struct {
	cfg  ResolveIssueConfig
	deps ResolveIssueDependencies
}

// NewResolveIssuer validates cfg and deps and returns a ResolveIssuer.
func NewResolveIssuer(cfg ResolveIssueConfig, deps ResolveIssueDependencies) (*ResolveIssuer, error) {
	if cfg.EntityID == "" {
		return nil, fmt.Errorf("federation: config: entity ID is required")
	}
	if err := ValidEntityID(cfg.EntityID); err != nil {
		return nil, fmt.Errorf("federation: config: %w", err)
	}
	if deps.Signer == nil {
		return nil, fmt.Errorf("federation: dependencies: signer is required")
	}
	if deps.KeyID == "" {
		return nil, fmt.Errorf("federation: dependencies: key id is required")
	}
	if deps.Clock == nil {
		return nil, fmt.Errorf("federation: dependencies: clock is required")
	}
	return &ResolveIssuer{cfg: cfg, deps: deps}, nil
}

// Response signs a Resolve Response (OpenID Federation 1.0 §8.3.2) for
// resolved — the result of a caller's own resolver.Resolve(ctx,
// subject) — answering a Resolve Request that named trustAnchors (its
// own "trust_anchor" parameter, which MAY repeat — see
// ResolveRequestFromHTTP) and, optionally, entityTypes (its own
// "entity_type" parameter; empty returns every Entity Type
// resolved.Metadata carries).
//
// Response itself checks resolved.TrustAnchor is one of trustAnchors —
// §8.3.1's own "trust_anchor request parameter MAY occur multiple
// times, in which case[] the resolver MAY return a successful resolve
// response using any of the Trust Anchor values provided" — rather than
// leaving that to the caller; Response has no second resolution attempt
// to try a different one if it isn't.
//
// The response's own "exp" claim is set from resolved.ExpiresAt exactly
// (§8.3.2: "MUST be the minimum of the exp value of the Trust Chain
// from which the resolve response was derived") — Response fails with a
// clear error if it's already passed, rather than silently issuing an
// already-expired response.
func (i *ResolveIssuer) Response(resolved ResolvedEntity, trustAnchors, entityTypes []string) (string, error) {
	if len(resolved.Tokens) == 0 {
		return "", fmt.Errorf("federation: resolved entity has no trust chain tokens")
	}
	if !slices.Contains(trustAnchors, resolved.TrustAnchor) {
		return "", fmt.Errorf("federation: resolved trust anchor %q is not among the requested trust anchors %v", resolved.TrustAnchor, trustAnchors)
	}

	metadata := resolved.Metadata
	if len(entityTypes) > 0 {
		metadata = filterResolvedEntityTypes(metadata, entityTypes)
	}

	now := i.deps.Clock.Now()
	lifetime := resolved.ExpiresAt.Sub(now)
	if lifetime <= 0 {
		return "", fmt.Errorf("federation: resolved entity's trust chain already expired at %s", resolved.ExpiresAt)
	}

	return intfed.CreateResolveResponse(intfed.CreateResolveResponseParams{
		Signer: i.deps.Signer, Algorithm: i.deps.Algorithm, KeyID: i.deps.KeyID,
		Issuer: i.cfg.EntityID, Subject: resolved.EntityID,
		Now: now, Lifetime: lifetime,
		Metadata: metadata, TrustChain: resolved.Tokens,
	})
}

func filterResolvedEntityTypes(metadata map[string]json.RawMessage, entityTypes []string) map[string]json.RawMessage {
	filtered := make(map[string]json.RawMessage, len(entityTypes))
	for entityType, v := range metadata {
		if slices.Contains(entityTypes, entityType) {
			filtered[entityType] = v
		}
	}
	return filtered
}

// ResolveRequestFromHTTP extracts and validates a Resolve Request
// (OpenID Federation 1.0 §8.3.1) from r's query parameters: "sub"
// (REQUIRED), "trust_anchor" (REQUIRED, and MAY repeat — every value is
// individually acceptable, per §8.3.1's own "the resolver MAY return a
// successful resolve response using any of the Trust Anchor values
// provided"; pass trustAnchors to Response unchanged), and
// "entity_type" (OPTIONAL, MAY also repeat). Returns a *Error
// (ErrorInvalidRequest, HTTP 400, ready to pass to WriteJSON) when
// "sub" or "trust_anchor" is absent, or "sub" is not a valid Entity
// Identifier.
//
// Only GET requests with query parameters are supported — this
// package's own §8.3.1 text notes a client-authenticated request uses
// POST with the same parameters in the body instead, which this helper
// does not parse; an embedder needing that variant reads r.PostForm's
// own values directly.
func ResolveRequestFromHTTP(r *http.Request) (subject string, trustAnchors, entityTypes []string, err error) {
	query := r.URL.Query()
	subject = query.Get("sub")
	if subject == "" {
		return "", nil, nil, newError(ErrorInvalidRequest, http.StatusBadRequest, `"sub" is required`, nil)
	}
	if verr := ValidEntityID(subject); verr != nil {
		return "", nil, nil, newError(ErrorInvalidRequest, http.StatusBadRequest, `"sub" is not a valid Entity Identifier`, verr)
	}
	trustAnchors = query["trust_anchor"]
	if len(trustAnchors) == 0 {
		return "", nil, nil, newError(ErrorInvalidRequest, http.StatusBadRequest, `"trust_anchor" is required`, nil)
	}
	return subject, trustAnchors, query["entity_type"], nil
}
