package federation

import (
	"context"
	"crypto"
	"fmt"
	"net/url"

	"github.com/idfoundry/fapigo/fapihttp"
	intfed "github.com/idfoundry/fapigo/internal/federation"
)

// ResolveResponseContentType is the content type every successful
// Resolve Response MUST declare (OpenID Federation 1.0 §8.3.2).
const ResolveResponseContentType = "application/resolve-response+jwt"

// ResolveRequest describes one Resolve Request (OpenID Federation 1.0
// §8.3.1) to make against a resolve endpoint.
type ResolveRequest struct {
	// Endpoint is the resolve endpoint URL to query — typically read
	// from a peer's own federation_entity metadata
	// (federation_resolve_endpoint), out of band or from a prior
	// Resolve call's own ResolvedEntity.Metadata. Required.
	Endpoint string

	// Subject is the "sub" query parameter — the Entity Identifier being
	// resolved. Required.
	Subject string

	// TrustAnchor is the "trust_anchor" query parameter — the Entity
	// Identifier the resolve endpoint MUST use when resolving Subject's
	// metadata. Required. Must be one of this Resolver's own configured
	// Config.TrustAnchors: ResolveViaEndpoint establishes trust in the
	// response by resolving its own issuer against this same Resolver
	// (see ResolveViaEndpoint's own doc comment), so a Trust Anchor this
	// Resolver doesn't itself trust could never produce a response
	// ResolveViaEndpoint would accept regardless of what this field
	// names.
	TrustAnchor string

	// EntityTypes is zero or more "entity_type" query parameters — which
	// Entity Type(s) to resolve. Empty means every Entity Type (§8.3.1:
	// "If this parameter is not present, then all Entity Types are
	// returned").
	EntityTypes []string
}

// ResolveViaEndpoint performs a Resolve Request (OpenID Federation 1.0
// §8.3) against req.Endpoint instead of walking req.Subject's own Trust
// Chain hop by hop the way Resolve does — a resolve endpoint performs
// that walk as a service (typically operated by, but not limited to, a
// Trust Anchor: "Any Federation Entity MAY publish a
// federation_resolve_endpoint") and returns its own, already-resolved
// answer as a signed Resolve Response.
//
// Trust in the response rests on the exact same "resolve the issuer as
// its own peer, cryptographically, before trusting its signature"
// pattern VerifyTrustMark and CheckTrustMarkStatus already establish:
// the response's own "iss" claim (the entity operating the resolve
// endpoint) is resolved as a fresh Trust Chain against this Resolver's
// own Config.TrustAnchors before its signature is ever checked, using
// that resolution's own ResolvedEntity.JWKS — never a key the response
// itself merely claims to hold. This package does not additionally
// re-verify each entry of the response's own TrustChain claim — doing
// so unconditionally would defeat the purpose of a resolve endpoint at
// all, which exists precisely so a caller doesn't have to perform that
// walk itself; a caller wanting to independently audit it can still
// parse those raw entries with intfed.Parse.
//
// Only the no-client-authentication GET-request shape (§8.3.1) is
// covered — the POST-with-client-authentication variant is not
// implemented in this first version.
func (r *Resolver) ResolveViaEndpoint(ctx context.Context, req ResolveRequest) (intfed.ResolveResponseClaims, error) {
	if req.Endpoint == "" {
		return intfed.ResolveResponseClaims{}, fmt.Errorf("federation: resolve endpoint is empty")
	}
	if req.Subject == "" {
		return intfed.ResolveResponseClaims{}, fmt.Errorf("federation: subject entity ID is empty")
	}
	if req.TrustAnchor == "" {
		return intfed.ResolveResponseClaims{}, fmt.Errorf("federation: trust anchor is empty")
	}

	target, err := url.Parse(req.Endpoint)
	if err != nil {
		return intfed.ResolveResponseClaims{}, fmt.Errorf("federation: invalid resolve endpoint %q: %w", req.Endpoint, err)
	}
	if target.Scheme != "https" {
		return intfed.ResolveResponseClaims{}, fmt.Errorf("federation: resolve endpoint %q must use https", req.Endpoint)
	}
	q := target.Query()
	q.Set("sub", req.Subject)
	q.Set("trust_anchor", req.TrustAnchor)
	for _, entityType := range req.EntityTypes {
		q.Add("entity_type", entityType)
	}
	target.RawQuery = q.Encode()

	res, err := r.deps.HTTP.Fetch(ctx, fapihttp.FetchRequest{URL: target, ExpectedContentType: ResolveResponseContentType})
	if err != nil {
		return intfed.ResolveResponseClaims{}, fmt.Errorf("federation: fetch resolve response for %q: %w", req.Subject, err)
	}
	resp, err := intfed.ParseResolveResponse(string(res.Body))
	if err != nil {
		return intfed.ResolveResponseClaims{}, fmt.Errorf("federation: parse resolve response: %w", err)
	}

	issuer, err := r.Resolve(ctx, resp.ClaimedIssuer())
	if err != nil {
		return intfed.ResolveResponseClaims{}, fmt.Errorf("federation: resolve resolve-response issuer %q: %w", resp.ClaimedIssuer(), err)
	}

	now := r.deps.Clock.Now()
	claims, err := verifyAgainstCandidateKeys(issuer.JWKS, resp.KeyID(), resp.Algorithm(), func(pub crypto.PublicKey) (intfed.ResolveResponseClaims, error) {
		return resp.Verify(pub, intfed.ResolveResponseVerifyPolicy{
			ExpectedIssuer: resp.ClaimedIssuer(), ExpectedSubject: req.Subject,
			Algorithm: resp.Algorithm(), Now: now, MaxClockSkew: r.cfg.Limits.MaxClockSkew,
		})
	})
	if err != nil {
		return intfed.ResolveResponseClaims{}, fmt.Errorf("federation: resolve response: %w", err)
	}
	return claims, nil
}
