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
	// Endpoint is the resolve endpoint URL to query: the
	// federation_resolve_endpoint of the resolver named by
	// ExpectedIssuer, from its federation_entity metadata or out of
	// band. Required. Where the URL came from doesn't decide whom the
	// response is trusted from: ExpectedIssuer does.
	Endpoint string

	// ExpectedIssuer is the Entity Identifier of the resolver this
	// caller trusts to answer: the Resolve Response must be issued
	// ("iss") and signed by exactly this entity, or ResolveViaEndpoint
	// refuses it. Required. OpenID Federation 1.0 lets any Federation
	// Entity run a resolve endpoint and leaves choosing a trusted
	// resolver to the caller (§11); the resolver answers for the
	// subject's Resolved Metadata, so it must be one the caller trusts,
	// typically the Trust Anchor itself (§17: "that entity should be
	// both Trust Anchor and Resolver"). Without it, any member of the
	// federation could sign a response about any subject, with
	// metadata of its choosing.
	ExpectedIssuer string

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
// Trust in the response rests on two checks. First, its "iss" must be
// req.ExpectedIssuer, the resolver the caller chose to trust, checked
// before anything else is fetched. Second, that issuer is resolved as a
// fresh Trust Chain against this Resolver's own Config.TrustAnchors,
// and the response's signature checked against that resolution's own
// ResolvedEntity.JWKS — never a key the response itself merely claims
// to hold — the same pattern VerifyTrustMark and CheckTrustMarkStatus
// use. This package does not additionally
// re-verify each entry of the response's own TrustChain claim — doing
// so unconditionally would defeat the purpose of a resolve endpoint at
// all, which exists precisely so a caller doesn't have to perform that
// walk itself. The entries stay available raw, in TrustChain, for a
// caller that wants to audit them with its own JWT handling.
//
// Only the no-client-authentication GET-request shape (§8.3.1) is
// covered — the POST-with-client-authentication variant is not
// implemented in this first version.
func (r *Resolver) ResolveViaEndpoint(ctx context.Context, req ResolveRequest) (ResolveResponseClaims, error) {
	if req.Endpoint == "" {
		return ResolveResponseClaims{}, fmt.Errorf("federation: resolve endpoint is empty")
	}
	if req.Subject == "" {
		return ResolveResponseClaims{}, fmt.Errorf("federation: subject entity ID is empty")
	}
	if req.TrustAnchor == "" {
		return ResolveResponseClaims{}, fmt.Errorf("federation: trust anchor is empty")
	}
	if err := ValidEntityID(req.ExpectedIssuer); err != nil {
		return ResolveResponseClaims{}, fmt.Errorf("federation: expected resolver issuer: %w", err)
	}

	target, err := url.Parse(req.Endpoint)
	if err != nil {
		return ResolveResponseClaims{}, fmt.Errorf("federation: invalid resolve endpoint %q: %w", req.Endpoint, err)
	}
	if target.Scheme != "https" {
		return ResolveResponseClaims{}, fmt.Errorf("federation: resolve endpoint %q must use https", req.Endpoint)
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
		return ResolveResponseClaims{}, fmt.Errorf("federation: fetch resolve response for %q: %w", req.Subject, err)
	}
	resp, err := intfed.ParseResolveResponse(string(res.Body))
	if err != nil {
		return ResolveResponseClaims{}, fmt.Errorf("federation: parse resolve response: %w", err)
	}

	// Checked before the issuer is resolved, so a response naming some
	// other issuer neither gets trusted nor makes this Resolver fetch
	// that issuer's Trust Chain.
	if resp.ClaimedIssuer() != req.ExpectedIssuer {
		return ResolveResponseClaims{}, fmt.Errorf("federation: resolve response is issued by %q, not the expected resolver %q", resp.ClaimedIssuer(), req.ExpectedIssuer)
	}

	issuer, err := r.Resolve(ctx, req.ExpectedIssuer)
	if err != nil {
		return ResolveResponseClaims{}, fmt.Errorf("federation: resolve resolve-response issuer %q: %w", req.ExpectedIssuer, err)
	}

	now := r.deps.Clock.Now()
	claims, err := verifyAgainstCandidateKeys(issuer.JWKS, resp.KeyID(), resp.Algorithm(), func(pub crypto.PublicKey) (ResolveResponseClaims, error) {
		return resp.Verify(pub, intfed.ResolveResponseVerifyPolicy{
			ExpectedIssuer: req.ExpectedIssuer, ExpectedSubject: req.Subject,
			Algorithm: resp.Algorithm(), Now: now, MaxClockSkew: r.cfg.Limits.MaxClockSkew,
		})
	})
	if err != nil {
		return ResolveResponseClaims{}, fmt.Errorf("federation: resolve response: %w", err)
	}
	return claims, nil
}
