package federation

import (
	"context"
	"crypto"
	"encoding/json"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/fapihttp"
	intfed "github.com/idfoundry/fapigo/internal/federation"
	"github.com/idfoundry/fapigo/internal/jose"
)

// VerifyTrustMark establishes trust in one of subjectID's own declared
// Trust Marks (see ResolvedEntity.TrustMarks) and returns its verified
// claims. OpenID Federation 1.0 §7's own "the trust in the Trust Mark
// Issuer comes before the trust in the trust mark" is implemented
// literally: raw.TrustMark's own unverified "iss" claim is resolved as
// a fresh Trust Chain against this Resolver's own Trust Anchors (the
// same ones subjectID itself was resolved against) before the Trust
// Mark's signature is ever checked, using the issuer's own
// ResolvedEntity.JWKS — the key set its immediate superior vouches for,
// not merely what the issuer claims about itself.
//
// If the Trust Anchor that vouched for the issuer names this Trust
// Mark's own type in its own "trust_mark_owners" claim (§7.2), a
// "delegation" claim proving the issuer was actually authorized by that
// type's real owner is additionally required and checked — see
// checkTrustMarkDelegation. This first version does not implement the
// Trust Mark Status or Trust Marked Entities Listing endpoints (§8/§9)
// — see internal/federation's own doc.go for exactly what is and is
// not covered.
func (r *Resolver) VerifyTrustMark(ctx context.Context, subjectID string, raw intfed.RawTrustMark, accreditation TrustMarkAccreditation) (intfed.TrustMarkClaims, error) {
	if subjectID == "" {
		return intfed.TrustMarkClaims{}, fmt.Errorf("federation: subject entity ID is empty")
	}
	if accreditation != RequireFederationAccreditation && accreditation != AcceptAnyFederationIssuer {
		return intfed.TrustMarkClaims{}, fmt.Errorf("federation: trust mark accreditation policy is required (RequireFederationAccreditation or AcceptAnyFederationIssuer)")
	}
	tm, err := intfed.ParseTrustMark(raw.TrustMark)
	if err != nil {
		return intfed.TrustMarkClaims{}, fmt.Errorf("federation: parse trust mark: %w", err)
	}
	// OpenID Federation 1.0 §7: a Trust Mark MUST carry the kid of its
	// signing key.
	if tm.KeyID() == "" {
		return intfed.TrustMarkClaims{}, fmt.Errorf("federation: trust mark has no kid header")
	}

	issuer, err := r.Resolve(ctx, tm.ClaimedIssuer())
	if err != nil {
		return intfed.TrustMarkClaims{}, fmt.Errorf("federation: resolve trust mark issuer %q: %w", tm.ClaimedIssuer(), err)
	}
	claims, err := r.verifyTrustMarkAgainstJWKS(tm, issuer.JWKS, subjectID, raw.TrustMarkType, tm.Algorithm(), r.deps.Clock.Now())
	if err != nil {
		return intfed.TrustMarkClaims{}, fmt.Errorf("federation: trust mark: %w", err)
	}
	trustAnchor, err := r.Resolve(ctx, issuer.TrustAnchor)
	if err != nil {
		return intfed.TrustMarkClaims{}, fmt.Errorf("federation: resolve trust anchor %q: %w", issuer.TrustAnchor, err)
	}
	if accreditation == RequireFederationAccreditation {
		if err := checkTrustMarkAccreditation(trustAnchor, claims); err != nil {
			return intfed.TrustMarkClaims{}, fmt.Errorf("federation: trust mark: %w", err)
		}
	}
	if err := r.checkTrustMarkDelegation(trustAnchor, tm, claims); err != nil {
		return intfed.TrustMarkClaims{}, fmt.Errorf("federation: trust mark: %w", err)
	}
	return claims, nil
}

// TrustMarkAccreditation is VerifyTrustMark's required choice of whether
// the federation itself must accredit a Trust Mark's issuer. Verifying a
// Trust Mark (OpenID Federation 1.0 §7.3) only establishes that its
// issuer is some member of the federation — any member, including the
// entity the mark is about, can sign one of any type. Whether that
// issuer is recognised for the mark's type is the Trust Anchor's
// "trust_mark_issuers" claim, a federation policy (§17.6) this choice
// decides whether to apply. There is no default.
type TrustMarkAccreditation uint8

const (
	_ TrustMarkAccreditation = iota

	// RequireFederationAccreditation accepts a Trust Mark only if the
	// Trust Anchor used to trust its issuer lists the mark's
	// trust_mark_type in its "trust_mark_issuers" claim, and either that
	// type's list is empty (anyone may issue it) or it names the issuer.
	RequireFederationAccreditation

	// AcceptAnyFederationIssuer accepts a Trust Mark from any issuer
	// with a valid Trust Chain, leaving accreditation to the caller —
	// for a mark whose accreditation authority is established out of
	// band (§17.6). Check TrustMarkClaims.Issuer yourself before
	// relying on it.
	AcceptAnyFederationIssuer
)

// checkTrustMarkAccreditation applies RequireFederationAccreditation
// against trustAnchor's own "trust_mark_issuers" claim.
func checkTrustMarkAccreditation(trustAnchor ResolvedEntity, claims intfed.TrustMarkClaims) error {
	issuers, listed := trustAnchor.TrustMarkIssuers[claims.TrustMarkType]
	if !listed {
		return fmt.Errorf("trust_mark_type %q is not in trust anchor %q's trust_mark_issuers", claims.TrustMarkType, trustAnchor.EntityID)
	}
	if len(issuers) > 0 && !slices.Contains(issuers, claims.Issuer) {
		return fmt.Errorf("trust anchor %q does not accredit %q to issue trust_mark_type %q", trustAnchor.EntityID, claims.Issuer, claims.TrustMarkType)
	}
	return nil
}

// checkTrustMarkDelegation requires and validates a "delegation" claim
// when trustAnchor names the mark's type in its "trust_mark_owners"
// claim (OpenID Federation 1.0 §7.3 steps 8-9).
func (r *Resolver) checkTrustMarkDelegation(trustAnchor ResolvedEntity, tm intfed.TrustMark, claims intfed.TrustMarkClaims) error {
	owner, required := trustAnchor.TrustMarkOwners[claims.TrustMarkType]
	if !required {
		return nil
	}
	if tm.ClaimedDelegation() == "" {
		return fmt.Errorf("trust_mark_type %q is named in the trust anchor's own trust_mark_owners claim, but the trust mark carries no delegation claim", claims.TrustMarkType)
	}
	delegation, err := intfed.ParseTrustMarkDelegation(tm.ClaimedDelegation())
	if err != nil {
		return fmt.Errorf("parse trust mark delegation: %w", err)
	}
	if _, err := r.verifyTrustMarkDelegationAgainstJWKS(delegation, owner.JWKS, owner.Subject, claims.Issuer, claims.TrustMarkType, delegation.Algorithm(), r.deps.Clock.Now()); err != nil {
		return fmt.Errorf("trust mark delegation: %w", err)
	}
	return nil
}

// verifyAgainstCandidateKeys resolves jwksRaw's own keys matching
// algorithm (and kid, if non-empty), calling verify with each
// candidate's public key until one succeeds. Shared by every "parsed
// token type + its own Verify(pub, policy) signature" this file checks
// against a resolved JWKS (TrustMark, TrustMarkDelegation,
// TrustMarkStatusResponse) — extracted once a third near-identical copy
// of this exact loop was about to exist (see PR #274's own
// SonarCloud-duplication lesson for why this is done proactively here
// rather than reactively after a gate failure).
func verifyAgainstCandidateKeys[C any](jwksRaw json.RawMessage, kid string, algorithm fapi.SignatureAlgorithm, verify func(pub crypto.PublicKey) (C, error)) (C, error) {
	var zero C
	candidates, err := jose.ParseJWKSet(jwksRaw)
	if err != nil {
		return zero, fmt.Errorf("parse jwks: %w", err)
	}
	var lastErr error
	tried := false
	for _, c := range candidates {
		if c.Algorithm != algorithm {
			continue
		}
		if kid != "" && c.KeyID != kid {
			continue
		}
		tried = true
		claims, err := verify(c.PublicKey)
		if err == nil {
			return claims, nil
		}
		lastErr = err
	}
	if !tried {
		return zero, fmt.Errorf("no candidate key found for algorithm %v kid %q among %d keys", algorithm, kid, len(candidates))
	}
	return zero, fmt.Errorf("signature verification failed against every candidate key: %w", lastErr)
}

// verifyTrustMarkAgainstJWKS verifies tm against jwksRaw's own
// candidate keys.
func (r *Resolver) verifyTrustMarkAgainstJWKS(tm intfed.TrustMark, jwksRaw json.RawMessage, expectedSubject, expectedTrustMarkType string, algorithm fapi.SignatureAlgorithm, now time.Time) (intfed.TrustMarkClaims, error) {
	policy := intfed.TrustMarkVerifyPolicy{
		ExpectedSubject: expectedSubject, ExpectedTrustMarkType: expectedTrustMarkType,
		Algorithm: algorithm, Now: now, MaxClockSkew: r.cfg.Limits.MaxClockSkew,
	}
	return verifyAgainstCandidateKeys(jwksRaw, tm.KeyID(), algorithm, func(pub crypto.PublicKey) (intfed.TrustMarkClaims, error) {
		return tm.Verify(pub, policy)
	})
}

// verifyTrustMarkDelegationAgainstJWKS verifies d against jwksRaw's own
// candidate keys.
func (r *Resolver) verifyTrustMarkDelegationAgainstJWKS(d intfed.TrustMarkDelegation, jwksRaw json.RawMessage, expectedIssuer, expectedSubject, expectedTrustMarkType string, algorithm fapi.SignatureAlgorithm, now time.Time) (intfed.TrustMarkDelegationClaims, error) {
	policy := intfed.TrustMarkDelegationVerifyPolicy{
		ExpectedIssuer: expectedIssuer, ExpectedSubject: expectedSubject, ExpectedTrustMarkType: expectedTrustMarkType,
		Algorithm: algorithm, Now: now, MaxClockSkew: r.cfg.Limits.MaxClockSkew,
	}
	return verifyAgainstCandidateKeys(jwksRaw, d.KeyID(), algorithm, func(pub crypto.PublicKey) (intfed.TrustMarkDelegationClaims, error) {
		return d.Verify(pub, policy)
	})
}

// CheckTrustMarkStatus queries trustMarkToken's own issuer for its
// current status (OpenID Federation 1.0 §8) and returns the verified
// response claims. §8: "The query MUST be sent to the Trust Mark
// Issuer" — trustMarkToken's own unverified "iss" claim names it, and
// that issuer is resolved as a fresh Trust Chain (the same way
// VerifyTrustMark already establishes trust in a Trust Mark's issuer)
// before its published federation_trust_mark_status_endpoint is ever
// queried or its response ever trusted.
//
// A Trust Mark Issuer that answers with HTTP 404 for an unknown Trust
// Mark (§8's own "MUST respond with 404") surfaces here as
// fapihttp.ErrUnexpectedStatus wrapping that status code — the same as
// any other unexpected status from a Fetch/Post call, not a dedicated
// typed error in this first version.
func (r *Resolver) CheckTrustMarkStatus(ctx context.Context, trustMarkToken string) (intfed.TrustMarkStatusResponseClaims, error) {
	if trustMarkToken == "" {
		return intfed.TrustMarkStatusResponseClaims{}, fmt.Errorf("federation: trust mark is empty")
	}
	tm, err := intfed.ParseTrustMark(trustMarkToken)
	if err != nil {
		return intfed.TrustMarkStatusResponseClaims{}, fmt.Errorf("federation: parse trust mark: %w", err)
	}

	issuer, err := r.Resolve(ctx, tm.ClaimedIssuer())
	if err != nil {
		return intfed.TrustMarkStatusResponseClaims{}, fmt.Errorf("federation: resolve trust mark issuer %q: %w", tm.ClaimedIssuer(), err)
	}
	issuerMeta, err := parseEntityMetadata(issuer.Metadata)
	if err != nil {
		return intfed.TrustMarkStatusResponseClaims{}, fmt.Errorf("federation: parse trust mark issuer's own federation_entity metadata: %w", err)
	}
	if issuerMeta.TrustMarkStatusEndpoint == "" {
		return intfed.TrustMarkStatusResponseClaims{}, fmt.Errorf("federation: trust mark issuer %q published no federation_trust_mark_status_endpoint", tm.ClaimedIssuer())
	}
	endpoint, err := url.Parse(issuerMeta.TrustMarkStatusEndpoint)
	if err != nil {
		return intfed.TrustMarkStatusResponseClaims{}, fmt.Errorf("federation: parse trust mark issuer's own status endpoint: %w", err)
	}

	body := url.Values{"trust_mark": {trustMarkToken}}.Encode()
	res, err := r.deps.HTTP.Post(ctx, fapihttp.PostRequest{
		URL: endpoint, Body: []byte(body), ContentType: "application/x-www-form-urlencoded",
		ExpectedContentType: "application/trust-mark-status-response+jwt",
	})
	if err != nil {
		return intfed.TrustMarkStatusResponseClaims{}, fmt.Errorf("federation: query trust mark status: %w", err)
	}

	response, err := intfed.ParseTrustMarkStatusResponse(strings.TrimSpace(string(res.Body)))
	if err != nil {
		return intfed.TrustMarkStatusResponseClaims{}, fmt.Errorf("federation: parse trust mark status response: %w", err)
	}
	claims, err := verifyAgainstCandidateKeys(issuer.JWKS, response.KeyID(), response.Algorithm(), func(pub crypto.PublicKey) (intfed.TrustMarkStatusResponseClaims, error) {
		return response.Verify(pub, intfed.TrustMarkStatusResponseVerifyPolicy{
			ExpectedIssuer: tm.ClaimedIssuer(), ExpectedTrustMark: trustMarkToken,
			Algorithm: response.Algorithm(), Now: r.deps.Clock.Now(), MaxClockSkew: r.cfg.Limits.MaxClockSkew,
		})
	})
	if err != nil {
		return intfed.TrustMarkStatusResponseClaims{}, fmt.Errorf("federation: trust mark status response: %w", err)
	}
	return claims, nil
}
