package federation

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	fapi "github.com/idfoundry/fapigo"
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
func (r *Resolver) VerifyTrustMark(ctx context.Context, subjectID string, raw intfed.RawTrustMark) (intfed.TrustMarkClaims, error) {
	if subjectID == "" {
		return intfed.TrustMarkClaims{}, fmt.Errorf("federation: subject entity ID is empty")
	}
	tm, err := intfed.ParseTrustMark(raw.TrustMark)
	if err != nil {
		return intfed.TrustMarkClaims{}, fmt.Errorf("federation: parse trust mark: %w", err)
	}

	issuer, err := r.Resolve(ctx, tm.ClaimedIssuer())
	if err != nil {
		return intfed.TrustMarkClaims{}, fmt.Errorf("federation: resolve trust mark issuer %q: %w", tm.ClaimedIssuer(), err)
	}

	claims, err := r.verifyTrustMarkAgainstJWKS(tm, issuer.JWKS, subjectID, raw.TrustMarkType, tm.Algorithm(), r.deps.Clock.Now())
	if err != nil {
		return intfed.TrustMarkClaims{}, fmt.Errorf("federation: trust mark: %w", err)
	}

	if err := r.checkTrustMarkDelegation(ctx, issuer.TrustAnchor, tm, claims); err != nil {
		return intfed.TrustMarkClaims{}, fmt.Errorf("federation: trust mark: %w", err)
	}

	return claims, nil
}

// checkTrustMarkDelegation enforces OpenID Federation 1.0 §7.2: when
// trustAnchorID's own "trust_mark_owners" claim names claims.TrustMarkType
// at all, tm MUST carry a "delegation" claim proving its own issuer
// (claims.Issuer) was actually authorized by that type's real owner —
// checked against the owner's keys as published directly in
// trust_mark_owners, never resolved via a separate Trust Chain the way
// the issuer's own keys are (OpenID Federation 1.0 §7.2's own "The
// Trust Mark Owner's keys can be found in the trust_mark_owners Claim
// in the Trust Anchor's Entity Configuration"). A type absent from
// trust_mark_owners requires no delegation at all — this is not a
// generic "delegation, if present, is always checked" pass.
func (r *Resolver) checkTrustMarkDelegation(ctx context.Context, trustAnchorID string, tm intfed.TrustMark, claims intfed.TrustMarkClaims) error {
	trustAnchor, err := r.Resolve(ctx, trustAnchorID)
	if err != nil {
		return fmt.Errorf("resolve trust anchor %q for trust_mark_owners: %w", trustAnchorID, err)
	}
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

// verifyTrustMarkAgainstJWKS mirrors Resolver.verifyAgainstJWKS exactly
// (resolve candidate keys matching algorithm/kid, try Verify against
// each), but for a TrustMark rather than an intfed.Statement — kept as
// a separate, small function rather than generalizing
// verifyAgainstJWKS itself, since the two verified types have distinct
// Verify signatures and this is the only other caller.
func (r *Resolver) verifyTrustMarkAgainstJWKS(tm intfed.TrustMark, jwksRaw json.RawMessage, expectedSubject, expectedTrustMarkType string, algorithm fapi.SignatureAlgorithm, now time.Time) (intfed.TrustMarkClaims, error) {
	candidates, err := jose.ParseJWKSet(jwksRaw)
	if err != nil {
		return intfed.TrustMarkClaims{}, fmt.Errorf("parse jwks: %w", err)
	}
	policy := intfed.TrustMarkVerifyPolicy{
		ExpectedSubject: expectedSubject, ExpectedTrustMarkType: expectedTrustMarkType,
		Algorithm: algorithm, Now: now, MaxClockSkew: r.cfg.Limits.MaxClockSkew,
	}
	kid := tm.KeyID()
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
		claims, err := tm.Verify(c.PublicKey, policy)
		if err == nil {
			return claims, nil
		}
		lastErr = err
	}
	if !tried {
		return intfed.TrustMarkClaims{}, fmt.Errorf("no candidate key found for algorithm %v kid %q among %d keys", algorithm, kid, len(candidates))
	}
	return intfed.TrustMarkClaims{}, fmt.Errorf("signature verification failed against every candidate key: %w", lastErr)
}

// verifyTrustMarkDelegationAgainstJWKS mirrors verifyTrustMarkAgainstJWKS
// exactly, for an intfed.TrustMarkDelegation rather than a TrustMark.
func (r *Resolver) verifyTrustMarkDelegationAgainstJWKS(d intfed.TrustMarkDelegation, jwksRaw json.RawMessage, expectedIssuer, expectedSubject, expectedTrustMarkType string, algorithm fapi.SignatureAlgorithm, now time.Time) (intfed.TrustMarkDelegationClaims, error) {
	candidates, err := jose.ParseJWKSet(jwksRaw)
	if err != nil {
		return intfed.TrustMarkDelegationClaims{}, fmt.Errorf("parse jwks: %w", err)
	}
	policy := intfed.TrustMarkDelegationVerifyPolicy{
		ExpectedIssuer: expectedIssuer, ExpectedSubject: expectedSubject, ExpectedTrustMarkType: expectedTrustMarkType,
		Algorithm: algorithm, Now: now, MaxClockSkew: r.cfg.Limits.MaxClockSkew,
	}
	kid := d.KeyID()
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
		claims, err := d.Verify(c.PublicKey, policy)
		if err == nil {
			return claims, nil
		}
		lastErr = err
	}
	if !tried {
		return intfed.TrustMarkDelegationClaims{}, fmt.Errorf("no candidate key found for algorithm %v kid %q among %d keys", algorithm, kid, len(candidates))
	}
	return intfed.TrustMarkDelegationClaims{}, fmt.Errorf("signature verification failed against every candidate key: %w", lastErr)
}
