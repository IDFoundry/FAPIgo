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
// This first version does not validate a "delegation" claim (OpenID
// Federation 1.0 §7.2) or cross-check a Trust Anchor's own
// "trust_mark_owners" claim — see internal/federation's own doc.go for
// exactly what is and is not covered.
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
	return claims, nil
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
