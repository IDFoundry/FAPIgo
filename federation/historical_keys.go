package federation

import (
	"context"
	"crypto"
	"fmt"
	"net/url"

	"github.com/idfoundry/fapigo/fapihttp"
	intfed "github.com/idfoundry/fapigo/internal/federation"
)

// HistoricalKeysContentType is the content type every successful
// Federation Historical Keys response MUST declare (OpenID Federation
// 1.0 §8.7.2).
const HistoricalKeysContentType = "application/jwk-set+jwt"

// FetchHistoricalKeys queries entityID's Federation Historical Keys
// endpoint (OpenID Federation 1.0 §8.7) and returns its previously used
// Federation Entity Keys — published so a Trust Chain signed under a
// since-rotated key remains verifiable after the rotation (§8.7's own
// "guarantees that Trust Chains will remain verifiable and usable as
// inputs to trust decisions after the key expiration, unless the key
// becomes revoked"), each carrying its own expiry and, if applicable,
// revocation status (§8.7.3) rather than a bare key.
//
// Trust in the response rests on the exact same "resolve the issuer as
// its own peer, cryptographically, before trusting its signature"
// pattern VerifyTrustMark, CheckTrustMarkStatus and ResolveViaEndpoint
// already use: entityID is resolved as a fresh Trust Chain against this
// Resolver's own Config.TrustAnchors before the response's signature is
// ever checked, using that resolution's own ResolvedEntity.JWKS —
// entityID's currently active federation key, never a key the response
// itself merely claims to hold, and never one of the historical keys
// the response is itself reporting on.
//
// This does not decide whether any particular key found here actually
// resolves a specific verification failure a caller hit — it only
// fetches and authenticates the published list; matching a statement's
// own "kid" against it, and checking that key's own ExpiresAt/Revoked
// against the statement's own iat, is the caller's own responsibility.
// Resolve itself does not consult this endpoint as an automatic
// fallback when a "kid" isn't found in an issuer's current jwks.
//
// endpoint is entityID's own published federation_historical_keys_endpoint
// (its federation_entity metadata, §5.1.1) — typically read from a
// prior Resolve call's own ResolvedEntity.Metadata, or out of band.
// Only the no-client-authentication GET-request shape (§8.7.1) is
// covered — the POST-with-client-authentication variant is not
// implemented in this first version.
func (r *Resolver) FetchHistoricalKeys(ctx context.Context, endpoint, entityID string) (intfed.HistoricalKeysClaims, error) {
	if endpoint == "" {
		return intfed.HistoricalKeysClaims{}, fmt.Errorf("federation: historical keys endpoint is empty")
	}
	if entityID == "" {
		return intfed.HistoricalKeysClaims{}, fmt.Errorf("federation: entity ID is empty")
	}

	target, err := url.Parse(endpoint)
	if err != nil {
		return intfed.HistoricalKeysClaims{}, fmt.Errorf("federation: invalid historical keys endpoint %q: %w", endpoint, err)
	}
	if target.Scheme != "https" {
		return intfed.HistoricalKeysClaims{}, fmt.Errorf("federation: historical keys endpoint %q must use https", endpoint)
	}

	res, err := r.deps.HTTP.Fetch(ctx, fapihttp.FetchRequest{URL: target, ExpectedContentType: HistoricalKeysContentType})
	if err != nil {
		return intfed.HistoricalKeysClaims{}, fmt.Errorf("federation: fetch historical keys for %q: %w", entityID, err)
	}
	resp, err := intfed.ParseHistoricalKeysResponse(string(res.Body))
	if err != nil {
		return intfed.HistoricalKeysClaims{}, fmt.Errorf("federation: parse historical keys response: %w", err)
	}

	issuer, err := r.Resolve(ctx, entityID)
	if err != nil {
		return intfed.HistoricalKeysClaims{}, fmt.Errorf("federation: resolve historical keys issuer %q: %w", entityID, err)
	}

	now := r.deps.Clock.Now()
	claims, err := verifyAgainstCandidateKeys(issuer.JWKS, resp.KeyID(), resp.Algorithm(), func(pub crypto.PublicKey) (intfed.HistoricalKeysClaims, error) {
		return resp.Verify(pub, intfed.HistoricalKeysVerifyPolicy{
			ExpectedIssuer: entityID, Algorithm: resp.Algorithm(), Now: now, MaxClockSkew: r.cfg.Limits.MaxClockSkew,
		})
	})
	if err != nil {
		return intfed.HistoricalKeysClaims{}, fmt.Errorf("federation: historical keys response: %w", err)
	}
	return claims, nil
}
