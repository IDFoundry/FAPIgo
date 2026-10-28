package resource

import (
	"context"
	"time"
)

// RevocationChecker lets this verifier reject an access token its
// issuing AS has since revoked — otherwise a cryptographically valid,
// unexpired, sender-constrained token would still be accepted after
// the AS detected it was issued from a reused authorization code (RFC
// 6749 §4.1.2), or after the application revoked its grant
// (server.Server.RevokeGrant). RFC 6750 §3.1 governs the invalid_token
// response a revoked token maps to. It is typically the same store the
// server records revocations in (its server.RevocationSink).
// Dependencies.Revocation has no default: pass a real implementation,
// or NoRevocation{} to explicitly decline — see NoRevocation's own doc
// comment for why declining must be a visible choice, not a silent one.
type RevocationChecker interface {
	// IsRevoked reports whether key has been revoked. Verify asks about
	// two kinds of key, which must both be answered from what the
	// server recorded: the token's own key (ResolvedAccessToken.Key —
	// a JWT's jti claim for JWTAccessTokens, an opaque token's own hash
	// for OpaqueAccessTokens), and, for a token carrying a grant_id
	// claim, the key server.Server.RevokeGrant records that grant under,
	// and for one carrying a code_grant_id claim, the key the server
	// records when the authorization code the token's grant came from
	// is reused. Run storage.TestRevocationStoreContract against an
	// implementation.
	IsRevoked(ctx context.Context, key string) (bool, error)
}

// NoRevocation is an explicit no-op RevocationChecker for a verifier
// that has decided not to check access-token revocation — see
// server.NoRevocation's doc comment for the same "declining must be
// visible, not silently defaulted" rationale.
//
// With it, a token the authorization server revoked (a reused
// authorization code, server.Server.RevokeGrant, a revoked refresh
// token's grant) stays usable here until it expires. That falls short of
// what a FAPI deployment expects of a resource server (FAPI 2.0 Security
// Profile §5.3.4), so AssuranceProduction refuses it: there, decline with
// NoRevocationUntilExpiry instead, which bounds how long that is.
type NoRevocation struct{}

// IsRevoked implements RevocationChecker by never reporting a token as
// revoked.
func (NoRevocation) IsRevoked(context.Context, string) (bool, error) { return false, nil }

// maxUnrevocableTokenLifetime is the longest MaxTokenLifetime
// NoRevocationUntilExpiry may declare under AssuranceProduction: a
// revoked token stays usable here at most this long.
const maxUnrevocableTokenLifetime = 15 * time.Minute

// NoRevocationUntilExpiry declines revocation checking, as NoRevocation
// does, and states how long that leaves a revoked token usable: Verify
// refuses an access token expiring more than MaxTokenLifetime (plus
// Limits.MaxClockSkew) from now, whichever AccessTokenResolver resolved
// it, so no token outlives the declared window. It is the decline
// AssuranceProduction accepts, with MaxTokenLifetime at most 15 minutes:
// short enough that a token the authorization server revoked (a reused
// authorization code, server.Server.RevokeGrant) expires soon after.
// Set MaxTokenLifetime to at least the authorization server's access
// token lifetime, or its tokens are refused here.
//
// Prefer a real RevocationChecker over the authorization server's
// revocation store (serverresource.NewVerifier wires one); this is for a
// resource server that can't reach it.
type NoRevocationUntilExpiry struct {
	// MaxTokenLifetime bounds how far ahead of now an accepted token's
	// expiry may be. Required (positive); at most 15 minutes under
	// AssuranceProduction.
	MaxTokenLifetime time.Duration
}

// IsRevoked implements RevocationChecker by never reporting a token as
// revoked.
func (NoRevocationUntilExpiry) IsRevoked(context.Context, string) (bool, error) {
	return false, nil
}

// unrevocableLifetime returns the MaxTokenLifetime revocation declares,
// when it's a NoRevocationUntilExpiry by value or pointer.
func unrevocableLifetime(revocation RevocationChecker) (time.Duration, bool) {
	switch r := revocation.(type) {
	case NoRevocationUntilExpiry:
		return r.MaxTokenLifetime, true
	case *NoRevocationUntilExpiry:
		if r != nil {
			return r.MaxTokenLifetime, true
		}
	}
	return 0, false
}
