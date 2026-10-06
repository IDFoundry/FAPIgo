package resource

import "context"

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
	// claim, the key server.Server.RevokeGrant records that grant under.
	IsRevoked(ctx context.Context, key string) (bool, error)
}

// NoRevocation is an explicit no-op RevocationChecker for a verifier
// that has decided not to check access-token revocation — see
// server.NoRevocation's doc comment for the same "declining must be
// visible, not silently defaulted" rationale.
type NoRevocation struct{}

// IsRevoked implements RevocationChecker by never reporting a token as
// revoked.
func (NoRevocation) IsRevoked(context.Context, string) (bool, error) { return false, nil }
