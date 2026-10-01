// Package grantrevocation is how a revoked grant is recorded and found:
// shared by server, which revokes grants and refuses their codes and
// refresh tokens, and resource, which refuses their access tokens.
package grantrevocation

// Claim is the access token claim carrying the grant ID — the name the
// OAuth Grant Management draft (FAPI working group) uses for the same
// concept.
const Claim = "grant_id"

// Key is the revocation-store key recording grantID as revoked. The
// prefix keeps it apart from the access token keys (a JWT's jti, an
// opaque token's hash) the same store holds.
func Key(grantID string) string { return "grant:" + grantID }
