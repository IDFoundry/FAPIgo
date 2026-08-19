package resource

import (
	"github.com/idfoundry/fapigo/storage"
)

// Dependencies are this verifier's injected collaborators. NewVerifier
// rejects a nil value for any field — there is no implicit fallback (no
// default clock, no silently-installed in-memory replay store).
type Dependencies struct {
	// AccessTokens verifies a presented access token. Required — pass
	// JWTAccessTokens{...} (the default), OpaqueAccessTokens{...}, or
	// your own AccessTokenVerifier.
	AccessTokens AccessTokenVerifier

	// Replay detects reuse of a DPoP proof's jti.
	Replay storage.ReplayStore

	// Revocation reports whether an access token has been revoked by
	// the issuing authorization server (RFC 6749 §4.1.2). Required,
	// like every field above — pass a real RevocationChecker, or
	// NoRevocation{} to explicitly decline (see NoRevocation's own doc
	// comment for why).
	Revocation RevocationChecker

	// Clock supplies the current time.
	Clock Clock
}
