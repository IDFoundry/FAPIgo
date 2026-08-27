package resource

import (
	"time"
)

// Limits bounds the clock tolerances this verifier enforces for DPoP
// proof verification — format-independent, unlike the JWT-specific
// concerns (issuer, audience, algorithm, max token lifetime) that
// moved into JWTAccessTokens itself; see its own doc comment. None of
// these have an implicit default — NewVerifier rejects a zero (or, for
// MaxClockSkew, negative) value.
type Limits struct {
	// MaxDPoPProofAge bounds how old (relative to verification time) a
	// DPoP proof's iat claim may be.
	MaxDPoPProofAge time.Duration

	// MaxClockSkew bounds how far in the future an iat claim may be, and
	// extends how long past a token's own expiry it's still accepted.
	// Zero means no tolerance.
	MaxClockSkew time.Duration

	// DPoPNonceLifetime bounds how long an issued DPoP nonce remains
	// valid. Required only when Dependencies.Nonces is non-nil — see
	// its own doc comment; NewVerifier rejects a zero value in that
	// case, exactly like MaxDPoPProofAge above, but leaves it
	// unvalidated when nonce-challenge support is disabled.
	DPoPNonceLifetime time.Duration
}

// Config is this verifier's immutable configuration. It is copied by
// NewVerifier; mutating a Config after passing it to NewVerifier has no
// effect.
type Config struct {
	Limits Limits
}
