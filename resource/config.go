package resource

import (
	"time"

	fapi "github.com/osanderson/go-fapi"
)

// Limits bounds the lifetimes and clock tolerances this verifier
// enforces. None of these have an implicit default — NewVerifier
// rejects a zero (or, for MaxClockSkew, negative) value.
type Limits struct {
	// MaxTokenLifetime bounds how far in the future an access token's exp
	// claim may be, relative to the time it's verified.
	MaxTokenLifetime time.Duration

	// MaxDPoPProofAge bounds how old (relative to verification time) a
	// DPoP proof's iat claim may be.
	MaxDPoPProofAge time.Duration

	// MaxClockSkew bounds how far in the future an iat claim may be, and
	// extends how long past exp a token is still accepted. Zero means no
	// tolerance.
	MaxClockSkew time.Duration
}

// Config is this verifier's immutable configuration. It is copied by
// NewVerifier; mutating a Config after passing it to NewVerifier has no
// effect.
type Config struct {
	// Issuer is the authorization server this verifier accepts access
	// tokens from. A token's iss claim must equal it exactly.
	Issuer fapi.URL

	// Audience is this resource server's own identifier — the value the
	// authorization server addresses access tokens to. A token's aud
	// claim must equal it exactly.
	Audience string

	// Algorithm is the algorithm the authorization server is registered
	// (or discovered) to sign access tokens with. A token's header
	// algorithm must equal it exactly — this must come from the
	// authorization server's metadata, never from the token itself, to
	// prevent algorithm-confusion attacks.
	Algorithm fapi.SignatureAlgorithm

	Limits Limits
}
