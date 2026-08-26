package client

import (
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/jose"
)

// RecommendedLimits returns a Limits value grounded the same way
// server.RecommendedLimits is: a defensible starting point to call and
// override, not something New reaches for on its own — calling this is
// as deliberate a choice as SystemClock is. Every field below is
// documented with exactly how grounded it is; most are this module's
// own conservative operational choices honestly labeled as such, not
// dressed up as mandates the spec doesn't actually make.
//
// MaxIDTokenLifetime is left at zero deliberately: unlike every other
// field here, it depends on the specific authorization server this
// client talks to (how long that server actually makes its ID tokens
// valid for), not on anything this module can recommend in the
// abstract. New still rejects a zero MaxIDTokenLifetime, so a caller
// must set this one field themselves before this value is usable.
func RecommendedLimits() Limits {
	return Limits{
		// Not spec-mandated — mirrors server.RecommendedLimits'
		// MaxClientAssertionLifetime (what a FAPIgo server accepts),
		// so a FAPIgo client signing against a FAPIgo server needs no
		// adjustment; short enough that a leaked assertion has little
		// value.
		ClientAssertionLifetime: 60 * time.Second,

		// Not spec-mandated — mirrors server.RecommendedLimits'
		// MaxRequestObjectLifetime for the same reason.
		RequestObjectLifetime: 60 * time.Second,

		// Not spec-mandated — a UX budget for how long a user has to
		// complete login/consent, not a protocol requirement. Mirrors
		// server.RecommendedLimits' InteractionLifetime.
		SessionLifetime: 5 * time.Minute,

		// Not spec-mandated. A JARM response is meant to be consumed
		// immediately at the redirect callback, so this only needs to
		// comfortably exceed what a real authorization server actually
		// issues — server.RecommendedLimits' own JARMResponseLifetime
		// is 90s, but at least one real conformance-tested
		// authorization server issues a 10-minute exp in practice; 15
		// minutes covers that with margin without being unboundedly
		// loose.
		MaxJARMResponseLifetime: 15 * time.Minute,

		// Spec: FAPI 2.0 Security Profile Final §5.3.2.1 item 13 — the
		// same clock-skew tolerance server.RecommendedLimits.MaxClockSkew
		// applies, here to what this client accepts from a server-issued
		// artifact's iat/nbf.
		MaxClockSkew: 10 * time.Second,

		// Not spec-mandated — an ordinary HTTP client timeout for a
		// single PAR or token-endpoint call.
		HTTPTimeout: 10 * time.Second,

		// Not spec-mandated — PAR and token-endpoint responses are
		// small JSON documents; 1 MiB is generous headroom without
		// being an effectively unbounded read.
		MaxHTTPResponseBytes: 1 << 20,

		// Not spec-mandated — the same 16 KiB this module's own JOSE
		// package uses as its default ceiling for a fixed-shape
		// artifact (jose.DefaultMaxCompactBytes), carried over here as
		// a starting point for an ID token or UserInfo response too. A
		// deployment whose issuer is configured to return many claims
		// (verified/assured identity claims, in particular, can run
		// well past this) should raise it explicitly rather than rely
		// on this default.
		MaxJOSECompactBytes: jose.DefaultMaxCompactBytes,
	}
}

// RecommendedAlgorithms returns an Algorithms value using ES256 for
// this client's own signing (ClientAuthentication, DPoP) — the same
// mature, widely-interoperable choice server.RecommendedAlgorithms
// makes for its own signing. Every other field is left zero
// deliberately: IDToken, RequestObject, JARM and UserInfo are
// algorithms this client only ever verifies, never produces, so which
// one to expect is a property of the specific authorization server
// it's configured against — discovered via Discover, not something
// this module can recommend independent of who it's talking to. The
// *KeyManagement/*ContentEncryption fields are left zero for the same
// reason encrypted ID token/UserInfo support is opt-in everywhere else
// in this module: most deployments never register for it.
func RecommendedAlgorithms() Algorithms {
	return Algorithms{
		ClientAuthentication: fapi.ES256,
		DPoP:                 fapi.ES256,
	}
}
