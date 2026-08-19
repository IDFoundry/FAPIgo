package server

import (
	"time"

	fapi "github.com/idfoundry/fapigo"
)

// RecommendedLimits returns a Limits value grounded in the FAPI 2.0
// Security Profile Final (https://openid.net/specs/fapi-security-profile-2_0-final.html)
// and RFC 9449 (DPoP), for a caller who wants a defensible starting
// point rather than researching nine duration values from scratch.
// Config still has no implicit defaults — New never reaches for this on
// its own; calling it is as deliberate a choice as SystemClock is.
//
// Every field below is documented with exactly how grounded it is.
// Three are direct spec requirements; the rest are this module's own
// conservative operational choices, honestly labeled as such rather
// than dressed up as mandates that don't exist — overclaiming spec
// grounding in a security library is worse than not claiming it at
// all. Every value here is a sane starting point, not a security
// boundary you're forbidden from adjusting: override any field your
// own risk assessment or deployment's real-world constraints call for.
func RecommendedLimits() Limits {
	return Limits{
		// Spec: FAPI 2.0 Security Profile Final §5.3.2.2 item 12 —
		// "shall issue pushed authorization requests request_uri with
		// expires_in values of less than 600 seconds." 90s is
		// comfortably under that ceiling: enough for a real network
		// round trip (PAR response -> browser redirect to
		// /authorize), short enough to keep the replay window small.
		PushedRequestLifetime: 90 * time.Second,

		// Not directly spec-numbered — §5.3.2.1 item 13 governs iat/nbf
		// clock-skew tolerance for these same artifact types (mapped to
		// MaxClockSkew below), not how far exp may sit in the future.
		// 60s applies the same short-lived-artifact principle the spec
		// uses elsewhere (see AuthorizationCodeLifetime), for
		// consistency, not because the spec numbers this field
		// specifically.
		MaxClientAssertionLifetime: 60 * time.Second,

		// Same reasoning as MaxClientAssertionLifetime — not directly
		// spec-numbered, same short-lived-artifact principle applied
		// for consistency.
		MaxRequestObjectLifetime: 60 * time.Second,

		// Not spec-mandated at all — how long a user has to complete
		// login/consent is a UX budget, not a protocol requirement.
		// 5 minutes is a reasonable operational default; tune to your
		// own login flow's actual expected duration.
		InteractionLifetime: 5 * time.Minute,

		// Spec: FAPI 2.0 Security Profile Final §5.3.2.1 item 11 —
		// "shall issue authorization codes with a maximum lifetime of
		// 60 seconds." This is the spec's own ceiling, used directly:
		// a code is exchanged immediately after redirect in a normal
		// flow, so there's no reason to allow longer.
		AuthorizationCodeLifetime: 60 * time.Second,

		// Not spec-mandated — aligned with the PAR/authorization-code
		// family (a JARM response is consumed immediately, the same
		// way a code is) for the same short-lived-artifact reasoning,
		// not a cited number.
		JARMResponseLifetime: 90 * time.Second,

		// Not spec-mandated. §6.1 recommends short-lived access tokens
		// "combined with refresh tokens" as good practice, without
		// giving a figure ("suggests minutes/hours as example
		// durations" — no requirement). 10 minutes is a conservative
		// operational choice, not a spec-cited value.
		AccessTokenLifetime: 10 * time.Minute,

		// Not spec-mandated — an ID token is normally consumed
		// immediately at the token endpoint response, same reasoning
		// as AccessTokenLifetime.
		IDTokenLifetime: 10 * time.Minute,

		// Not spec-mandated — this is a session-length choice, not a
		// protocol requirement. 24 hours is a reasonable "valid for
		// the day" default; adjust to your own session policy.
		RefreshTokenLifetime: 24 * time.Hour,

		// RFC 9449 §11.1 (DPoP) gives qualitative guidance only:
		// servers "MUST only accept DPoP proofs for a limited time
		// after their creation (preferably only for a relatively
		// brief period on the order of seconds or minutes)" — no
		// specific number. 60s is a concrete point within that
		// guidance, not a value RFC 9449 itself specifies.
		MaxDPoPProofAge: 60 * time.Second,

		// Spec: FAPI 2.0 Security Profile Final §5.3.2.1 item 13 —
		// "to accommodate clock offsets, shall accept JWTs with an
		// iat or nbf timestamp between 0 and 10 seconds in the
		// future" (client assertions and request objects). This is
		// the spec's own recommended tighter value, used directly —
		// the same requirement's Note 3 explicitly permits up to 60
		// seconds "to greatly increase interoperability" if 10s
		// proves too tight against a real deployment's clock drift;
		// widen it if you hit that in practice, but start tight.
		MaxClockSkew: 10 * time.Second,
	}
}

// RecommendedAlgorithms returns an AlgorithmPolicy using only ES256 —
// the narrower of the two algorithms this module implements (see
// RecommendedAlgorithmSet's own doc comment for why only two, not the
// three FAPI 2.0 permits) — for every signing purpose, and accepting
// both ES256 and PS256 from clients. As with RecommendedLimits, this is
// a starting point to call and override, not something New applies on
// its own.
//
// JARM is set even under Config.Profile == ProfileFAPISecurity, where
// it goes unused (New only validates it under
// ProfileFAPISecurityWithMessageSigning) — harmless to set regardless,
// and one less thing to remember if you switch profiles later.
//
// Has no AccessToken field — that algorithm is now
// Dependencies.AccessTokens' own concern (see JWTAccessTokens), not
// Config's. If using JWTAccessTokens, the same ES256 recommendation
// applies there too; pass fapi.ES256 or reuse this policy's own
// IDToken value.
func RecommendedAlgorithms() AlgorithmPolicy {
	return AlgorithmPolicy{
		ClientAssertion: RecommendedAlgorithmSet(),
		RequestObject:   RecommendedAlgorithmSet(),
		JARM:            fapi.ES256,
		IDToken:         fapi.ES256,
	}
}

// RecommendedAlgorithmSet returns {ES256, PS256} — both algorithms this
// module implements, and both explicitly permitted by FAPI 2.0 Security
// Profile Final §5.4.1 item 1.b ("use PS256, ES256, or EdDSA (using the
// Ed25519 variant) algorithms"). The spec also permits EdDSA/Ed25519;
// this module doesn't implement it (fapi.SignatureAlgorithm's closed
// set is ES256 and PS256 only, see algorithm.go), so accepting exactly
// these two is a fully spec-compliant subset, not a narrowing this
// module imposes beyond what it can actually verify.
func RecommendedAlgorithmSet() AlgorithmSet {
	return AlgorithmSet{fapi.ES256, fapi.PS256}
}
