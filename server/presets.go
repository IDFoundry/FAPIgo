package server

import (
	"time"

	fapi "github.com/idfoundry/fapigo"
)

// RecommendedLimits returns a Limits value grounded in the FAPI 2.0
// Security Profile Final (https://openid.net/specs/fapi-security-profile-2_0-final.html)
// and RFC 9449 (DPoP), for a caller who wants a defensible starting
// point rather than researching each lifetime from scratch. Config
// still has no implicit defaults — New never reaches for this on its
// own; calling it is as deliberate a choice as SystemClock is.
//
// It covers the limits every server needs. The ones only an optional
// feature needs are left zero, and New refuses that zero once the
// feature is enabled, so set them yourself: the three BackchannelAuthentication limits
// (Endpoints.BackchannelAuthentication), and MaxClientAttestationLifetime
// and MaxClientAttestationPoPAge
// (Config.AttestationBasedClientAuthentication).
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
		// The check allows exp up to this plus MaxClockSkew away, so a
		// client whose clock runs ahead by no more than MaxClockSkew
		// can still use the full lifetime.
		// 60s applies the same short-lived-artifact principle the spec
		// uses elsewhere (see AuthorizationCodeLifetime), for
		// consistency, not because the spec numbers this field
		// specifically.
		MaxClientAssertionLifetime: 60 * time.Second,

		// Not directly spec-numbered as a recommendation: FAPI 2.0
		// Message Signing §5.3.1 only caps a request object's exp at
		// 60 minutes after its nbf (Assurance Production enforces that
		// ceiling). 10 minutes leaves headroom for conformant clients
		// that sign request objects with a window of a few minutes —
		// the OIDF conformance suite's own request objects use
		// exp - nbf = 300s, which a 60s limit would refuse — while
		// staying well inside the spec's ceiling. A FAPIgo client signs
		// with client.RecommendedLimits' shorter RequestObjectLifetime,
		// which fits within this.
		MaxRequestObjectLifetime: 10 * time.Minute,

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

		// Not spec-mandated — no spec bounds ID token size, but relying
		// parties do: this module's own client rejects a compact token
		// over 16 KiB by default, and encryption adds about a third. 4
		// KiB of non-standard claims keeps a signed ID token near 6 KiB
		// and an encrypted one under 9 KiB, with room to spare;
		// provider-specific and typical identity claims are well under
		// 1 KiB. Raise it only alongside your relying parties' limits.
		MaxIDTokenClaimsBytes: 4096,

		// Not spec-mandated — no spec bounds access token size, but
		// resource servers do: resource.JWTAccessTokens rejects a
		// compact token over 16 KiB by default. 6 KiB of non-standard
		// claims (authorization_details and extension claims) encodes
		// to 8 KiB, leaving 8 KiB for the header, signature and
		// standard claims, so Limits.MaxAccessTokenBytes is exactly 16
		// KiB. Raise it only alongside your resource servers' limits.
		MaxAccessTokenClaimsBytes: 6144,

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

		// RFC 9449 §8 sets no number either: a server "will need to
		// keep a window of recent nonces" and decides when to supply a
		// new one. A nonce here is valid until it expires and is
		// replaced once half its lifetime has passed, so 5 minutes
		// keeps a client reusing one nonce for minutes at a time (one
		// use_dpop_nonce round trip per client per endpoint at most
		// every couple of minutes) while staying well inside
		// AssuranceProduction's 15-minute ceiling. Unused under
		// NoDPoPNonces{}.
		DPoPNonceLifetime: 5 * time.Minute,

		// Spec: FAPI 2.0 Security Profile Final §5.3.2.1 item 13 —
		// "to accommodate clock offsets, shall accept JWTs with an
		// iat or nbf timestamp between 0 and 10 seconds in the
		// future but shall reject JWTs with an iat or nbf timestamp
		// greater than 60 seconds in the future" (every JWT a client
		// sends: client assertions, request objects, DPoP proofs,
		// attestations). 10s is the spec's own value, which its Note 3
		// says "does not affect security while greatly increasing
		// interoperability"; the same note lets implementers accept
		// up to 60s, and reports some ecosystems need 30s. Widen it
		// if a real deployment's clock drift needs it, but never past
		// 60s.
		MaxClockSkew: 10 * time.Second,
	}
}

// RecommendedAlgorithms returns an AlgorithmPolicy using ES256 — a
// mature, widely-interoperable choice, not a narrower one than this
// module can offer — for every signing purpose this server does
// itself, while accepting any of ES256, PS256 or EdDSA from clients
// (RecommendedAlgorithmSet). As with RecommendedLimits, this is a
// starting point to call and override, not something New applies on
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

// RecommendedAlgorithmSet returns every algorithm this module
// implements — {ES256, PS256, EdDSA} — which is also exactly the set
// FAPI 2.0 Security Profile Final §5.4.1 item 1.b permits ("use PS256,
// ES256, or EdDSA (using the Ed25519 variant) algorithms"). This is a
// client-verification allow-list (ClientAssertion/RequestObject, not
// this server's own signing choice — see RecommendedAlgorithms), so
// including all three only widens what a client may present; it never
// weakens anything this server itself signs with.
func RecommendedAlgorithmSet() AlgorithmSet {
	return AlgorithmSet{fapi.ES256, fapi.PS256, fapi.EdDSA}
}
