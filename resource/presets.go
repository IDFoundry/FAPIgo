package resource

import "time"

// RecommendedLimits returns a Limits value with the same DPoP and
// clock-skew values server.RecommendedLimits uses, grounded the same
// way: a defensible starting point to call and override, not something
// NewVerifier reaches for on its own — Limits still has no implicit
// defaults, and calling this is as deliberate a choice as SystemClock
// is. A resource server built from it accepts the proofs and the clock
// offsets its authorization server does, and the values satisfy
// AssuranceProduction's bounds.
//
// Every field below is documented with exactly how grounded it is.
// Override any of them your own risk assessment or deployment calls
// for, within the bounds NewVerifier enforces.
func RecommendedLimits() Limits {
	return Limits{
		// RFC 9449 §11.1 (DPoP) gives qualitative guidance only:
		// servers "MUST only accept DPoP proofs for a limited time
		// after their creation (preferably only for a relatively
		// brief period on the order of seconds or minutes)" — no
		// specific number. 60s is a concrete point within that
		// guidance, not a value RFC 9449 itself specifies, and is at
		// most AssuranceProduction's 5-minute ceiling.
		MaxDPoPProofAge: 60 * time.Second,

		// Spec: FAPI 2.0 Security Profile Final §5.3.2.1 item 13 —
		// "to accommodate clock offsets, shall accept JWTs with an
		// iat or nbf timestamp between 0 and 10 seconds in the
		// future but shall reject JWTs with an iat or nbf timestamp
		// greater than 60 seconds in the future". 10s is the spec's
		// own value, and the floor AssuranceProduction requires;
		// widen it if a real deployment's clock drift needs it, but
		// never past 60s.
		MaxClockSkew: 10 * time.Second,

		// RFC 9449 §8 sets no number: the server decides when to
		// supply a new nonce, and "servers need to keep a window of
		// recent nonces". A nonce here is valid until it expires and
		// the next is handed out once half its lifetime has passed,
		// so 5 minutes keeps a client reusing one nonce for minutes
		// at a time while staying well inside AssuranceProduction's
		// 15-minute ceiling. Unused when Dependencies.Nonces is nil
		// or NoDPoPNonces{}.
		DPoPNonceLifetime: 5 * time.Minute,
	}
}
