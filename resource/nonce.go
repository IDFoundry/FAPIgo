package resource

import (
	"context"
	"fmt"
	"time"

	"github.com/idfoundry/fapigo/internal/dpopnonce"
)

// IssueDPoPNonce returns a DPoP nonce this Verifier will accept, for a
// resource server to hand out ahead of a request rather than in answer
// to one: an OpenID4VCI 1.0 §7.2 Nonce Response's DPoP-Nonce header,
// say, which the Wallet then uses at the Credential Endpoint this
// Verifier guards. It returns "" and no error when Dependencies.Nonces is
// nil: the Verifier doesn't use DPoP nonces, so there is none to give.
//
// It is the nonce the Verifier currently hands out to every caller, the
// same one Verify's challenges and AuthorizationContext.NextDPoPNonce
// carry: a new one is stored only once half of
// Config.Limits.DPoPNonceLifetime has passed, so calling this from an
// endpoint anyone may call (§7.1's Nonce Endpoint is) adds no record per
// call.
func (v *Verifier) IssueDPoPNonce(ctx context.Context) (string, error) {
	if v.deps.Nonces == nil {
		return "", nil
	}
	return v.issueDPoPNonce(ctx, v.deps.Clock.Now())
}

// issueDPoPNonce returns the nonce this Verifier currently hands out
// (see internal/dpopnonce.Rotator), persisting a fresh one in
// v.deps.Nonces once half of v.cfg.Limits.DPoPNonceLifetime has passed.
// Only ever called once v.deps.Nonces is known to be non-nil.
func (v *Verifier) issueDPoPNonce(ctx context.Context, now time.Time) (string, error) {
	nonce, err := v.nonces.Current(ctx, v.deps.Nonces, v.deps.Random, v.cfg.Limits.DPoPNonceLifetime, now)
	if err != nil {
		return "", fmt.Errorf("resource: %w", err)
	}
	return nonce, nil
}

// checkDPoPNonce enforces the nonce challenge (RFC 9449 §8, §9) when
// v.deps.Nonces is configured: presented is the DPoP proof's own
// "nonce" claim (empty if absent). A nonce this Verifier issued is
// valid until it expires, for any number of proofs; each proof's "jti"
// is what refuses a replay. A missing, unknown or expired nonce is
// rejected with the current nonce attached (via *Error's own Nonce
// method) for the caller to retry with; a valid one returns nil,
// letting Verify proceed.
//
// Called only when v.deps.Nonces != nil — Verify itself guards that,
// since this is the one dependency this package treats as genuinely
// optional rather than required-with-visible-opt-out (see
// Dependencies.Nonces's own doc comment).
func (v *Verifier) checkDPoPNonce(ctx context.Context, presented string, now time.Time) *Error {
	valid, err := dpopnonce.Valid(ctx, v.deps.Nonces, presented, now)
	if err != nil && storeUnavailable(err) {
		return newError(ErrorServerError, 500, "failed to check dpop nonce", err)
	}
	if valid {
		return nil
	}

	current, err := v.issueDPoPNonce(ctx, now)
	if err != nil {
		return newError(ErrorServerError, 500, "failed to issue dpop nonce", err)
	}
	challenge := newError(ErrorUseDPoPNonce, 401, "DPoP proof must carry a current nonce", nil)
	challenge.nonce = current
	return challenge
}
