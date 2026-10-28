package server

import (
	"context"
	"fmt"
	"time"

	"github.com/idfoundry/fapigo/internal/dpopnonce"
)

// issueDPoPNonce returns the nonce this server currently hands out (see
// internal/dpopnonce.Rotator): the same one for every client and
// response until half of s.cfg.Limits.DPoPNonceLifetime has passed, then
// a fresh one, persisted in s.deps.Nonces. Only ever called once
// s.deps.Nonces is known to be non-nil.
func (s *Server) issueDPoPNonce(ctx context.Context, now time.Time) (string, error) {
	nonce, err := s.nonces.Current(ctx, s.deps.Nonces, s.deps.Random, s.cfg.Limits.DPoPNonceLifetime, now)
	if err != nil {
		return "", fmt.Errorf("server: %w", err)
	}
	return nonce, nil
}

// checkDPoPNonce enforces the nonce challenge (RFC 9449 §8) when
// s.deps.Nonces is configured: presented is the DPoP proof's own
// "nonce" claim (empty if absent) — shared by both the token endpoint
// and PAR, since one nonce store covers everything this server
// verifies (see Dependencies.Nonces's own doc comment). A nonce this
// server issued is valid until it expires, for any number of proofs
// (§8.2: the client uses it "until the server supplies a new nonce");
// each proof's "jti" is what refuses a replay. A missing, unknown or
// expired nonce is rejected with the current nonce attached (via
// *Error's own Nonce method) for the caller to retry with; a valid one
// returns nil, letting the caller proceed.
//
// Called only when s.deps.Nonces != nil — every call site guards that,
// since this is the one dependency this package treats as genuinely
// optional rather than required-with-visible-opt-out (see
// Dependencies.Nonces's own doc comment).
func (s *Server) checkDPoPNonce(ctx context.Context, presented string, now time.Time) *Error {
	if valid, _ := dpopnonce.Valid(ctx, s.deps.Nonces, presented, now); valid {
		return nil
	}

	current, err := s.issueDPoPNonce(ctx, now)
	if err != nil {
		return newError(ErrorServerError, 500, "failed to issue dpop nonce", err)
	}
	// RFC 9449 §8 token-endpoint nonce errors are ordinary RFC 6749
	// §5.2 OAuth errors — 400, not the 401 WWW-Authenticate challenge
	// resource.ErrorUseDPoPNonce uses for a protected-resource request.
	challenge := newError(ErrorUseDPoPNonce, 400, "DPoP proof must carry a current nonce", nil)
	challenge.nonce = current
	return challenge
}
