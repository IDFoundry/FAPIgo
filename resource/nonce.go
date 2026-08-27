package resource

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"time"

	"github.com/idfoundry/fapigo/storage"
)

// dpopNonceSize is the byte length of a generated DPoP nonce — 256
// bits, matching this module's other generated identifiers (see
// server's own interactionHandleSize/par.referenceSize).
const dpopNonceSize = 32

func generateDPoPNonce(random io.Reader) (string, error) {
	if random == nil {
		random = rand.Reader
	}
	buf := make([]byte, dpopNonceSize)
	if _, err := io.ReadFull(random, buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// issueDPoPNonce generates and persists a fresh nonce, valid from now
// for v.cfg.Limits.DPoPNonceLifetime. Only ever called once v.deps.Nonces
// is known to be non-nil.
func (v *Verifier) issueDPoPNonce(ctx context.Context, now time.Time) (string, error) {
	nonce, err := generateDPoPNonce(v.deps.Random)
	if err != nil {
		return "", fmt.Errorf("resource: generate dpop nonce: %w", err)
	}
	if err := v.deps.Nonces.Issue(ctx, storage.NonceIssuance{
		Nonce: nonce, ExpiresAt: now.Add(v.cfg.Limits.DPoPNonceLifetime),
	}); err != nil {
		return "", fmt.Errorf("resource: issue dpop nonce: %w", err)
	}
	return nonce, nil
}

// checkDPoPNonce enforces the nonce challenge (RFC 9449 §8, §9) when
// v.deps.Nonces is configured: presented is the DPoP proof's own
// "nonce" claim (empty if absent). A missing, unknown, already-consumed
// or expired nonce is rejected with a freshly issued replacement
// attached (via *Error's own Nonce method) for the caller to retry
// with; a validly consumed nonce returns nil, letting Verify proceed.
//
// Called only when v.deps.Nonces != nil — Verify itself guards that,
// since this is the one dependency this package treats as genuinely
// optional rather than required-with-visible-opt-out (see
// Dependencies.Nonces's own doc comment).
func (v *Verifier) checkDPoPNonce(ctx context.Context, presented string, now time.Time) *Error {
	valid := false
	if presented != "" {
		record, err := v.deps.Nonces.Consume(ctx, storage.NonceConsumption{Nonce: presented})
		valid = err == nil && !now.After(record.ExpiresAt)
	}
	if valid {
		return nil
	}

	fresh, err := v.issueDPoPNonce(ctx, now)
	if err != nil {
		return newError(ErrorServerError, 500, "failed to issue dpop nonce", err)
	}
	challenge := newError(ErrorUseDPoPNonce, 401, "DPoP proof must carry a current nonce", nil)
	challenge.nonce = fresh
	return challenge
}
