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

// IssueDPoPNonce issues a fresh DPoP nonce this Verifier will accept, for
// a resource server to hand out ahead of a request rather than in answer
// to one: an OpenID4VCI 1.0 §7.2 Nonce Response's DPoP-Nonce header,
// say, which the Wallet then uses at the Credential Endpoint this
// Verifier guards. It returns "" and no error when Dependencies.Nonces is
// nil: the Verifier doesn't use DPoP nonces, so there is none to give.
//
// Each call stores a nonce until Config.Limits.DPoPNonceLifetime has
// passed. Called from an endpoint anyone may call (§7.1's Nonce Endpoint
// is), it lets anyone add records, as that endpoint's own c_nonce does:
// rate-limit it the same way.
func (v *Verifier) IssueDPoPNonce(ctx context.Context) (string, error) {
	if v.deps.Nonces == nil {
		return "", nil
	}
	return v.issueDPoPNonce(ctx, v.deps.Clock.Now())
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
		if err != nil && storeUnavailable(err) {
			return newError(ErrorServerError, 500, "failed to check dpop nonce", err)
		}
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
