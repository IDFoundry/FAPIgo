package server

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
// generateInteractionHandle/par.GenerateRequestURI).
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
// for s.cfg.Limits.DPoPNonceLifetime. Only ever called once
// s.deps.Nonces is known to be non-nil.
func (s *Server) issueDPoPNonce(ctx context.Context, now time.Time) (string, error) {
	nonce, err := generateDPoPNonce(s.deps.Random)
	if err != nil {
		return "", fmt.Errorf("server: generate dpop nonce: %w", err)
	}
	if err := s.deps.Nonces.Issue(ctx, storage.NonceIssuance{
		Nonce: nonce, ExpiresAt: now.Add(s.cfg.Limits.DPoPNonceLifetime),
	}); err != nil {
		return "", fmt.Errorf("server: issue dpop nonce: %w", err)
	}
	return nonce, nil
}

// checkDPoPNonce enforces the nonce challenge (RFC 9449 §8) when
// s.deps.Nonces is configured: presented is the DPoP proof's own
// "nonce" claim (empty if absent) — shared by both the token endpoint
// and PAR, since one nonce store covers everything this server
// verifies (see Dependencies.Nonces's own doc comment). A missing,
// unknown, already-consumed or expired nonce is rejected with a
// freshly issued replacement attached (via *Error's own Nonce method)
// for the caller to retry with; a validly consumed nonce returns nil,
// letting the caller proceed.
//
// Called only when s.deps.Nonces != nil — every call site guards that,
// since this is the one dependency this package treats as genuinely
// optional rather than required-with-visible-opt-out (see
// Dependencies.Nonces's own doc comment).
func (s *Server) checkDPoPNonce(ctx context.Context, presented string, now time.Time) *Error {
	valid := false
	if presented != "" {
		record, err := s.deps.Nonces.Consume(ctx, storage.NonceConsumption{Nonce: presented})
		valid = err == nil && !now.After(record.ExpiresAt)
	}
	if valid {
		return nil
	}

	fresh, err := s.issueDPoPNonce(ctx, now)
	if err != nil {
		return newError(ErrorServerError, 500, "failed to issue dpop nonce", err)
	}
	// RFC 9449 §8 token-endpoint nonce errors are ordinary RFC 6749
	// §5.2 OAuth errors — 400, not the 401 WWW-Authenticate challenge
	// resource.ErrorUseDPoPNonce uses for a protected-resource request.
	challenge := newError(ErrorUseDPoPNonce, 400, "DPoP proof must carry a current nonce", nil)
	challenge.nonce = fresh
	return challenge
}
