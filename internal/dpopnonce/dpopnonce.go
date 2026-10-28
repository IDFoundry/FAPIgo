// Package dpopnonce hands out the DPoP nonces (RFC 9449 §8, §9) package
// server and package resource issue: one current nonce per verifier,
// valid for its whole lifetime and replaced before half of it has
// passed.
//
// RFC 9449 §8 expects "clients need to keep only one nonce value and
// servers need to keep a window of recent nonces": a client presents
// the nonce it last received on every request until the server supplies
// a new one (§8.2). A nonce is therefore valid for a time window, not
// for one use; the proof's "jti" is what refuses a replay. A verifier
// that retired a nonce on first use, and issued a new one per response,
// would refuse every concurrent request from a client but the first.
package dpopnonce

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/idfoundry/fapigo/storage"
)

// size is the byte length of a generated DPoP nonce — 256 bits,
// matching this module's other generated identifiers.
const size = 32

// Rotator holds the nonce a verifier currently hands out. Its zero value
// is ready to use; it must not be copied after first use.
//
// Each instance of a horizontally scaled verifier has its own Rotator
// but the same store, so every instance accepts every other instance's
// nonces: Lookup, not the Rotator, decides validity.
type Rotator struct {
	mu        sync.Mutex
	current   string
	expiresAt time.Time
}

// Current returns the nonce to hand out at now: the one it last issued
// while more than half of lifetime remains, otherwise a new one drawn
// from random (crypto/rand.Reader when nil) and persisted in store until
// now+lifetime. A client given the previous nonce can keep using it
// until it expires, at least lifetime/2 after the switch, so a client's
// requests in flight across a rotation still succeed.
func (r *Rotator) Current(ctx context.Context, store storage.NonceStore, random io.Reader, lifetime time.Duration, now time.Time) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.current != "" && now.Before(r.expiresAt.Add(-lifetime/2)) {
		return r.current, nil
	}
	nonce, err := generate(random)
	if err != nil {
		return "", fmt.Errorf("generate dpop nonce: %w", err)
	}
	expiresAt := now.Add(lifetime)
	if err := store.Issue(ctx, storage.NonceIssuance{Nonce: nonce, ExpiresAt: expiresAt}); err != nil {
		return "", fmt.Errorf("issue dpop nonce: %w", err)
	}
	r.current, r.expiresAt = nonce, expiresAt
	return nonce, nil
}

// Valid reports whether presented names a nonce store holds that hasn't
// expired at now. err is store's own error for a nonce it couldn't find,
// for a caller that tells an unavailable store apart from an unknown
// nonce; valid is false whenever err is non-nil.
func Valid(ctx context.Context, store storage.NonceStore, presented string, now time.Time) (valid bool, err error) {
	if presented == "" {
		return false, nil
	}
	record, err := store.Lookup(ctx, storage.NonceLookup{Nonce: presented})
	if err != nil {
		return false, err
	}
	return !now.After(record.ExpiresAt), nil
}

func generate(random io.Reader) (string, error) {
	if random == nil {
		random = rand.Reader
	}
	buf := make([]byte, size)
	if _, err := io.ReadFull(random, buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
