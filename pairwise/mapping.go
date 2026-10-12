package pairwise

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"

	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/storage"
)

// ErrSubjectNotFound is the error a Lookup wraps when no internal
// subject has the body under the issuer and sector: a body that was
// never issued, or one issued under another issuer or sector. An error
// wrapping storage.ErrStoreUnavailable instead means the store couldn't
// answer, and is never "not found".
var ErrSubjectNotFound = errors.New("pairwise: no internal subject has this body")

// mappingAttempts bounds how many random bodies NewMapping's Deriver
// tries for one input before giving up. Two 256-bit random values
// colliding is vanishingly unlikely, so a collision that persists means
// the random source or the store is broken.
const mappingAttempts = 3

// mappingBodyBytes is the size of a mapping body's random value: 256
// bits, the same strength as an HMAC body.
const mappingBodyBytes = 32

// NewMapping returns a Deriver that gives each end user a random
// pairwise subject identifier per issuer and sector, kept in store, and
// maps it back through Lookup: the mapping-table alternative to NewHMAC
// and a reversible deriver. No key exists whose loss would let anyone
// compute or reverse identifiers; the store is what must be protected
// and kept. Its body is 43 characters: 256 random bits, base64url.
//
// The first body stored for an input is its body from then on, on every
// instance sharing store (PairwiseSubjectStore.GetOrCreate is atomic).
// A store that can't answer fails the derivation; it never falls back
// to anything else.
//
// The returned Deriver implements keys.KeyCustodyAssurance only when
// store implements storage.StoreAssurance, reporting its Durable and
// CrossInstanceConsistent declarations, so a production server holds
// the store to the same standard as a key: storage/memstore never
// declares any, so it serves development and tests only. Bodies always
// come from crypto/rand.Reader: a predictable source would make every
// identifier guessable, so there is no option to replace it.
func NewMapping(store storage.PairwiseSubjectStore) (Deriver, error) {
	return newMapping(store, rand.Reader)
}

// newMapping is NewMapping with its random source, for tests.
func newMapping(store storage.PairwiseSubjectStore, random io.Reader) (Deriver, error) {
	if store == nil {
		return nil, errors.New("pairwise: mapping store is nil")
	}
	if random == nil {
		return nil, errors.New("pairwise: mapping random source is nil")
	}
	d := mappingDeriver{store: store, random: random}
	if asserter, ok := store.(storage.StoreAssurance); ok {
		return assuredMappingDeriver{mappingDeriver: d, store: asserter}, nil
	}
	return d, nil
}

// mappingDeriver is NewMapping's Deriver for a store that declares no
// capabilities.
type mappingDeriver struct {
	store  storage.PairwiseSubjectStore
	random io.Reader
}

// DerivePairwiseSubject implements Deriver.
func (d mappingDeriver) DerivePairwiseSubject(ctx context.Context, in Input) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if in.IsZero() {
		return "", errZeroInput
	}
	key := storage.PairwiseSubjectKey{Issuer: in.Issuer(), Sector: in.Sector(), Subject: in.Subject()}
	var lastErr error
	for range mappingAttempts {
		candidate, err := d.candidate()
		if err != nil {
			return "", err
		}
		body, err := d.store.GetOrCreate(ctx, key, candidate)
		if errors.Is(err, storage.ErrPairwiseSubjectCollision) {
			lastErr = err
			continue
		}
		if err != nil {
			return "", fmt.Errorf("pairwise: mapping store: %w", err)
		}
		if err := CheckBody(body); err != nil {
			return "", fmt.Errorf("pairwise: mapping store returned an invalid body: %w", err)
		}
		return body, nil
	}
	return "", fmt.Errorf("pairwise: no unused body after %d attempts: %w", mappingAttempts, lastErr)
}

// candidate returns a fresh random body.
func (d mappingDeriver) candidate() (string, error) {
	raw := make([]byte, mappingBodyBytes)
	if _, err := io.ReadFull(d.random, raw); err != nil {
		return "", fmt.Errorf("pairwise: mapping random source: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// LookupInternalSubject implements Lookup.
func (d mappingDeriver) LookupInternalSubject(ctx context.Context, issuer, sector, body string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	subject, err := d.store.Lookup(ctx, issuer, sector, body)
	if errors.Is(err, storage.ErrPairwiseSubjectNotFound) {
		return "", fmt.Errorf("%w: %w", ErrSubjectNotFound, err)
	}
	if err != nil {
		return "", fmt.Errorf("pairwise: mapping store: %w", err)
	}
	return subject, nil
}

// assuredMappingDeriver is a mappingDeriver whose store declares its
// capabilities.
type assuredMappingDeriver struct {
	mappingDeriver
	store storage.StoreAssurance
}

// KeyCustody implements keys.KeyCustodyAssurance with the store's own
// declaration: the store is what a mapping deriver's identifiers depend
// on, as a key is for a deriving one.
func (d assuredMappingDeriver) KeyCustody() keys.KeyCustody {
	caps := d.store.Capabilities()
	return keys.KeyCustody{Durable: caps.Durable, CrossInstanceConsistent: caps.CrossInstanceConsistent}
}
