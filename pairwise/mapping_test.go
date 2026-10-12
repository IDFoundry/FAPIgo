package pairwise_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"testing"

	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/pairwise"
	"github.com/idfoundry/fapigo/storage"
	"github.com/idfoundry/fapigo/storage/memstore"
)

func TestMappingDeriverContract(t *testing.T) {
	// Every instance shares one store, as every server instance would.
	store := memstore.NewPairwiseSubjectStore()
	pairwise.TestDeriverContract(t, func(t *testing.T) pairwise.Deriver {
		return newMapping(t, store, rand.Reader)
	})
}

func newMapping(t *testing.T, store storage.PairwiseSubjectStore, random io.Reader) pairwise.Deriver {
	t.Helper()
	d, err := pairwise.NewMapping(store, random)
	if err != nil {
		t.Fatalf("NewMapping: %v", err)
	}
	return d
}

func mappingInput(t *testing.T, subject string) pairwise.Input {
	t.Helper()
	in, err := pairwise.NewInput("https://op.example", "rp.example", subject)
	if err != nil {
		t.Fatalf("NewInput: %v", err)
	}
	return in
}

func TestNewMappingRefusesNilDependencies(t *testing.T) {
	if _, err := pairwise.NewMapping(nil, rand.Reader); err == nil {
		t.Error("NewMapping(nil store) succeeded")
	}
	if _, err := pairwise.NewMapping(memstore.NewPairwiseSubjectStore(), nil); err == nil {
		t.Error("NewMapping(nil random) succeeded")
	}
}

func TestMappingBodyIsRandom256Bits(t *testing.T) {
	random := bytes.NewReader(bytes.Repeat([]byte{0xff}, 32))
	body, err := newMapping(t, memstore.NewPairwiseSubjectStore(), random).DerivePairwiseSubject(context.Background(), mappingInput(t, "user-1"))
	if err != nil {
		t.Fatalf("DerivePairwiseSubject: %v", err)
	}
	if want := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0xff}, 32)); body != want || len(body) != 43 {
		t.Errorf("body = %q, want 32 bytes of 0xff base64url-encoded (%q)", body, want)
	}
}

// collidingStore reports a collision for its first collisions calls,
// then delegates.
type collidingStore struct {
	storage.PairwiseSubjectStore
	collisions int
	calls      int
	candidates []string
}

func (s *collidingStore) GetOrCreate(ctx context.Context, key storage.PairwiseSubjectKey, candidate string) (string, error) {
	s.calls++
	s.candidates = append(s.candidates, candidate)
	if s.calls <= s.collisions {
		return "", fmt.Errorf("fake: %w", storage.ErrPairwiseSubjectCollision)
	}
	return s.PairwiseSubjectStore.GetOrCreate(ctx, key, candidate)
}

func TestMappingRetriesACollisionWithAFreshCandidate(t *testing.T) {
	store := &collidingStore{PairwiseSubjectStore: memstore.NewPairwiseSubjectStore(), collisions: 2}
	body, err := newMapping(t, store, rand.Reader).DerivePairwiseSubject(context.Background(), mappingInput(t, "user-1"))
	if err != nil {
		t.Fatalf("DerivePairwiseSubject: %v", err)
	}
	if store.calls != 3 {
		t.Errorf("GetOrCreate calls = %d, want 3", store.calls)
	}
	if body != store.candidates[2] {
		t.Errorf("body = %q, want the third candidate %q", body, store.candidates[2])
	}
	if store.candidates[0] == store.candidates[1] || store.candidates[1] == store.candidates[2] {
		t.Errorf("candidates %q repeat: each retry must draw a fresh one", store.candidates)
	}
}

func TestMappingGivesUpAfterRepeatedCollisions(t *testing.T) {
	store := &collidingStore{PairwiseSubjectStore: memstore.NewPairwiseSubjectStore(), collisions: 100}
	_, err := newMapping(t, store, rand.Reader).DerivePairwiseSubject(context.Background(), mappingInput(t, "user-1"))
	if !errors.Is(err, storage.ErrPairwiseSubjectCollision) {
		t.Fatalf("DerivePairwiseSubject = %v, want an error wrapping ErrPairwiseSubjectCollision", err)
	}
	if store.calls != 3 {
		t.Errorf("GetOrCreate calls = %d, want 3", store.calls)
	}
}

// failingStore answers every call with err, or with body.
type failingStore struct {
	err  error
	body string
}

func (s failingStore) GetOrCreate(context.Context, storage.PairwiseSubjectKey, string) (string, error) {
	return s.body, s.err
}

func (s failingStore) Lookup(context.Context, string, string, string) (string, error) {
	return "", s.err
}

func TestMappingFailsClosedWhenTheStoreIsUnavailable(t *testing.T) {
	d := newMapping(t, failingStore{err: fmt.Errorf("fake: %w", storage.ErrStoreUnavailable)}, rand.Reader)
	ctx := context.Background()
	if _, err := d.DerivePairwiseSubject(ctx, mappingInput(t, "user-1")); !errors.Is(err, storage.ErrStoreUnavailable) {
		t.Errorf("DerivePairwiseSubject = %v, want an error wrapping ErrStoreUnavailable", err)
	}
	_, err := d.(pairwise.Lookup).LookupInternalSubject(ctx, "https://op.example", "rp.example", "body")
	if !errors.Is(err, storage.ErrStoreUnavailable) || errors.Is(err, pairwise.ErrSubjectNotFound) {
		t.Errorf("LookupInternalSubject = %v, want ErrStoreUnavailable and never ErrSubjectNotFound", err)
	}
}

func TestMappingRefusesAnInvalidStoredBody(t *testing.T) {
	d := newMapping(t, failingStore{body: "has space"}, rand.Reader)
	if body, err := d.DerivePairwiseSubject(context.Background(), mappingInput(t, "user-1")); err == nil {
		t.Errorf("DerivePairwiseSubject = %q, want an error for a body that isn't printable ASCII", body)
	}
}

func TestMappingFailsWhenRandomFails(t *testing.T) {
	store := memstore.NewPairwiseSubjectStore()
	d := newMapping(t, store, bytes.NewReader(make([]byte, 31)))
	if body, err := d.DerivePairwiseSubject(context.Background(), mappingInput(t, "user-1")); err == nil {
		t.Errorf("DerivePairwiseSubject = %q with a short random source, want an error", body)
	}
}

func TestMappingLookupNotFound(t *testing.T) {
	d := newMapping(t, memstore.NewPairwiseSubjectStore(), rand.Reader)
	_, err := d.(pairwise.Lookup).LookupInternalSubject(context.Background(), "https://op.example", "rp.example", "never-issued")
	if !errors.Is(err, pairwise.ErrSubjectNotFound) || !errors.Is(err, storage.ErrPairwiseSubjectNotFound) {
		t.Errorf("LookupInternalSubject = %v, want ErrSubjectNotFound wrapping ErrPairwiseSubjectNotFound", err)
	}
}

func TestMappingHonoursCancellation(t *testing.T) {
	d := newMapping(t, memstore.NewPairwiseSubjectStore(), rand.Reader)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := d.DerivePairwiseSubject(ctx, mappingInput(t, "user-1")); !errors.Is(err, context.Canceled) {
		t.Errorf("DerivePairwiseSubject = %v, want context.Canceled", err)
	}
	if _, err := d.(pairwise.Lookup).LookupInternalSubject(ctx, "https://op.example", "rp.example", "body"); !errors.Is(err, context.Canceled) {
		t.Errorf("LookupInternalSubject = %v, want context.Canceled", err)
	}
}

// assuredStore is a memstore pairwise store declaring caps.
type assuredStore struct {
	storage.PairwiseSubjectStore
	caps storage.Capabilities
}

func (s assuredStore) Capabilities() storage.Capabilities { return s.caps }

func TestMappingReportsTheStoresDeclarationAsCustody(t *testing.T) {
	if _, ok := newMapping(t, memstore.NewPairwiseSubjectStore(), rand.Reader).(keys.KeyCustodyAssurance); ok {
		t.Error("a mapping over memstore implements KeyCustodyAssurance; it must declare nothing")
	}
	for _, caps := range []storage.Capabilities{
		{Durable: true, CrossInstanceConsistent: true},
		{Durable: true},
		{CrossInstanceConsistent: true},
	} {
		d := newMapping(t, assuredStore{PairwiseSubjectStore: memstore.NewPairwiseSubjectStore(), caps: caps}, rand.Reader)
		asserter, ok := d.(keys.KeyCustodyAssurance)
		if !ok {
			t.Fatalf("a mapping over a store declaring %+v doesn't implement KeyCustodyAssurance", caps)
		}
		want := keys.KeyCustody{Durable: caps.Durable, CrossInstanceConsistent: caps.CrossInstanceConsistent}
		if got := asserter.KeyCustody(); got != want {
			t.Errorf("KeyCustody() = %+v, want %+v", got, want)
		}
		if _, ok := d.(pairwise.Lookup); !ok {
			t.Error("the assured mapping deriver doesn't implement Lookup")
		}
	}
}
