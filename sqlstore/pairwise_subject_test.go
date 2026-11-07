package sqlstore_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/fapigo/sqlstore"
	"github.com/idfoundry/fapigo/storage"
)

// A returning user's GetOrCreate is a read: it returns the stored body,
// not the new candidate, without waiting for the write lock (on SQLite,
// held here by another writer of the same handle).
func TestPairwiseReturningUserIsARead(t *testing.T) {
	ctx := context.Background()
	d := freshDB(t, sqlstore.SQLite)
	key := storage.PairwiseSubjectKey{Issuer: "i", Sector: "s", Subject: "u"}
	body, err := d.PairwiseSubjects().GetOrCreate(ctx, key, "first")
	if err != nil || body != "first" {
		t.Fatalf("first GetOrCreate = %q, %v, want first", body, err)
	}
	release := sqlstore.HoldSQLiteWrites(d)
	defer release()
	short, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if body, err := d.PairwiseSubjects().GetOrCreate(short, key, "second"); err != nil || body != "first" {
		t.Fatalf("returning user's GetOrCreate with writes held = %q, %v, want first, nil", body, err)
	}
}

// Of concurrent first uses through several handles, each user gets one
// body and a body goes to one user: for one user and many candidates
// every call returns the same body, and for many users and one
// candidate exactly one gets it and every other a collision.
func TestPairwiseConcurrentFirstUse(t *testing.T) {
	forEachDialect(t, func(t *testing.T, dialect sqlstore.Dialect) {
		ctx := context.Background()
		p := newPlace(t, dialect)
		p.migrated()
		var handles []*sqlstore.DB
		for range 4 {
			d, _ := p.openPool()
			handles = append(handles, d)
		}
		bodies := make([]string, 20)
		concurrentWins(handles, func(d *sqlstore.DB, i int) bool {
			body, err := d.PairwiseSubjects().GetOrCreate(ctx, storage.PairwiseSubjectKey{Issuer: "i", Sector: "s", Subject: "one user"}, fmt.Sprint("candidate-", i))
			bodies[i] = fmt.Sprint(body, err)
			return err == nil
		})
		for _, body := range bodies {
			if body != bodies[0] || !strings.HasPrefix(body, "candidate-") {
				t.Fatalf("concurrent first uses by one user returned %q, want one body", bodies)
			}
		}
		errs := make([]error, 20)
		owners := concurrentWins(handles, func(d *sqlstore.DB, i int) bool {
			body, err := d.PairwiseSubjects().GetOrCreate(ctx, storage.PairwiseSubjectKey{Issuer: "i", Sector: "s", Subject: fmt.Sprint("user-", i)}, "contested")
			errs[i] = err
			return err == nil && body == "contested"
		})
		checkOneWinner(t, "GetOrCreate of one body for many users", errs, func(err error) bool {
			return errors.Is(err, storage.ErrPairwiseSubjectCollision)
		})
		if owners != 1 {
			t.Fatalf("%d users got one contested body, want exactly 1", owners)
		}
	})
}
