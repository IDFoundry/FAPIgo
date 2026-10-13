package pairwise_test

import (
	"context"
	"testing"

	"github.com/idfoundry/fapigo/pairwise"
)

// FuzzReversibleWithRoundTrip: over ops holding the keys,
// NewReversibleWith derives exactly NewReversible's body for every
// Input the construction holds, and that body round-trips through its
// Lookup (and is not found under another sector).
func FuzzReversibleWithRoundTrip(f *testing.F) {
	f.Add("https://op.example", "rp.example", "user-1", "other.example")
	f.Add("https://op.example/x", "a", "user with spaces", "rp.example.")
	inMemory, _ := fuzzReversible(f)
	withOps, err := pairwise.NewReversibleWith(newHSMOps(f, testMACKey, testEncKey))
	if err != nil {
		f.Fatal(err)
	}
	lookup := withOps.(pairwise.Lookup)
	f.Fuzz(func(t *testing.T, issuer, sector, subject, otherSector string) {
		in, err := pairwise.NewInput(issuer, sector, subject)
		if err != nil || len(subject) > pairwise.MaxReversibleSubjectLength {
			return
		}
		want, err := inMemory.DerivePairwiseSubject(context.Background(), in)
		if err != nil {
			t.Fatal(err)
		}
		got, err := withOps.DerivePairwiseSubject(context.Background(), in)
		if err != nil || got != want {
			t.Fatalf("NewReversibleWith body = %q, %v; NewReversible's = %q", got, err, want)
		}
		checkReversibleRoundTrip(t, withOps, lookup, in, otherSector)
	})
}
