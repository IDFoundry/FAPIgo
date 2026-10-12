package pairwise_test

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/idfoundry/fapigo/pairwise"
)

// fuzzReversible is a Deriver and its Lookup, built once per target.
func fuzzReversible(f *testing.F) (pairwise.Deriver, pairwise.Lookup) {
	f.Helper()
	d, err := pairwise.NewReversible(testMACKey, testEncKey)
	if err != nil {
		f.Fatal(err)
	}
	return d, d.(pairwise.Lookup)
}

// FuzzReversibleRoundTrip: every Input NewInput accepts with a subject
// the construction holds derives to a valid body that looks up to that
// subject under its own issuer and sector, and to nothing (never another
// subject) under any other.
func FuzzReversibleRoundTrip(f *testing.F) {
	f.Add("https://op.example", "rp.example", "user-1", "other.example")
	f.Add("https://op.example", "a", "u", "b")
	f.Add("https://op.example/x", "rp.example", "user with spaces", "rp.example.")
	d, lookup := fuzzReversible(f)
	f.Fuzz(func(t *testing.T, issuer, sector, subject, otherSector string) {
		in, err := pairwise.NewInput(issuer, sector, subject)
		if err != nil || len(subject) > pairwise.ReversibleMaxSubjectLength {
			return
		}
		checkReversibleRoundTrip(t, d, lookup, in, otherSector)
	})
}

// checkReversibleRoundTrip derives in's body and checks it is valid,
// looks up to in's subject, and is not found under otherSector.
func checkReversibleRoundTrip(t *testing.T, d pairwise.Deriver, lookup pairwise.Lookup, in pairwise.Input, otherSector string) {
	t.Helper()
	ctx := context.Background()
	body, err := d.DerivePairwiseSubject(ctx, in)
	if err != nil {
		t.Fatalf("DerivePairwiseSubject: %v", err)
	}
	if err := pairwise.CheckBody(body); err != nil || len(body) != pairwise.ReversibleBodyLength {
		t.Fatalf("body %q: %v (length %d)", body, err, len(body))
	}
	if got, err := lookup.LookupInternalSubject(ctx, in.Issuer(), in.Sector(), body); err != nil || got != in.Subject() {
		t.Fatalf("lookup = %q, %v; want %q", got, err, in.Subject())
	}
	if otherSector == in.Sector() {
		return
	}
	if got, err := lookup.LookupInternalSubject(ctx, in.Issuer(), otherSector, body); !errors.Is(err, pairwise.ErrSubjectNotFound) {
		t.Fatalf("lookup under sector %q = %q, %v; want ErrSubjectNotFound", otherSector, got, err)
	}
}

// FuzzReversibleTamper: changing any byte of a body's decoded form (IV
// or ciphertext) to any other value fails authentication.
func FuzzReversibleTamper(f *testing.F) {
	f.Add("user-1", uint8(0), uint8(1))
	f.Add("user-1", uint8(16), uint8(0x80))
	f.Add("u", uint8(167), uint8(0xff))
	d, lookup := fuzzReversible(f)
	f.Fuzz(func(t *testing.T, subject string, at, xor uint8) {
		in, err := pairwise.NewInput("https://op.example", "rp.example", subject)
		if err != nil || len(subject) > pairwise.ReversibleMaxSubjectLength || xor == 0 {
			return
		}
		body, err := d.DerivePairwiseSubject(context.Background(), in)
		if err != nil {
			t.Fatal(err)
		}
		sealed, err := base64.RawURLEncoding.DecodeString(body)
		if err != nil {
			t.Fatal(err)
		}
		sealed[int(at)%len(sealed)] ^= xor
		got, err := lookup.LookupInternalSubject(context.Background(), in.Issuer(), in.Sector(), base64.RawURLEncoding.EncodeToString(sealed))
		if !errors.Is(err, pairwise.ErrSubjectNotFound) {
			t.Fatalf("tampered body looked up to %q, %v; want ErrSubjectNotFound", got, err)
		}
	})
}

// FuzzReversibleLookupArbitrary: any string as a body, under any issuer
// and sector, is either ErrSubjectNotFound or (for a body this Deriver
// actually derived) its subject; it never panics.
func FuzzReversibleLookupArbitrary(f *testing.F) {
	f.Add("https://op.example", "rp.example", "")
	f.Add("https://op.example", "rp.example", "AAAA")
	f.Add("x", "y", string(make([]byte, pairwise.ReversibleBodyLength)))
	_, lookup := fuzzReversible(f)
	f.Fuzz(func(t *testing.T, issuer, sector, body string) {
		got, err := lookup.LookupInternalSubject(context.Background(), issuer, sector, body)
		if err == nil {
			t.Fatalf("an arbitrary body %q looked up to %q", body, got)
		}
		if !errors.Is(err, pairwise.ErrSubjectNotFound) {
			t.Fatalf("err = %v, want ErrSubjectNotFound", err)
		}
	})
}
