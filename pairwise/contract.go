package pairwise

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// This file is a reusable contract test suite, not a _test.go file, so
// that a Deriver of the embedder's own (backed by an HSM, a KMS or an
// identity platform's existing pairwise service) can import it and run
// it against its own factory, as storage's contract suites are run
// against a store.

// TestDeriverContract checks the observable parts of the Deriver
// contract against factory's Derivers: a valid body, the same body for
// the same Input from two separately built Derivers (as two instances,
// or one instance before and after a restart, would build them),
// different bodies for different users, sectors and issuers, and the
// zero Input refused. When the Deriver implements Lookup, it also checks
// that every body it derives looks up to its internal subject, and that
// an altered body and a body under another sector are ErrSubjectNotFound. factory must
// build each Deriver from the same configuration and secret.
//
// It can't check that a body is unlinkable without the secret; that is
// for the construction's own review.
func TestDeriverContract(t *testing.T, factory func(t *testing.T) Deriver) {
	t.Helper()
	t.Run("ValidBody", func(t *testing.T) { testDeriverValidBody(t, factory) })
	t.Run("DeterministicAcrossInstances", func(t *testing.T) { testDeriverDeterministic(t, factory) })
	t.Run("DistinctInputsDistinctBodies", func(t *testing.T) { testDeriverDistinct(t, factory) })
	t.Run("ZeroInputRefused", func(t *testing.T) { testDeriverZeroInput(t, factory) })
	t.Run("LookupRoundTrips", func(t *testing.T) { testDeriverLookup(t, factory) })
}

func contractInput(t *testing.T, issuer, sector, subject string) Input {
	t.Helper()
	in, err := NewInput(issuer, sector, subject)
	if err != nil {
		t.Fatalf("NewInput(%q, %q, %q): %v", issuer, sector, subject, err)
	}
	return in
}

func contractDerive(t *testing.T, d Deriver, in Input) string {
	t.Helper()
	body, err := d.DerivePairwiseSubject(context.Background(), in)
	if err != nil {
		t.Fatalf("DerivePairwiseSubject(%v): %v", in, err)
	}
	return body
}

func testDeriverValidBody(t *testing.T, factory func(t *testing.T) Deriver) {
	d := factory(t)
	for _, subject := range []string{"u", "user-1", "user with spaces", longSubject} {
		body := contractDerive(t, d, contractInput(t, "https://op.example", "rp.example", subject))
		if err := CheckBody(body); err != nil {
			t.Errorf("body for %q: %v", subject, err)
		}
	}
}

func testDeriverDeterministic(t *testing.T, factory func(t *testing.T) Deriver) {
	in := contractInput(t, "https://op.example", "rp.example", "user-1")
	first := contractDerive(t, factory(t), in)
	if second := contractDerive(t, factory(t), in); second != first {
		t.Errorf("two Derivers from the same configuration gave %q and %q for the same Input", first, second)
	}
	if again := contractDerive(t, factory(t), in); again != first {
		t.Errorf("a Deriver gave %q, then %q, for the same Input", first, again)
	}
}

func testDeriverDistinct(t *testing.T, factory func(t *testing.T) Deriver) {
	d := factory(t)
	inputs := []Input{
		contractInput(t, "https://op.example", "rp.example", "user-1"),
		contractInput(t, "https://op.example", "rp.example", "user-2"),
		contractInput(t, "https://op.example", "other.example", "user-1"),
		contractInput(t, "https://other-op.example", "rp.example", "user-1"),
		// Inputs whose fields concatenate the same way.
		contractInput(t, "https://op.example", "rp.exampleuser", "-1"),
		contractInput(t, "https://op.examplerp.example", "u", "ser-1"),
	}
	seen := map[string]Input{}
	for _, in := range inputs {
		body := contractDerive(t, d, in)
		if prev, dup := seen[body]; dup {
			t.Errorf("%v and %v both gave %q", prev, in, body)
		}
		seen[body] = in
	}
}

func testDeriverZeroInput(t *testing.T, factory func(t *testing.T) Deriver) {
	if body, err := factory(t).DerivePairwiseSubject(context.Background(), Input{}); err == nil {
		t.Errorf("DerivePairwiseSubject(Input{}) = %q, want an error", body)
	}
}

func testDeriverLookup(t *testing.T, factory func(t *testing.T) Deriver) {
	d := factory(t)
	lookup, ok := d.(Lookup)
	if !ok {
		t.Skip("the Deriver doesn't implement Lookup")
	}
	ctx := context.Background()
	in := contractInput(t, "https://op.example", "rp.example", "user-1")
	body := contractDerive(t, d, in)
	if got, err := lookup.LookupInternalSubject(ctx, in.Issuer(), in.Sector(), body); err != nil || got != in.Subject() {
		t.Errorf("LookupInternalSubject(%q) = %q, %v; want %q", body, got, err, in.Subject())
	}
	if got, err := factory(t).(Lookup).LookupInternalSubject(ctx, in.Issuer(), in.Sector(), body); err != nil || got != in.Subject() {
		t.Errorf("another instance's LookupInternalSubject(%q) = %q, %v; want %q", body, got, err, in.Subject())
	}
	if got, err := lookup.LookupInternalSubject(ctx, in.Issuer(), "other.example", body); !errors.Is(err, ErrSubjectNotFound) {
		t.Errorf("LookupInternalSubject under another sector = %q, %v; want ErrSubjectNotFound", got, err)
	}
	if got, err := lookup.LookupInternalSubject(ctx, "https://other-op.example", in.Sector(), body); !errors.Is(err, ErrSubjectNotFound) {
		t.Errorf("LookupInternalSubject under another issuer = %q, %v; want ErrSubjectNotFound", got, err)
	}
	other := contractInput(t, "https://op.example", "rp.example", "user-2")
	otherBody := contractDerive(t, d, other)
	if got, err := lookup.LookupInternalSubject(ctx, other.Issuer(), other.Sector(), otherBody); err != nil || got != other.Subject() {
		t.Errorf("LookupInternalSubject(%q) = %q, %v; want %q", otherBody, got, err, other.Subject())
	}
	if got, err := lookup.LookupInternalSubject(ctx, in.Issuer(), in.Sector(), alterBody(otherBody)); !errors.Is(err, ErrSubjectNotFound) {
		t.Errorf("LookupInternalSubject of an altered body = %q, %v; want ErrSubjectNotFound", got, err)
	}
	// A well-formed body of the Deriver's own length that it never gave.
	never := strings.Repeat("A", len(body))
	if got, err := lookup.LookupInternalSubject(ctx, in.Issuer(), in.Sector(), never); !errors.Is(err, ErrSubjectNotFound) {
		t.Errorf("LookupInternalSubject of a body never derived = %q, %v; want ErrSubjectNotFound", got, err)
	}
}

// base64URLAlphabet is the alphabet of a base64url-encoded body.
const base64URLAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

// alterBody returns body with its middle character changed to another
// printable one. A base64url character becomes the next one in the
// alphabet, so a body that decodes still decodes, and the change
// reaches the Deriver's own check (authentication, or a lookup) rather
// than only its decoding.
func alterBody(body string) string {
	altered := []byte(body)
	i := len(altered) / 2
	if j := strings.IndexByte(base64URLAlphabet, altered[i]); j >= 0 {
		altered[i] = base64URLAlphabet[(j+1)%len(base64URLAlphabet)]
	} else if altered[i] == '~' {
		altered[i] = '!'
	} else {
		altered[i]++
	}
	return string(altered)
}

// longSubject is the longest internal subject every Deriver must
// accept: a Reversible one may cap internal subjects at 151 bytes.
var longSubject = strings.Repeat("x", 151)
