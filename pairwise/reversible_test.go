package pairwise_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/pairwise"
)

var (
	testMACKey = bytes.Repeat([]byte{0x01, 0x02}, 16)
	testEncKey = bytes.Repeat([]byte{0x03, 0x04}, 16)
)

func newReversible(t *testing.T) pairwise.Deriver {
	t.Helper()
	d, err := pairwise.NewReversible(testMACKey, testEncKey)
	if err != nil {
		t.Fatalf("NewReversible: %v", err)
	}
	return d
}

func reversibleLookup(t *testing.T, d pairwise.Deriver) pairwise.Lookup {
	t.Helper()
	lookup, ok := d.(pairwise.Lookup)
	if !ok {
		t.Fatal("NewReversible's Deriver doesn't implement pairwise.Lookup")
	}
	return lookup
}

func reversibleInput(t *testing.T, issuer, sector, subject string) pairwise.Input {
	t.Helper()
	in, err := pairwise.NewInput(issuer, sector, subject)
	if err != nil {
		t.Fatalf("NewInput: %v", err)
	}
	return in
}

func deriveReversible(t *testing.T, d pairwise.Deriver, in pairwise.Input) string {
	t.Helper()
	body, err := d.DerivePairwiseSubject(context.Background(), in)
	if err != nil {
		t.Fatalf("DerivePairwiseSubject: %v", err)
	}
	return body
}

func TestReversibleDeriverContract(t *testing.T) {
	pairwise.TestDeriverContract(t, newReversible)
}

// TestReversibleKnownAnswers checks the construction against vectors
// computed by an independent implementation (testdata/reversible_vectors.py:
// Python's hmac/hashlib for the synthetic IV, the OpenSSL command-line
// tool for AES-256-CTR), in both directions.
func TestReversibleKnownAnswers(t *testing.T) {
	raw, err := os.ReadFile("testdata/reversible_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Vectors []struct {
			MACKey  string `json:"mac_key"`
			EncKey  string `json:"enc_key"`
			Issuer  string `json:"issuer"`
			Sector  string `json:"sector"`
			Subject string `json:"subject"`
			Body    string `json:"body"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	if len(file.Vectors) == 0 {
		t.Fatal("no vectors")
	}
	for _, v := range file.Vectors {
		d := reversibleFromHex(t, v.MACKey, v.EncKey)
		in := reversibleInput(t, v.Issuer, v.Sector, v.Subject)
		if body := deriveReversible(t, d, in); body != v.Body {
			t.Errorf("derive(%s, %q, %q, %.20q) = %q, want %q", v.MACKey[:8], v.Issuer, v.Sector, v.Subject, body, v.Body)
		}
		got, err := reversibleLookup(t, d).LookupInternalSubject(context.Background(), v.Issuer, v.Sector, v.Body)
		if err != nil || got != v.Subject {
			t.Errorf("lookup(%.20q) = %q, %v; want %q", v.Body, got, err, v.Subject)
		}
	}
}

func reversibleFromHex(t *testing.T, macHex, encHex string) pairwise.Deriver {
	t.Helper()
	macKey, err := hex.DecodeString(macHex)
	if err != nil {
		t.Fatal(err)
	}
	encKey, err := hex.DecodeString(encHex)
	if err != nil {
		t.Fatal(err)
	}
	d, err := pairwise.NewReversible(macKey, encKey)
	if err != nil {
		t.Fatalf("NewReversible: %v", err)
	}
	return d
}

func TestReversibleBodyLength(t *testing.T) {
	if pairwise.ReversibleBodyLength != 224 {
		t.Errorf("ReversibleBodyLength = %d, want 224", pairwise.ReversibleBodyLength)
	}
	if pairwise.ReversibleBodyLength+pairwise.MaxPrefixLength > 255 {
		t.Errorf("a %d-character body with a %d-character prefix exceeds OIDC's 255-character sub", pairwise.ReversibleBodyLength, pairwise.MaxPrefixLength)
	}
	d := newReversible(t)
	for _, subject := range []string{"u", "user-1", strings.Repeat("x", pairwise.MaxReversibleSubjectLength)} {
		body := deriveReversible(t, d, reversibleInput(t, "https://op.example", "rp.example", subject))
		if len(body) != pairwise.ReversibleBodyLength {
			t.Errorf("body for a %d-byte subject is %d characters, want %d", len(subject), len(body), pairwise.ReversibleBodyLength)
		}
	}
}

func TestNewReversibleRefusesWeakKeys(t *testing.T) {
	for name, keyPair := range map[string][2][]byte{
		"empty MAC key":    {nil, testEncKey},
		"empty enc key":    {testMACKey, nil},
		"short MAC key":    {testMACKey[:31], testEncKey},
		"long enc key":     {testMACKey, append(append([]byte(nil), testEncKey...), 0x05)},
		"zero MAC key":     {make([]byte, 32), testEncKey},
		"repeated enc key": {testMACKey, bytes.Repeat([]byte{0x5a}, 32)},
		"equal keys":       {testMACKey, append([]byte(nil), testMACKey...)},
	} {
		if _, err := pairwise.NewReversible(keyPair[0], keyPair[1]); err == nil {
			t.Errorf("NewReversible(%s) succeeded, want an error", name)
		}
	}
}

func TestNewReversibleCopiesTheKeys(t *testing.T) {
	macKey := append([]byte(nil), testMACKey...)
	encKey := append([]byte(nil), testEncKey...)
	d, err := pairwise.NewReversible(macKey, encKey)
	if err != nil {
		t.Fatal(err)
	}
	in := reversibleInput(t, "https://op.example", "rp.example", "user-1")
	before := deriveReversible(t, d, in)
	macKey[0] ^= 0xff
	encKey[0] ^= 0xff
	if after := deriveReversible(t, d, in); after != before {
		t.Error("changing the caller's key slices changed the Deriver's output")
	}
}

func TestReversibleRefusesALongSubject(t *testing.T) {
	in := reversibleInput(t, "https://op.example", "rp.example", strings.Repeat("x", pairwise.MaxReversibleSubjectLength+1))
	if _, err := newReversible(t).DerivePairwiseSubject(context.Background(), in); !errors.Is(err, pairwise.ErrSubjectTooLong) {
		t.Errorf("err = %v, want ErrSubjectTooLong", err)
	}
}

func TestReversibleRefusesTheZeroInput(t *testing.T) {
	if _, err := newReversible(t).DerivePairwiseSubject(context.Background(), pairwise.Input{}); err == nil {
		t.Error("DerivePairwiseSubject(Input{}) succeeded, want an error")
	}
}

// TestReversibleLookupRefuses: every body that isn't exactly one this
// Deriver derived for that issuer and sector is ErrSubjectNotFound,
// never a different subject.
func TestReversibleLookupRefuses(t *testing.T) {
	d := newReversible(t)
	in := reversibleInput(t, "https://op.example", "rp.example", "user-1")
	body := deriveReversible(t, d, in)
	other, err := pairwise.NewReversible(testEncKey, testMACKey)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]struct {
		lookup                 pairwise.Lookup
		issuer, sector, target string
	}{
		"another sector": {reversibleLookup(t, d), in.Issuer(), "other.example", body},
		"another issuer": {reversibleLookup(t, d), "https://other-op.example", in.Sector(), body},
		"other keys":     {reversibleLookup(t, other), in.Issuer(), in.Sector(), body},
		"empty":          {reversibleLookup(t, d), in.Issuer(), in.Sector(), ""},
		"truncated":      {reversibleLookup(t, d), in.Issuer(), in.Sector(), body[:len(body)-1]},
		"extended":       {reversibleLookup(t, d), in.Issuer(), in.Sector(), body + "A"},
		"padded base64":  {reversibleLookup(t, d), in.Issuer(), in.Sector(), body[:len(body)-2] + "=="},
		"HMAC-shaped":    {reversibleLookup(t, d), in.Issuer(), in.Sector(), body[:pairwise.HMACBodyLength]},
	}
	if std := strings.NewReplacer("-", "+", "_", "/").Replace(body); std != body {
		cases["standard alphabet"] = struct {
			lookup                 pairwise.Lookup
			issuer, sector, target string
		}{reversibleLookup(t, d), in.Issuer(), in.Sector(), std}
	}
	for name, tc := range cases {
		got, err := tc.lookup.LookupInternalSubject(context.Background(), tc.issuer, tc.sector, tc.target)
		if !errors.Is(err, pairwise.ErrSubjectNotFound) {
			t.Errorf("%s: LookupInternalSubject = %q, %v; want ErrSubjectNotFound", name, got, err)
		}
	}
}

// TestReversibleLookupRefusesEveryBitFlip: flipping any single bit of
// the decoded body (in the IV or the ciphertext) fails authentication.
func TestReversibleLookupRefusesEveryBitFlip(t *testing.T) {
	d := newReversible(t)
	lookup := reversibleLookup(t, d)
	in := reversibleInput(t, "https://op.example", "rp.example", "user-1")
	sealed, err := base64.RawURLEncoding.DecodeString(deriveReversible(t, d, in))
	if err != nil {
		t.Fatal(err)
	}
	for i := range len(sealed) * 8 {
		flipped := append([]byte(nil), sealed...)
		flipped[i/8] ^= 1 << (i % 8)
		got, err := lookup.LookupInternalSubject(context.Background(), in.Issuer(), in.Sector(), base64.RawURLEncoding.EncodeToString(flipped))
		if !errors.Is(err, pairwise.ErrSubjectNotFound) {
			t.Fatalf("bit %d flipped: LookupInternalSubject = %q, %v; want ErrSubjectNotFound", i, got, err)
		}
	}
}

func TestReversibleHonoursCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	d := newReversible(t)
	in := reversibleInput(t, "https://op.example", "rp.example", "user-1")
	if _, err := d.DerivePairwiseSubject(ctx, in); !errors.Is(err, context.Canceled) {
		t.Errorf("DerivePairwiseSubject err = %v, want context.Canceled", err)
	}
	body := deriveReversible(t, d, in)
	if _, err := reversibleLookup(t, d).LookupInternalSubject(ctx, in.Issuer(), in.Sector(), body); !errors.Is(err, context.Canceled) {
		t.Errorf("LookupInternalSubject err = %v, want context.Canceled", err)
	}
}

func TestNewReversibleDeclaresCustodyOnlyWhenGiven(t *testing.T) {
	if _, ok := newReversible(t).(keys.KeyCustodyAssurance); ok {
		t.Error("a reversible Deriver with no custody declared implements keys.KeyCustodyAssurance")
	}
	want := keys.KeyCustody{Durable: true, CrossInstanceConsistent: true}
	d, err := pairwise.NewReversible(testMACKey, testEncKey, keys.DeclareCustody(want))
	if err != nil {
		t.Fatal(err)
	}
	asserter, ok := d.(keys.KeyCustodyAssurance)
	if !ok || asserter.KeyCustody() != want {
		t.Errorf("custody = %+v (implements: %v), want %+v", asserter, ok, want)
	}
	if _, ok := d.(pairwise.Lookup); !ok {
		t.Error("a reversible Deriver with custody declared doesn't implement pairwise.Lookup")
	}
}

// TestReversibleLookupRefusesOverlongContext: an issuer or sector longer
// than MaxInputLength, which no Input carries, is refused before
// anything is computed over it.
func TestReversibleLookupRefusesOverlongContext(t *testing.T) {
	d := newReversible(t)
	in := reversibleInput(t, "https://op.example", "rp.example", "user-1")
	body := deriveReversible(t, d, in)
	long := strings.Repeat("x", pairwise.MaxInputLength+1)
	for name, args := range map[string][2]string{"issuer": {long, in.Sector()}, "sector": {in.Issuer(), long}} {
		got, err := reversibleLookup(t, d).LookupInternalSubject(context.Background(), args[0], args[1], body)
		if !errors.Is(err, pairwise.ErrSubjectNotFound) || !strings.Contains(err.Error(), "longer than") {
			t.Errorf("%s too long: LookupInternalSubject = %q, %v; want ErrSubjectNotFound for its length", name, got, err)
		}
	}
	atLimit := reversibleInput(t, strings.Repeat("i", pairwise.MaxInputLength), strings.Repeat("s", pairwise.MaxInputLength), "user-1")
	if got, err := reversibleLookup(t, d).LookupInternalSubject(context.Background(), atLimit.Issuer(), atLimit.Sector(), deriveReversible(t, d, atLimit)); err != nil || got != "user-1" {
		t.Errorf("lookup at MaxInputLength = %q, %v; want user-1", got, err)
	}
}
