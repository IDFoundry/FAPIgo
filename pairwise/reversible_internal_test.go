package pairwise

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

// TestParseReversiblePlaintext: the parser only accepts what
// reversiblePlaintext produces. Lookup authenticates first, so these
// refusals are a second line, reachable only with the keys.
func TestParseReversiblePlaintext(t *testing.T) {
	valid, err := reversiblePlaintext("user-1")
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := parseReversiblePlaintext(valid); !ok || got != "user-1" {
		t.Fatalf("parse(valid) = %q, %v; want user-1", got, ok)
	}
	full, err := reversiblePlaintext(strings.Repeat("x", MaxReversibleSubjectLength))
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := parseReversiblePlaintext(full); !ok || len(got) != MaxReversibleSubjectLength {
		t.Fatalf("parse(full) = %d bytes, %v", len(got), ok)
	}
	mutate := func(f func(p []byte)) []byte {
		p := append([]byte(nil), valid...)
		f(p)
		return p
	}
	for name, p := range map[string][]byte{
		"zero length":        mutate(func(p []byte) { p[0] = 0 }),
		"empty subject":      make([]byte, ReversiblePlaintextLength),
		"length too long":    mutate(func(p []byte) { p[0] = MaxReversibleSubjectLength + 1 }),
		"length 255":         mutate(func(p []byte) { p[0] = 0xff }),
		"non-zero padding":   mutate(func(p []byte) { p[len(p)-1] = 1 }),
		"padding after":      mutate(func(p []byte) { p[1+len("user-1")] = 'x' }),
		"control in subject": mutate(func(p []byte) { p[1] = '\n' }),
		"high byte":          mutate(func(p []byte) { p[2] = 0x80 }),
	} {
		if got, ok := parseReversiblePlaintext(p); ok {
			t.Errorf("%s: parse = %q, accepted", name, got)
		}
	}
	if !bytes.Equal(valid[1+len("user-1"):], make([]byte, ReversiblePlaintextLength-1-len("user-1"))) {
		t.Error("reversiblePlaintext didn't zero-pad")
	}
}

// TestReversibleAuthenticatesTheWholeIV: a body whose IV differs from
// the synthetic IV in any one byte, even with the plaintext encrypted
// correctly under that IV, is refused, so the comparison covers the
// whole 16-byte tag.
func TestReversibleAuthenticatesTheWholeIV(t *testing.T) {
	d, err := NewReversible(bytes.Repeat([]byte{1, 2}, 16), bytes.Repeat([]byte{3, 4}, 16))
	if err != nil {
		t.Fatal(err)
	}
	r := d.(reversibleDeriver)
	plaintext, err := reversiblePlaintext("user-1")
	if err != nil {
		t.Fatal(err)
	}
	iv := r.syntheticIV("https://op.example", "rp.example", plaintext)
	for i := range reversibleIVLength {
		forged := append([]byte(nil), iv...)
		forged[i] ^= 0x01
		sealed := make([]byte, reversibleIVLength+ReversiblePlaintextLength)
		copy(sealed, forged)
		r.ctr(forged, sealed[reversibleIVLength:], plaintext)
		got, err := r.LookupInternalSubject(context.Background(), "https://op.example", "rp.example", base64.RawURLEncoding.EncodeToString(sealed))
		if !errors.Is(err, ErrSubjectNotFound) {
			t.Fatalf("IV byte %d altered: lookup = %q, %v; want ErrSubjectNotFound", i, got, err)
		}
	}
}

// TestAlterBodyReachesAuthentication: the contract's altered body still
// decodes, for every base64url character at the altered position, so
// against NewReversible it fails authentication, not decoding.
func TestAlterBodyReachesAuthentication(t *testing.T) {
	d, err := NewReversible(bytes.Repeat([]byte{1, 2}, 16), bytes.Repeat([]byte{3, 4}, 16))
	if err != nil {
		t.Fatal(err)
	}
	r := d.(reversibleDeriver)
	in, err := NewInput("https://op.example", "rp.example", "user-1")
	if err != nil {
		t.Fatal(err)
	}
	body, err := r.DerivePairwiseSubject(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []byte(base64URLAlphabet) {
		b := []byte(body)
		b[len(b)/2] = c
		altered := alterBody(string(b))
		if altered == string(b) {
			t.Fatalf("alterBody left %q unchanged", c)
		}
		if altered == body {
			continue // this character rotates back to the genuine body
		}
		if _, ok := decodeReversibleBody(altered); !ok {
			t.Fatalf("alterBody turned %q into a body that doesn't decode", c)
		}
		_, err := r.LookupInternalSubject(context.Background(), in.Issuer(), in.Sector(), altered)
		if !errors.Is(err, ErrSubjectNotFound) || !strings.Contains(err.Error(), "authenticate") {
			t.Fatalf("altered %q: err = %v, want an authentication failure", c, err)
		}
	}
	for _, c := range []byte("!~.") {
		if altered := alterBody(string([]byte{'a', c, 'a'})); altered[1] == c || altered[1] < 0x21 || altered[1] > 0x7e {
			t.Errorf("alterBody(%q) = %q, want another printable character", c, altered)
		}
	}
}
