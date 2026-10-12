package pairwise

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/idfoundry/fapigo/storage/memstore"
)

func internalInput(t *testing.T) Input {
	t.Helper()
	in, err := NewInput("https://op.example", "rp.example", "user-1")
	if err != nil {
		t.Fatalf("NewInput: %v", err)
	}
	return in
}

func TestNewMappingRefusesANilStore(t *testing.T) {
	if _, err := NewMapping(nil); err == nil {
		t.Error("NewMapping(nil) succeeded")
	}
	if _, err := newMapping(memstore.NewPairwiseSubjectStore(), nil); err == nil {
		t.Error("newMapping(nil random) succeeded")
	}
}

func TestNewMappingDrawsFromCryptoRand(t *testing.T) {
	d, err := NewMapping(memstore.NewPairwiseSubjectStore())
	if err != nil {
		t.Fatalf("NewMapping: %v", err)
	}
	var random any
	switch m := d.(type) {
	case mappingDeriver:
		random = m.random
	case assuredMappingDeriver:
		random = m.random
	default:
		t.Fatalf("NewMapping returned %T", d)
	}
	if random != rand.Reader {
		t.Errorf("NewMapping's random source is %T, want crypto/rand.Reader", random)
	}
}

func TestMappingBodyIsRandom256Bits(t *testing.T) {
	d, err := newMapping(memstore.NewPairwiseSubjectStore(), bytes.NewReader(bytes.Repeat([]byte{0xff}, 32)))
	if err != nil {
		t.Fatalf("newMapping: %v", err)
	}
	body, err := d.DerivePairwiseSubject(context.Background(), internalInput(t))
	if err != nil {
		t.Fatalf("DerivePairwiseSubject: %v", err)
	}
	if want := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0xff}, 32)); body != want || len(body) != 43 {
		t.Errorf("body = %q, want 32 bytes of 0xff base64url-encoded (%q)", body, want)
	}
}

func TestMappingFailsWhenRandomFails(t *testing.T) {
	d, err := newMapping(memstore.NewPairwiseSubjectStore(), bytes.NewReader(make([]byte, 31)))
	if err != nil {
		t.Fatalf("newMapping: %v", err)
	}
	if body, err := d.DerivePairwiseSubject(context.Background(), internalInput(t)); err == nil {
		t.Errorf("DerivePairwiseSubject = %q with a short random source, want an error", body)
	}
}
