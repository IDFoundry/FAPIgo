package pairwise_test

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/pairwise"
)

// hsmOps is a ReversibleOps over the standard library, standing in for
// an HSM or KMS: the keys stay inside it, and only the two operations
// cross the boundary.
type hsmOps struct {
	macKey []byte
	block  cipher.Block
}

func newHSMOps(t testing.TB, macKey, encKey []byte) hsmOps {
	t.Helper()
	block, err := aes.NewCipher(encKey)
	if err != nil {
		t.Fatal(err)
	}
	return hsmOps{macKey: macKey, block: block}
}

func (o hsmOps) MAC(_ context.Context, data []byte) ([]byte, error) {
	mac := hmac.New(sha256.New, o.macKey)
	mac.Write(data)
	return mac.Sum(nil), nil
}

func (o hsmOps) EncryptCTR(_ context.Context, iv, data []byte) ([]byte, error) {
	out := make([]byte, len(data))
	cipher.NewCTR(o.block, iv).XORKeyStream(out, data)
	return out, nil
}

// counter32Ops is hsmOps with the common porting mistake: a CTR mode
// that increments only the counter block's last 32 bits, as GCM does.
type counter32Ops struct{ hsmOps }

func (o counter32Ops) EncryptCTR(_ context.Context, iv, data []byte) ([]byte, error) {
	out := make([]byte, len(data))
	counter := append([]byte(nil), iv...)
	keystream := make([]byte, aes.BlockSize)
	for i := 0; i < len(data); i += aes.BlockSize {
		o.block.Encrypt(keystream, counter)
		for j := i; j < len(data) && j < i+aes.BlockSize; j++ {
			out[j] = data[j] ^ keystream[j-i]
		}
		binary.BigEndian.PutUint32(counter[12:], binary.BigEndian.Uint32(counter[12:])+1)
	}
	return out, nil
}

// faultyOps is hsmOps whose results can be made to fail or be the wrong
// size.
type faultyOps struct {
	hsmOps
	macErr, ctrErr error
	macLen, ctrLen int // when not 0, the length to return instead
}

func (o faultyOps) MAC(ctx context.Context, data []byte) ([]byte, error) {
	if o.macErr != nil {
		return nil, o.macErr
	}
	sum, _ := o.hsmOps.MAC(ctx, data)
	if o.macLen != 0 {
		return make([]byte, o.macLen), nil
	}
	return sum, nil
}

func (o faultyOps) EncryptCTR(ctx context.Context, iv, data []byte) ([]byte, error) {
	if o.ctrErr != nil {
		return nil, o.ctrErr
	}
	out, _ := o.hsmOps.EncryptCTR(ctx, iv, data)
	if o.ctrLen != 0 {
		return make([]byte, o.ctrLen), nil
	}
	return out, nil
}

func newReversibleWith(t *testing.T, ops pairwise.ReversibleOps) pairwise.Deriver {
	t.Helper()
	d, err := pairwise.NewReversibleWith(ops)
	if err != nil {
		t.Fatalf("NewReversibleWith: %v", err)
	}
	return d
}

func TestNewReversibleWithDeriverContract(t *testing.T) {
	pairwise.TestDeriverContract(t, func(t *testing.T) pairwise.Deriver {
		return newReversibleWith(t, newHSMOps(t, testMACKey, testEncKey))
	})
}

// TestNewReversibleWithKnownAnswers: over ops holding the keys,
// NewReversibleWith reproduces every published vector in both
// directions, so it derives exactly what NewReversible does.
func TestNewReversibleWithKnownAnswers(t *testing.T) {
	for _, v := range reversibleVectors(t) {
		d := newReversibleWith(t, newHSMOps(t, mustHex(t, v.MACKey), mustHex(t, v.EncKey)))
		in := reversibleInput(t, v.Issuer, v.Sector, v.Subject)
		if body := deriveReversible(t, d, in); body != v.Body {
			t.Errorf("derive(%q, %q, %.20q) = %q, want %q", v.Issuer, v.Sector, v.Subject, body, v.Body)
		}
		got, err := reversibleLookup(t, d).LookupInternalSubject(context.Background(), v.Issuer, v.Sector, v.Body)
		if err != nil || got != v.Subject {
			t.Errorf("lookup(%.20q) = %q, %v; want %q", v.Body, got, err, v.Subject)
		}
	}
}

// TestReversibleOpsWith32BitCounterFailCarryVector: ops whose CTR mode
// increments only the last 32 bits of the counter block derive the
// wrong body for the vector whose IV carries out of that word, and
// can't look up its real body.
func TestReversibleOpsWith32BitCounterFailCarryVector(t *testing.T) {
	carry := carryVector(t)
	d := newReversibleWith(t, counter32Ops{newHSMOps(t, mustHex(t, carry.MACKey), mustHex(t, carry.EncKey))})
	in := reversibleInput(t, carry.Issuer, carry.Sector, carry.Subject)
	if deriveReversible(t, d, in) == carry.Body {
		t.Error("a 32-bit counter derived the carry vector's body, want a different one")
	}
	if _, err := reversibleLookup(t, d).LookupInternalSubject(context.Background(), carry.Issuer, carry.Sector, carry.Body); !errors.Is(err, pairwise.ErrSubjectNotFound) {
		t.Errorf("lookup = %v, want ErrSubjectNotFound", err)
	}
}

// TestNewReversibleWithFailsWhenOpsFail: an error or a wrong-sized
// result from ops fails derivation and lookup, and is never
// ErrSubjectNotFound: the key service couldn't answer.
func TestNewReversibleWithFailsWhenOpsFail(t *testing.T) {
	good := newHSMOps(t, testMACKey, testEncKey)
	in := reversibleInput(t, "https://op.example", "rp.example", "user-1")
	body := deriveReversible(t, newReversibleWith(t, good), in)
	unavailable := errors.New("key service unavailable")
	for name, ops := range map[string]faultyOps{
		"MAC error":        {hsmOps: good, macErr: unavailable},
		"CTR error":        {hsmOps: good, ctrErr: unavailable},
		"short MAC":        {hsmOps: good, macLen: sha256.Size - 1},
		"long MAC":         {hsmOps: good, macLen: sha256.Size + 1},
		"short ciphertext": {hsmOps: good, ctrLen: pairwise.ReversiblePlaintextLength - 1},
		"long ciphertext":  {hsmOps: good, ctrLen: pairwise.ReversiblePlaintextLength + 1},
	} {
		t.Run(name, func(t *testing.T) {
			d := newReversibleWith(t, ops)
			if _, err := d.DerivePairwiseSubject(context.Background(), in); err == nil || errors.Is(err, pairwise.ErrSubjectNotFound) {
				t.Errorf("derive err = %v, want a failure that isn't ErrSubjectNotFound", err)
			}
			if _, err := reversibleLookup(t, d).LookupInternalSubject(context.Background(), in.Issuer(), in.Sector(), body); err == nil || errors.Is(err, pairwise.ErrSubjectNotFound) {
				t.Errorf("lookup err = %v, want a failure that isn't ErrSubjectNotFound", err)
			}
		})
	}
}

// ctxOps records the context its operations get.
type ctxOps struct {
	hsmOps
	seen *[]context.Context
}

func (o ctxOps) MAC(ctx context.Context, data []byte) ([]byte, error) {
	*o.seen = append(*o.seen, ctx)
	return o.hsmOps.MAC(ctx, data)
}

func (o ctxOps) EncryptCTR(ctx context.Context, iv, data []byte) ([]byte, error) {
	*o.seen = append(*o.seen, ctx)
	return o.hsmOps.EncryptCTR(ctx, iv, data)
}

type ctxKey struct{}

// TestNewReversibleWithPassesTheContext: each operation gets the
// caller's context, so a key service call is bounded by the request.
func TestNewReversibleWithPassesTheContext(t *testing.T) {
	var seen []context.Context
	d := newReversibleWith(t, ctxOps{hsmOps: newHSMOps(t, testMACKey, testEncKey), seen: &seen})
	ctx := context.WithValue(context.Background(), ctxKey{}, "request")
	in := reversibleInput(t, "https://op.example", "rp.example", "user-1")
	body, err := d.DerivePairwiseSubject(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reversibleLookup(t, d).LookupInternalSubject(ctx, in.Issuer(), in.Sector(), body); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 4 {
		t.Fatalf("ops calls = %d, want 4 (MAC and CTR each for derive and lookup)", len(seen))
	}
	for i, got := range seen {
		if got.Value(ctxKey{}) != "request" {
			t.Errorf("call %d didn't get the caller's context", i)
		}
	}
}

func TestNewReversibleWithRefusesNilOps(t *testing.T) {
	if _, err := pairwise.NewReversibleWith(nil); err == nil {
		t.Error("NewReversibleWith(nil) succeeded, want an error")
	}
}

// TestNewReversibleWithDeclaresCustody: opts declare the keys' custody,
// as for NewReversible.
func TestNewReversibleWithDeclaresCustody(t *testing.T) {
	ops := newHSMOps(t, testMACKey, testEncKey)
	plain := newReversibleWith(t, ops)
	if got := plain.(keys.KeyCustodyAssurance).KeyCustody(); got != (keys.KeyCustody{}) {
		t.Errorf("undeclared deriver reports custody %+v, want none", got)
	}
	d, err := pairwise.NewReversibleWith(ops, keys.DeclareCustody(keys.KeyCustody{Durable: true, CrossInstanceConsistent: true}))
	if err != nil {
		t.Fatal(err)
	}
	if got := d.KeyCustody(); !got.Durable || !got.CrossInstanceConsistent {
		t.Errorf("declared deriver custody = %+v, want Durable and CrossInstanceConsistent", got)
	}
	if _, ok := any(d).(pairwise.Lookup); !ok {
		t.Error("declared deriver doesn't implement Lookup")
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// sharedBufferOps is a correct ReversibleOps over in-memory keys, except
// that EncryptCTR returns one buffer it reuses across calls, as a pooled
// HSM or KMS client might. onMAC runs once, inside the next MAC call: a
// concurrent request's EncryptCTR landing between a lookup's MAC and its
// parse.
type sharedBufferOps struct {
	macKey []byte
	block  cipher.Block
	buf    []byte
	onMAC  func()
}

func (o *sharedBufferOps) MAC(_ context.Context, data []byte) ([]byte, error) {
	m := hmac.New(sha256.New, o.macKey)
	m.Write(data)
	sum := m.Sum(nil)
	if f := o.onMAC; f != nil {
		o.onMAC = nil
		f()
	}
	return sum, nil
}

func (o *sharedBufferOps) EncryptCTR(_ context.Context, iv, data []byte) ([]byte, error) {
	if cap(o.buf) < len(data) {
		o.buf = make([]byte, len(data))
	}
	out := o.buf[:len(data)]
	cipher.NewCTR(o.block, iv).XORKeyStream(out, data)
	return out, nil
}

// TestReversibleWithCopiesOpsOutput: a lookup parses the plaintext it
// authenticated, even when ops reuses its output buffer and another
// lookup overwrites it in between, so one user's body never resolves to
// another user.
func TestReversibleWithCopiesOpsOutput(t *testing.T) {
	block, err := aes.NewCipher(bytes.Repeat([]byte{3, 4}, 16))
	if err != nil {
		t.Fatal(err)
	}
	ops := &sharedBufferOps{macKey: bytes.Repeat([]byte{1, 2}, 16), block: block}
	d, err := pairwise.NewReversibleWith(ops)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	const issuer, sector = "https://op.example", "rp.example"
	derive := func(subject string) string {
		in, err := pairwise.NewInput(issuer, sector, subject)
		if err != nil {
			t.Fatal(err)
		}
		body, err := d.DerivePairwiseSubject(ctx, in)
		if err != nil {
			t.Fatal(err)
		}
		return body
	}
	alice, bob := derive("alice"), derive("bob")
	lookup, ok := any(d).(pairwise.Lookup)
	if !ok {
		t.Fatal("NewReversibleWith's Deriver doesn't implement Lookup")
	}
	ops.onMAC = func() {
		if _, err := lookup.LookupInternalSubject(ctx, issuer, sector, bob); err != nil {
			t.Fatal(err)
		}
	}
	got, err := lookup.LookupInternalSubject(ctx, issuer, sector, alice)
	if err != nil || got != "alice" {
		t.Fatalf("alice's body resolved to %q, %v; want alice", got, err)
	}
}
