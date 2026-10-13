package pairwise

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/idfoundry/fapigo/internal/sealkeys"
	"github.com/idfoundry/fapigo/keys"
)

// The reversible construction is SIV (Rogaway and Shrimpton, "A
// Provable-Security Treatment of the Key-Wrap Problem", EUROCRYPT 2006):
// deterministic authenticated encryption built from a PRF and a
// counter-mode cipher under two independent keys.
//
//	A    = u32be(len(f)) || f, for f in [reversibleDomain, issuer, sector]
//	P    = byte(len(subject)) || subject || zero padding, ReversiblePlaintextLength bytes
//	IV   = HMAC-SHA-256(macKey, A || P), first 16 bytes
//	C    = AES-256-CTR(encKey, IV, P)
//	body = base64url(IV || C), without padding
//
// The issuer and sector are associated data: they never appear in the
// body, but a body only opens under the issuer and sector it was derived
// for. P is padded to a fixed size so every body has the same length and
// reveals nothing about the internal subject's length. Go's standard
// library has no AES-SIV, and FAPIgo has no third-party dependencies, so
// the composition is assembled here from crypto/hmac, crypto/sha256 and
// crypto/aes; pairwise/testdata/reversible_vectors.json holds vectors
// computed by an independent implementation.

// reversibleDomain separates this construction's inputs from any other
// use of the same keys. It isn't a key version, and never appears in a
// sub.
const reversibleDomain = "fapigo ppid r1"

const (
	// MaxReversibleSubjectLength is the longest internal subject
	// NewReversible's Deriver accepts, in bytes: its plaintext has room
	// for a length byte and this many bytes of subject.
	MaxReversibleSubjectLength = 151

	// ReversiblePlaintextLength is the fixed size of the padded
	// plaintext: a length byte, the internal subject, and zero padding.
	ReversiblePlaintextLength = 1 + MaxReversibleSubjectLength

	// reversibleIVLength is the synthetic IV's length: one AES block.
	reversibleIVLength = aes.BlockSize

	// ReversibleBodyLength is the length of every body NewReversible's
	// Deriver returns: the base64url encoding, without padding, of the
	// 16-byte synthetic IV and the 152-byte ciphertext.
	ReversibleBodyLength = (8*(reversibleIVLength+ReversiblePlaintextLength) + 5) / 6
)

// ErrSubjectTooLong is what NewReversible's Deriver returns for an
// internal subject longer than MaxReversibleSubjectLength, which its
// fixed-size plaintext can't hold.
var ErrSubjectTooLong = fmt.Errorf("pairwise: reversible derivation holds internal subjects of at most %d bytes", MaxReversibleSubjectLength)

// errReversibleOps wraps a ReversibleOps failure: the derivation or
// lookup couldn't be answered, which is never ErrSubjectNotFound.
var errReversibleOps = errors.New("pairwise: reversible key operation failed")

// ReversibleOps are the two keyed operations the reversible construction
// needs, for keys kept outside this process: in an HSM or a KMS that
// never releases them. NewReversibleWith builds the Deriver on them, and
// produces exactly the bodies NewReversible would from the same two
// keys. Both are called once per derivation and once per lookup, with
// the context of the request that needs them.
type ReversibleOps interface {
	// MAC returns HMAC-SHA-256 of data under the MAC key: the full
	// 32-byte output, which the construction truncates itself. PKCS#11:
	// CKM_SHA256_HMAC.
	MAC(ctx context.Context, data []byte) ([]byte, error)

	// EncryptCTR returns data XORed with the AES-256-CTR keystream under
	// the encryption key, starting from iv (16 bytes) as the whole
	// initial counter block, which is incremented as one 128-bit
	// big-endian integer, as Go's cipher.NewCTR does. The result is as
	// long as data. Decryption is the same operation. PKCS#11:
	// CKM_AES_CTR with ulCounterBits = 128.
	//
	// A counter of only the block's last 32 bits (as GCM uses, and some
	// CTR implementations default to) gives different output once those
	// bits carry; the published test vector whose IV ends in 0xfffffffd
	// catches it.
	EncryptCTR(ctx context.Context, iv, data []byte) ([]byte, error)
}

// NewReversible returns the built-in Reversible Deriver, which also
// implements Lookup: the body is the internal subject, encrypted under
// encKey and authenticated under macKey together with the issuer and
// sector, so the OP can map any body it issued back to its end user
// without storing anything. It is deterministic: the same Input always
// gives the same body.
//
// The construction is SIV (Rogaway and Shrimpton, "A Provable-Security
// Treatment of the Key-Wrap Problem", EUROCRYPT 2006): a synthetic IV,
// HMAC-SHA-256 under macKey over the length-prefixed domain, issuer and
// sector followed by the padded plaintext, truncated to 16 bytes, then
// AES-256-CTR under encKey from that IV. Go's standard library has no
// AES-SIV and FAPIgo has no third-party dependencies, so it is assembled
// here from crypto/hmac, crypto/sha256 and crypto/aes; the exact layout
// is documented in this file's source, and
// pairwise/testdata/reversible_vectors.json holds vectors computed by an
// independent implementation. Every body is ReversibleBodyLength
// characters, whatever the internal subject's length.
//
// macKey and encKey must be two different sets of 32 random bytes,
// used for nothing else. A key that is a single byte repeated (all
// zeros, say), or two equal keys, are refused.
//
// Anyone holding both keys can map every pairwise sub this deployment
// has ever issued, at every client, back to its end user: a leak of the
// keys de-anonymises them all at once, and every resource server given
// the keys to resolve subs shares that risk. The keys can't be rotated
// without giving every user a new sub at every pairwise client. Keep
// them, and back them up, like signing keys. Where unlinkability matters
// more than reversibility, use NewHMAC; where no key should be able to
// reverse a sub, use NewMapping.
//
// The keys are used in this process's memory: the construction needs
// raw AES-CTR, which not every KMS offers, and a resource server resolves
// a sub on every request it verifies. Keep them wrapped by a KMS or HSM
// (envelope encryption): store only their ciphertext and have the KMS
// decrypt them once at startup, wherever NewReversible is called.
//
// Internal subjects longer than MaxReversibleSubjectLength bytes are
// refused with ErrSubjectTooLong. opts declare the keys' custody, as
// for NewHMAC: server.AssuranceProduction requires a Durable one (and
// CrossInstanceConsistent for a horizontally scaled deployment).
func NewReversible(macKey, encKey []byte, opts ...keys.CustodyOption) (Deriver, error) {
	if err := sealkeys.Check("pairwise: reversible", [][]byte{macKey, encKey}); err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, fmt.Errorf("pairwise: reversible: %w", err)
	}
	return NewReversibleWith(memoryReversibleOps{macKey: append([]byte(nil), macKey...), block: block}, opts...)
}

// NewReversibleWith returns the reversible Deriver (see NewReversible)
// over ops, for a MAC key and an encryption key that never leave an HSM
// or KMS. For the same two keys it derives exactly the bodies
// NewReversible does, so a deployment can move between them without
// changing any sub. The returned Deriver also implements Lookup.
//
// The keys' service must offer HMAC-SHA-256 and raw AES-256-CTR with a
// caller-supplied IV and a full 128-bit counter: PKCS#11 HSMs
// (CKM_SHA256_HMAC, and CKM_AES_CTR with ulCounterBits 128) and Google
// Cloud KMS (HMAC_SHA256 and AES_256_CTR raw encryption) can; AWS KMS,
// Azure Key Vault Managed HSM and HashiCorp Vault Transit can't (they
// offer no raw AES-CTR). GETTING_STARTED.md's "Keeping the reversible
// keys in an HSM or KMS" has the per-service details, caveats and
// sources. Check an implementation against
// pairwise/testdata/reversible_vectors.json, whose vector with an IV
// ending in 0xfffffffd catches a counter narrower than 128 bits.
//
// The server and every resource server that resolves subs need the same
// pair of keys. Each derivation and each lookup is one MAC call and one
// CTR call; derivation happens once per grant, but with self-contained
// (JWT) access tokens a resource server looks the sub up on every
// request it verifies, so each API call costs two key operations.
// Opaque access tokens avoid that (their record holds the internal
// subject), or an application can put a bounded cache in front of its
// ReversibleOps. Where the keys may be held in memory, NewReversible
// over keys a KMS unwraps once at startup is the simpler choice.
//
// Every value ops returns is checked: a MAC that isn't 32 bytes, or a
// CTR result that isn't as long as its input, fails the call. An error
// from ops (or a wrong-sized result) means the derivation or lookup
// couldn't be answered, never ErrSubjectNotFound. opts declare the keys'
// custody, as for NewReversible.
func NewReversibleWith(ops ReversibleOps, opts ...keys.CustodyOption) (Deriver, error) {
	if ops == nil {
		return nil, errors.New("pairwise: reversible: ops is nil")
	}
	d := reversibleDeriver{ops: ops}
	if custody, declared := custodyFrom(opts); declared {
		return custodyReversibleDeriver{reversibleDeriver: d, custody: custody}, nil
	}
	return d, nil
}

// memoryReversibleOps is NewReversible's ReversibleOps, over keys held
// in this process.
type memoryReversibleOps struct {
	macKey []byte
	block  cipher.Block
}

// MAC implements ReversibleOps.
func (o memoryReversibleOps) MAC(_ context.Context, data []byte) ([]byte, error) {
	mac := hmac.New(sha256.New, o.macKey)
	mac.Write(data)
	return mac.Sum(nil), nil
}

// EncryptCTR implements ReversibleOps.
func (o memoryReversibleOps) EncryptCTR(_ context.Context, iv, data []byte) ([]byte, error) {
	out := make([]byte, len(data))
	cipher.NewCTR(o.block, iv).XORKeyStream(out, data)
	return out, nil
}

// reversibleDeriver is the reversible Deriver without a custody
// declaration.
type reversibleDeriver struct {
	ops ReversibleOps
}

// DerivePairwiseSubject implements Deriver.
func (d reversibleDeriver) DerivePairwiseSubject(ctx context.Context, in Input) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if in.IsZero() {
		return "", errZeroInput
	}
	plaintext, err := reversiblePlaintext(in.subject)
	if err != nil {
		return "", err
	}
	iv, err := d.syntheticIV(ctx, in.issuer, in.sector, plaintext)
	if err != nil {
		return "", err
	}
	ciphertext, err := d.ctr(ctx, iv, plaintext)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(append(iv, ciphertext...)), nil
}

// LookupInternalSubject implements Lookup: it opens body under issuer
// and sector, and returns the internal subject inside. Any body that
// isn't one this Deriver derived under exactly that issuer and sector
// (altered, truncated, from another deployment, or for another sector)
// fails authentication and is ErrSubjectNotFound.
func (d reversibleDeriver) LookupInternalSubject(ctx context.Context, issuer, sector, body string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	// No Input has an issuer or sector this long, so no body was derived
	// under one; refusing it also keeps writeLengthPrefixed's 4-byte
	// lengths exact.
	if len(issuer) > MaxInputLength || len(sector) > MaxInputLength {
		return "", fmt.Errorf("%w: issuer or sector longer than %d bytes", ErrSubjectNotFound, MaxInputLength)
	}
	sealed, ok := decodeReversibleBody(body)
	if !ok {
		return "", fmt.Errorf("%w: not a reversible body", ErrSubjectNotFound)
	}
	iv, ciphertext := sealed[:reversibleIVLength], sealed[reversibleIVLength:]
	plaintext, err := d.ctr(ctx, iv, ciphertext)
	if err != nil {
		return "", err
	}
	// Authenticate before reading anything from the plaintext: the IV is
	// recomputed over the associated data and the decrypted plaintext,
	// and only an exact match (compared in constant time) proves the body
	// was derived by these keys for this issuer and sector.
	expected, err := d.syntheticIV(ctx, issuer, sector, plaintext)
	if err != nil {
		return "", err
	}
	if subtle.ConstantTimeCompare(iv, expected) != 1 {
		return "", fmt.Errorf("%w: the body doesn't authenticate under this issuer and sector", ErrSubjectNotFound)
	}
	subject, ok := parseReversiblePlaintext(plaintext)
	if !ok {
		// Unreachable without the keys: an authentic plaintext was built by
		// reversiblePlaintext. Refused rather than trusted all the same.
		return "", fmt.Errorf("%w: malformed plaintext", ErrSubjectNotFound)
	}
	return subject, nil
}

// syntheticIV is HMAC-SHA-256 under the MAC key over the associated data
// (domain, issuer, sector, each length-prefixed) followed by the
// fixed-size plaintext, truncated to one AES block.
func (d reversibleDeriver) syntheticIV(ctx context.Context, issuer, sector string, plaintext []byte) ([]byte, error) {
	var data bytes.Buffer
	for _, field := range [...]string{reversibleDomain, issuer, sector} {
		writeLengthPrefixed(&data, field)
	}
	data.Write(plaintext)
	sum, err := d.ops.MAC(ctx, data.Bytes())
	if err != nil {
		return nil, fmt.Errorf("%w: MAC: %w", errReversibleOps, err)
	}
	if len(sum) != sha256.Size {
		return nil, fmt.Errorf("%w: MAC returned %d bytes, want %d", errReversibleOps, len(sum), sha256.Size)
	}
	return append([]byte(nil), sum[:reversibleIVLength]...), nil
}

// ctr is src XORed with the AES-256-CTR keystream under the encryption
// key, starting from iv as the initial counter block (the whole block
// incremented as a 128-bit big-endian integer). Encryption and
// decryption are the same operation.
func (d reversibleDeriver) ctr(ctx context.Context, iv, src []byte) ([]byte, error) {
	out, err := d.ops.EncryptCTR(ctx, iv, src)
	if err != nil {
		return nil, fmt.Errorf("%w: AES-CTR: %w", errReversibleOps, err)
	}
	if len(out) != len(src) {
		return nil, fmt.Errorf("%w: AES-CTR returned %d bytes, want %d", errReversibleOps, len(out), len(src))
	}
	return out, nil
}

// reversiblePlaintext lays subject out as the fixed-size plaintext: its
// length in one byte, its bytes, and zero padding.
func reversiblePlaintext(subject string) ([]byte, error) {
	if len(subject) > MaxReversibleSubjectLength {
		return nil, ErrSubjectTooLong
	}
	plaintext := make([]byte, ReversiblePlaintextLength)
	plaintext[0] = byte(len(subject)) // #nosec G115 -- at most MaxReversibleSubjectLength
	copy(plaintext[1:], subject)
	return plaintext, nil
}

// parseReversiblePlaintext reverses reversiblePlaintext, refusing any
// plaintext it couldn't have produced: a length out of range, padding
// that isn't all zero, or a subject NewInput wouldn't accept.
func parseReversiblePlaintext(plaintext []byte) (string, bool) {
	n := int(plaintext[0])
	if n < 1 || n > MaxReversibleSubjectLength {
		return "", false
	}
	for _, b := range plaintext[1+n:] {
		if b != 0 {
			return "", false
		}
	}
	subject := plaintext[1 : 1+n]
	for _, c := range subject {
		if c < 0x20 || c > 0x7e {
			return "", false
		}
	}
	return string(subject), true
}

// decodeReversibleBody decodes body to the synthetic IV and ciphertext,
// accepting only the canonical, unpadded base64url encoding of exactly
// ReversibleBodyLength characters.
func decodeReversibleBody(body string) ([]byte, bool) {
	if len(body) != ReversibleBodyLength {
		return nil, false
	}
	sealed, err := base64.RawURLEncoding.Strict().DecodeString(body)
	if err != nil || len(sealed) != reversibleIVLength+ReversiblePlaintextLength {
		return nil, false
	}
	return sealed, true
}

// custodyReversibleDeriver is a reversibleDeriver whose caller declared
// its keys' custody.
type custodyReversibleDeriver struct {
	reversibleDeriver
	custody keys.KeyCustody
}

// KeyCustody implements keys.KeyCustodyAssurance.
func (d custodyReversibleDeriver) KeyCustody() keys.KeyCustody { return d.custody }
