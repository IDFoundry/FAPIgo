package pairwise

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/idfoundry/fapigo/internal/sealkeys"
	"github.com/idfoundry/fapigo/keys"
)

// hmacDomain separates this construction's inputs from any other use of
// the same key. It isn't a key version, and never appears in a sub.
const hmacDomain = "fapigo ppid h1"

// HMACBodyLength is the length of every body NewHMAC's Deriver returns:
// an HMAC-SHA-256 output, base64url-encoded without padding.
const HMACBodyLength = 43

// NewHMAC returns the built-in one-way Deriver: HMAC-SHA-256 under key,
// over a domain label and the Input's issuer, sector and internal
// subject, each length-prefixed so no two Inputs share an encoding. The
// body is the 43-character base64url encoding of the 32-byte output.
// Nothing, the OP included, can map a body back to its user: the
// returned HMACDeriver doesn't implement Lookup.
//
// key must be 32 random bytes from crypto/rand, used for nothing else.
// A key that is a single byte repeated (all zeros, say) is refused as a
// placeholder, and one made entirely of printable text as a passphrase
// or a still-encoded key: decode a hex or base64 key first. The
// key can't be rotated without giving every user a new sub at every
// pairwise client, so keep it, and back it up, like a signing key.
//
// opts declare the key's custody, as for keys.NewKeyManagerFromSigners:
// server.AssuranceProduction requires a Durable one (and
// CrossInstanceConsistent for a horizontally scaled deployment), since
// every instance must derive the same sub; without one, KeyCustody
// reports none.
func NewHMAC(key []byte, opts ...keys.CustodyOption) (*HMACDeriver, error) {
	if err := sealkeys.Check("pairwise: HMAC", [][]byte{key}); err != nil {
		return nil, err
	}
	return NewHMACWith(memoryHMACOps{key: append([]byte(nil), key...)}, opts...)
}

// HMACOps is the one keyed operation the one-way construction needs, for
// a key kept outside this process: in an HSM or a KMS that never
// releases it. NewHMACWith builds the Deriver on it, and produces
// exactly the bodies NewHMAC would from the same key.
//
// MAC returns HMAC-SHA-256 of data under the key: the full 32-byte
// output. It is called once per derivation, with the context of the
// request that needs it, and may be called concurrently. It must not
// retain or modify data.
type HMACOps interface {
	MAC(ctx context.Context, data []byte) ([]byte, error)
}

// NewHMACWith returns the one-way Deriver (see NewHMAC) over ops, for a
// key that never leaves an HSM or KMS. For the same key it derives
// exactly the bodies NewHMAC does, so a deployment can move between them
// without changing any sub.
//
// HMAC-SHA-256 is widely offered: PKCS#11 HSMs (CKM_SHA256_HMAC), AWS
// KMS (GenerateMac with HMAC_SHA_256 keys), Google Cloud KMS
// (MacSign with HMAC_SHA256 keys), Azure Key Vault Managed HSM (HS256
// on an oct-HSM key) and HashiCorp Vault Transit (hmac, whose
// "vault:v1:"-prefixed base64 output the implementation decodes).
// GETTING_STARTED.md's "Keeping the one-way key in an HSM or KMS" has
// the details and sources. Check an implementation against
// pairwise/testdata/hmac_vectors.json.
//
// Each derivation is one MAC call; a one-way deriver is never asked to
// look a sub up, so it costs nothing per resource-server request. A MAC
// that isn't 32 bytes, or an error from ops, fails the derivation. opts
// declare the key's custody, as for NewHMAC.
func NewHMACWith(ops HMACOps, opts ...keys.CustodyOption) (*HMACDeriver, error) {
	if ops == nil {
		return nil, errors.New("pairwise: HMAC: ops is nil")
	}
	custody, _ := custodyFrom(opts)
	return &HMACDeriver{ops: ops, custody: custody}, nil
}

// memoryHMACOps is NewHMAC's HMACOps, over a key held in this process.
type memoryHMACOps struct {
	key []byte
}

// MAC implements HMACOps.
func (o memoryHMACOps) MAC(_ context.Context, data []byte) ([]byte, error) {
	mac := hmac.New(sha256.New, o.key)
	mac.Write(data)
	return mac.Sum(nil), nil
}

// custodyFrom applies opts to a KeyCustody, reporting whether any
// (non-nil) option declared one.
func custodyFrom(opts []keys.CustodyOption) (keys.KeyCustody, bool) {
	var custody keys.KeyCustody
	declared := false
	for _, opt := range opts {
		if opt != nil {
			opt(&custody)
			declared = true
		}
	}
	return custody, declared
}

// HMACDeriver is the built-in one-way Deriver NewHMAC and NewHMACWith
// return. It doesn't implement Lookup.
type HMACDeriver struct {
	ops     HMACOps
	custody keys.KeyCustody
}

// DerivePairwiseSubject implements Deriver.
func (d *HMACDeriver) DerivePairwiseSubject(ctx context.Context, in Input) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if in.IsZero() {
		return "", errZeroInput
	}
	var data bytes.Buffer
	for _, field := range [...]string{hmacDomain, in.issuer, in.sector, in.subject} {
		writeLengthPrefixed(&data, field)
	}
	sum, err := d.ops.MAC(ctx, data.Bytes())
	if err != nil {
		return "", fmt.Errorf("pairwise: HMAC key operation failed: %w", err)
	}
	if len(sum) != sha256.Size {
		return "", fmt.Errorf("pairwise: HMAC key operation returned %d bytes, want %d", len(sum), sha256.Size)
	}
	return base64.RawURLEncoding.EncodeToString(sum), nil
}

// KeyCustody implements keys.KeyCustodyAssurance: the custody NewHMAC's
// options declared, or none.
func (d *HMACDeriver) KeyCustody() keys.KeyCustody { return d.custody }

// writeLengthPrefixed writes field to w (a hash, or a buffer that
// can't fail) as its length, a 4-byte big endian integer, followed by
// its bytes.
func writeLengthPrefixed(w io.Writer, field string) {
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(field))) // #nosec G115 -- fields are at most MaxInputLength bytes
	_, _ = w.Write(length[:])
	_, _ = w.Write([]byte(field))
}
