package pairwise

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
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
// key must be 32 random bytes, used for nothing else. A key that is a
// single byte repeated (all zeros, say) is refused as a placeholder. The
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
	custody, _ := custodyFrom(opts)
	return &HMACDeriver{key: append([]byte(nil), key...), custody: custody}, nil
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

// HMACDeriver is the built-in one-way Deriver NewHMAC returns. It
// doesn't implement Lookup.
type HMACDeriver struct {
	key     []byte
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
	mac := hmac.New(sha256.New, d.key)
	for _, field := range [...]string{hmacDomain, in.issuer, in.sector, in.subject} {
		writeLengthPrefixed(mac, field)
	}
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
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
