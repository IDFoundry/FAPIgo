package jwe

import (
	"context"
	"crypto/ecdh"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"testing"

	fapi "github.com/idfoundry/fapigo"
)

// p256Key is the P-256 private key with scalar d. The scalars these
// tests use are fixed so that one public coordinate is below 2^248:
// 379's x and 43's y, whose minimal encodings are 31 octets naming a
// real point.
func p256Key(t *testing.T, d int64) *ecdh.PrivateKey {
	t.Helper()
	scalar := make([]byte, 32)
	big.NewInt(d).FillBytes(scalar)
	priv, err := ecdh.P256().NewPrivateKey(scalar)
	if err != nil {
		t.Fatalf("NewPrivateKey(%d): %v", d, err)
	}
	return priv
}

// coordinates is priv's public x and y at full length.
func coordinates(priv *ecdh.PrivateKey) (x, y []byte) {
	point := priv.PublicKey().Bytes() // 0x04 || x || y
	return point[1 : 1+p256CoordinateSize], point[1+p256CoordinateSize:]
}

// epkHeader is a protected header whose epk has coordinates x and y.
func epkHeader(x, y []byte) string {
	enc := base64.RawURLEncoding.EncodeToString
	return ecdhHeaderPrefix + epkMember(fmt.Sprintf(`"x":%q,"y":%q`, enc(x), enc(y))) + `}`
}

// TestParseHeaderRefusesEPKCoordinatesNotFullLength covers RFC 7518
// §6.2.1.2 and §6.2.1.3 for an epk, as for any EC JWK: x and y are each
// 32 octets, leading zero octets included. A coordinate of another
// length is refused, though it encodes a point on the curve, where it
// used to be padded, or trimmed of its zeros, into one; so is a pair
// split 33 and 31 octets, whose 64 octets together name the point.
func TestParseHeaderRefusesEPKCoordinatesNotFullLength(t *testing.T) {
	shortX, otherY := coordinates(p256Key(t, 379))
	otherX, shortY := coordinates(p256Key(t, 43))
	if shortX[0] != 0 || shortY[0] != 0 {
		t.Fatalf("premise: x = %x and y = %x should each start with a zero octet", shortX, shortY)
	}
	zeros := func(n int, b []byte) []byte { return append(make([]byte, n), b...) }
	for name, tc := range map[string]struct {
		x, y []byte
		ok   bool
	}{
		"full length, x below 2^248": {shortX, otherY, true},
		"full length, y below 2^248": {otherX, shortY, true},
		"31-octet x":                 {shortX[1:], otherY, false},
		"31-octet y":                 {otherX, shortY[1:], false},
		"33-octet x":                 {zeros(1, shortX), otherY, false},
		"33-octet y":                 {otherX, zeros(1, shortY), false},
		"37-octet x":                 {zeros(5, shortX), otherY, false},
		"37-octet y":                 {otherX, zeros(5, shortY), false},
		"33-octet x, 31-octet y":     {slices.Concat(shortX, otherY[:1]), otherY[1:], false},
		"31-octet x, 33-octet y":     {shortX[:31], slices.Concat(shortX[31:], otherY), false},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseHeader([]byte(epkHeader(tc.x, tc.y))); (err == nil) != tc.ok {
				t.Fatalf("parseHeader = %v, want accepted: %v", err, tc.ok)
			}
		})
	}
}

// TestDecryptRefusesShortEPKCoordinate: a JWE whose epk writes x in 31
// octets, which named the sender's real ephemeral key and so used to
// decrypt, is refused as malformed, while the same JWE with x at full
// length opens.
func TestDecryptRefusesShortEPKCoordinate(t *testing.T) {
	priv, eph := generateECDHKey(t), p256Key(t, 379)
	decrypt := func(trim int) error {
		compact := sealFromEphemeralKey(t, priv.PublicKey(), eph, func(x, y []byte) string {
			return epkHeader(x[trim:], y)
		})
		_, err := Decrypt(context.Background(), DecryptRequest{
			Algorithm: fapi.ECDHESA256KW, Encryption: fapi.A256GCM, RecipientKey: priv, Compact: compact,
		})
		return err
	}
	if err := decrypt(0); err != nil {
		t.Fatalf("Decrypt(32-octet x) = %v, want nil", err)
	}
	if err := decrypt(1); !errors.Is(err, ErrMalformed) {
		t.Fatalf("Decrypt(31-octet x) = %v, want ErrMalformed", err)
	}
}
