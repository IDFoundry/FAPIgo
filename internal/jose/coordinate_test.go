package jose

import (
	"bytes"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"testing"

	fapi "github.com/idfoundry/fapigo"
)

// p256Point is the P-256 public key of the private scalar d, as its
// coordinates at full length. The scalars these tests use are fixed so
// that one coordinate is below 2^248: 379's x and 43's y, whose minimal
// encodings are 31 octets naming a real point.
func p256Point(t *testing.T, d int64) (x, y []byte) {
	t.Helper()
	scalar := make([]byte, 32)
	big.NewInt(d).FillBytes(scalar)
	priv, err := ecdh.P256().NewPrivateKey(scalar)
	if err != nil {
		t.Fatalf("NewPrivateKey(%d): %v", d, err)
	}
	raw := priv.PublicKey().Bytes() // 0x04 || x || y
	return raw[1:33], raw[33:]
}

// withLeadingZeros is b after n zero octets.
func withLeadingZeros(n int, b []byte) []byte {
	return append(make([]byte, n), b...)
}

// TestECCoordinatesMustBeFullLength covers RFC 7518 §6.2.1.2 and
// §6.2.1.3: an EC JWK's "x" and "y" are each the full size of a
// coordinate on its curve, leading zero octets included. Every way this
// package parses an EC JWK refuses, or in a JWK Set skips, a coordinate
// of another length, though it encodes a point on the curve, and
// accepts that point written at full length. P-256 is the one EC curve
// this package accepts.
func TestECCoordinatesMustBeFullLength(t *testing.T) {
	shortX, otherY := p256Point(t, 379)
	otherX, shortY := p256Point(t, 43)
	if shortX[0] != 0 || shortY[0] != 0 {
		t.Fatalf("premise: x = %x and y = %x should each start with a zero octet", shortX, shortY)
	}
	for name, tc := range map[string]struct {
		x, y []byte
		ok   bool
	}{
		"full length, x below 2^248": {shortX, otherY, true},
		"full length, y below 2^248": {otherX, shortY, true},
		"31-octet x":                 {shortX[1:], otherY, false},
		"31-octet y":                 {otherX, shortY[1:], false},
		"33-octet x":                 {withLeadingZeros(1, shortX), otherY, false},
		"33-octet y":                 {otherX, withLeadingZeros(1, shortY), false},
		"37-octet x":                 {withLeadingZeros(5, shortX), otherY, false},
		"37-octet y":                 {otherX, withLeadingZeros(5, shortY), false},
	} {
		t.Run(name, func(t *testing.T) { checkECJWKParsers(t, tc.x, tc.y, tc.ok) })
	}
}

// checkECJWKParsers parses a P-256 JWK with coordinates x and y through
// ParseJWK, a JWS header's "jwk" and each JWK Set parser, wanting every
// one to accept it if ok, and otherwise to refuse it with
// ErrCoordinateLength or skip it.
func checkECJWKParsers(t *testing.T, x, y []byte, ok bool) {
	t.Helper()
	enc := base64.RawURLEncoding.EncodeToString
	members := fmt.Sprintf(`"kty":"EC","crv":"P-256","x":%q,"y":%q`, enc(x), enc(y))
	_, err := ParseJWK([]byte("{"+members+"}"), fapi.ES256)
	checkCoordinateLengthRefusal(t, "ParseJWK", err, ok)
	_, err = parseHeader([]byte(`{"alg":"ES256","jwk":{` + members + `}}`))
	checkCoordinateLengthRefusal(t, "parseHeader", err, ok)

	want := 0
	if ok {
		want = 1
	}
	set := []byte(`{"keys":[{` + members + `}]}`)
	signing, err := ParseJWKSet(set)
	checkKeptEntries(t, "ParseJWKSet", len(signing), err, want)
	trusted, err := ParseTrustedJWKSet(set)
	checkKeptEntries(t, "ParseTrustedJWKSet", len(trusted), err, want)
	encryption, err := ParseEncryptionJWKSet([]byte(`{"keys":[{` + members + `,"use":"enc"}]}`))
	checkKeptEntries(t, "ParseEncryptionJWKSet", len(encryption), err, want)
}

// checkCoordinateLengthRefusal wants err nil if ok, and otherwise
// ErrCoordinateLength.
func checkCoordinateLengthRefusal(t *testing.T, what string, err error, ok bool) {
	t.Helper()
	if (ok && err != nil) || (!ok && !errors.Is(err, ErrCoordinateLength)) {
		t.Errorf("%s = %v, want accepted: %v", what, err, ok)
	}
}

// checkKeptEntries wants a JWK Set parser to succeed and keep want of
// its entries.
func checkKeptEntries(t *testing.T, what string, kept int, err error, want int) {
	t.Helper()
	if err != nil || kept != want {
		t.Errorf("%s kept %d entries, error %v; want %d", what, kept, err, want)
	}
}

// TestOKPCoordinateMustBeFullLength is the same for an Ed25519 "x",
// which RFC 8037 §2 makes the 32-octet public key.
func TestOKPCoordinateMustBeFullLength(t *testing.T) {
	pub, _ := generateEd25519Key(t)
	enc := base64.RawURLEncoding.EncodeToString
	for _, x := range [][]byte{pub[1:], withLeadingZeros(1, pub), withLeadingZeros(5, pub)} {
		data := fmt.Sprintf(`{"kty":"OKP","crv":"Ed25519","x":%q}`, enc(x))
		if _, err := ParseJWK([]byte(data), fapi.EdDSA); err == nil {
			t.Errorf("ParseJWK(%d-octet x) = nil error, want a refusal", len(x))
		}
	}
}

// TestRSALeadingZerosAreReadAsTheInteger: an RSA "n" or "e" with
// leading zero octets, which RFC 7518 §2 asks a producer to drop but
// some keep (a 257-octet modulus), is accepted as the integer it
// encodes. The parsed key is the canonical one: MarshalJSON writes its
// "n" and "e" minimally, as checked member by member, and its
// Thumbprint is the canonical key's, so nothing derived from it
// depends on the spelling received.
func TestRSALeadingZerosAreReadAsTheInteger(t *testing.T) {
	key := &generateRSA(t).PublicKey
	canonical, err := NewJWK(key, fapi.PS256)
	if err != nil {
		t.Fatalf("NewJWK: %v", err)
	}
	wantJSON, wantThumbprint := marshalAndThumbprint(t, canonical)
	enc := base64.RawURLEncoding.EncodeToString
	n := enc(key.N.Bytes())
	for name, ne := range map[string][2]string{
		"257-octet n":       {enc(withLeadingZeros(1, key.N.Bytes())), "AQAB"},
		"e as AAEAAQ":       {n, "AAEAAQ"},
		"e as AAABAAE":      {n, "AAABAAE"},
		"both with zeros":   {enc(withLeadingZeros(2, key.N.Bytes())), "AAABAAE"},
		"canonical control": {n, "AQAB"},
	} {
		data := []byte(fmt.Sprintf(`{"kty":"RSA","n":%q,"e":%q}`, ne[0], ne[1]))
		parsed, err := ParseJWK(data, fapi.PS256)
		if err != nil {
			t.Fatalf("%s: ParseJWK = %v", name, err)
		}
		gotJSON, gotThumbprint := marshalAndThumbprint(t, parsed)
		if !bytes.Equal(gotJSON, wantJSON) || gotThumbprint != wantThumbprint {
			t.Errorf("%s: MarshalJSON = %s, Thumbprint %s; want %s, %s", name, gotJSON, gotThumbprint, wantJSON, wantThumbprint)
		}
		checkMinimalRSAMembers(t, name, n, gotJSON)
		set, err := ParseJWKSet([]byte(`{"keys":[` + string(data) + `]}`))
		if err != nil || len(set) != 1 || !key.Equal(set[0].PublicKey) {
			t.Errorf("%s: ParseJWKSet = %+v, %v; want the canonical key", name, set, err)
		}
	}
}

// checkMinimalRSAMembers wants data, a marshalled RSA JWK, to write "n"
// as n and "e" as AQAB: the minimal encodings RFC 7518 §2 requires of
// its producer, over which other implementations compute a thumbprint.
// Comparing with another MarshalJSON result alone would pass a
// MarshalJSON that wrote every key non-minimally.
func checkMinimalRSAMembers(t *testing.T, what, n string, data []byte) {
	t.Helper()
	var members struct {
		N string `json:"n"`
		E string `json:"e"`
	}
	if err := json.Unmarshal(data, &members); err != nil || members.N != n || members.E != "AQAB" {
		t.Errorf("%s: MarshalJSON = %s (%v); want n %s and e AQAB", what, data, err, n)
	}
}

// marshalAndThumbprint is k's MarshalJSON and Thumbprint.
func marshalAndThumbprint(t *testing.T, k JWK) ([]byte, Thumbprint) {
	t.Helper()
	data, err := k.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}
	thumbprint, err := k.Thumbprint()
	if err != nil {
		t.Fatalf("Thumbprint: %v", err)
	}
	return data, thumbprint
}
