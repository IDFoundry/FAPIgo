package jose

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"math/big"
	"testing"

	fapi "github.com/idfoundry/fapigo"
)

// TestThumbprintKeyID: a key's thumbprint kid is its RFC 7638 JWK
// thumbprint, base64url without padding — RFC 7638 Appendix A.1's
// worked example — and a key that doesn't fit the algorithm has none.
func TestThumbprintKeyID(t *testing.T) {
	const rfc7638Example = `{"kty":"RSA","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw","e":"AQAB"}`
	jwk, err := ParseJWK([]byte(rfc7638Example), fapi.PS256)
	if err != nil {
		t.Fatalf("ParseJWK: %v", err)
	}
	kid, err := ThumbprintKeyID(jwk.PublicKey(), fapi.PS256)
	if err != nil || kid != "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs" {
		t.Fatalf("ThumbprintKeyID = %q, %v; want RFC 7638's example thumbprint", kid, err)
	}
	if kid, err := ThumbprintKeyID(jwk.PublicKey(), fapi.ES256); err == nil || kid != "" {
		t.Fatalf("ThumbprintKeyID(an RSA key, ES256) = %q, %v; want no kid and an error", kid, err)
	}
}

// TestThumbprintKeyIDRefusesKeysItCannotEncode: a key a caller built by
// hand, rather than parsed or generated, can be empty, off its curve or
// hold a coordinate wider than the curve's size. Thumbprint encodes
// each coordinate at that size, so such a key has no thumbprint kid:
// ThumbprintKeyID reports an error rather than panicking.
func TestThumbprintKeyIDRefusesKeysItCannotEncode(t *testing.T) {
	valid, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wide := new(big.Int).Lsh(big.NewInt(1), 256) // 2^256: 33 octets
	cases := []struct {
		name string
		pub  crypto.PublicKey
		alg  fapi.SignatureAlgorithm
	}{
		{"nil ECDSA key", (*ecdsa.PublicKey)(nil), fapi.ES256},
		{"ECDSA key without coordinates", &ecdsa.PublicKey{Curve: elliptic.P256()}, fapi.ES256},
		{"ECDSA key without y", &ecdsa.PublicKey{Curve: elliptic.P256(), X: valid.X}, fapi.ES256},
		{"x wider than P-256", &ecdsa.PublicKey{Curve: elliptic.P256(), X: wide, Y: valid.Y}, fapi.ES256},
		{"y wider than P-256", &ecdsa.PublicKey{Curve: elliptic.P256(), X: valid.X, Y: wide}, fapi.ES256},
		{"point off the curve", &ecdsa.PublicKey{Curve: elliptic.P256(), X: valid.X, Y: new(big.Int).Add(valid.Y, big.NewInt(1))}, fapi.ES256},
		{"negative x", &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).Neg(valid.X), Y: valid.Y}, fapi.ES256},
		{"nil RSA key", (*rsa.PublicKey)(nil), fapi.PS256},
		{"RSA key without a modulus", &rsa.PublicKey{E: 65537}, fapi.PS256},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if kid, err := ThumbprintKeyID(tc.pub, tc.alg); err == nil || kid != "" {
				t.Fatalf("ThumbprintKeyID = %q, %v; want no kid and an error", kid, err)
			}
			if _, err := NewJWK(tc.pub, tc.alg); err == nil {
				t.Fatal("NewJWK accepted the key; want an error")
			}
		})
	}
	if kid, err := ThumbprintKeyID(&valid.PublicKey, fapi.ES256); err != nil || kid == "" {
		t.Fatalf("ThumbprintKeyID(a generated P-256 key) = %q, %v; want its thumbprint", kid, err)
	}
}

// TestNewEncryptionJWKRefusesEmptyKeys: a nil key of the right type is
// refused, not dereferenced.
func TestNewEncryptionJWKRefusesEmptyKeys(t *testing.T) {
	if _, err := NewEncryptionJWK((*rsa.PublicKey)(nil), fapi.RSAOAEP256); err == nil {
		t.Fatal("NewEncryptionJWK accepted a nil RSA key")
	}
	if _, err := NewEncryptionJWK(&rsa.PublicKey{E: 65537}, fapi.RSAOAEP256); err == nil {
		t.Fatal("NewEncryptionJWK accepted an RSA key without a modulus")
	}
	if _, err := NewEncryptionJWK((*ecdh.PublicKey)(nil), fapi.ECDHESA256KW); err == nil {
		t.Fatal("NewEncryptionJWK accepted a nil ECDH key")
	}
}
