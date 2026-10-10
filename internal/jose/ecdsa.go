package jose

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/asn1"
	"fmt"
	"math/big"
)

// p256CoordinateSize is the fixed byte width of an R or S value for
// P-256, per RFC 7518 §3.4 — JWS uses fixed-width concatenation, not the
// ASN.1 DER encoding crypto.Signer implementations return.
const p256CoordinateSize = 32

func signECDSA(signer crypto.Signer, hash []byte) ([]byte, error) {
	pub, ok := signer.Public().(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("jose: ES256 signer must use an ECDSA key, got %T", signer.Public())
	}
	if pub.Curve != elliptic.P256() {
		return nil, fmt.Errorf("jose: ES256 requires curve P-256")
	}

	der, err := signer.Sign(rand.Reader, hash, crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("jose: ecdsa sign: %w", err)
	}
	var parsed struct{ R, S *big.Int }
	rest, err := asn1.Unmarshal(der, &parsed)
	if err != nil {
		return nil, fmt.Errorf("jose: decode ecdsa signature: %w", err)
	}
	// The signer is the embedder's (a KMS, an HSM): refuse what no valid
	// ECDSA signature can be, rather than panic in FillBytes on an
	// oversized value or issue a token whose signature can't verify.
	if len(rest) != 0 {
		return nil, fmt.Errorf("jose: decode ecdsa signature: trailing data")
	}
	n := pub.Curve.Params().N
	for _, v := range [...]*big.Int{parsed.R, parsed.S} {
		if v == nil || v.Sign() <= 0 || v.Cmp(n) >= 0 {
			return nil, fmt.Errorf("jose: ecdsa signer returned a signature value out of range")
		}
	}

	out := make([]byte, 2*p256CoordinateSize)
	parsed.R.FillBytes(out[:p256CoordinateSize])
	parsed.S.FillBytes(out[p256CoordinateSize:])
	return out, nil
}

func verifyECDSA(pubKey crypto.PublicKey, hash, sig []byte) error {
	pub, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("%w: ES256 requires an ECDSA public key, got %T", ErrInvalidSignature, pubKey)
	}
	if pub.Curve != elliptic.P256() {
		return fmt.Errorf("%w: ES256 requires curve P-256", ErrInvalidSignature)
	}
	if len(sig) != 2*p256CoordinateSize {
		return fmt.Errorf("%w: malformed ES256 signature length %d", ErrInvalidSignature, len(sig))
	}
	r := new(big.Int).SetBytes(sig[:p256CoordinateSize])
	s := new(big.Int).SetBytes(sig[p256CoordinateSize:])
	if !ecdsa.Verify(pub, hash, r, s) {
		return ErrInvalidSignature
	}
	return nil
}
