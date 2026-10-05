package jose

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
)

// signEdDSA signs message (the raw JWS Signing Input, never a digest of
// it — RFC 8037 §3.1 requires pure EdDSA) and returns the signature
// exactly as crypto/ed25519 produces it: unlike ECDSA, no DER decoding
// or fixed-width re-encoding is needed, since Ed25519's 64-byte
// signature is already the wire format RFC 8037 requires.
func signEdDSA(signer crypto.Signer, message []byte) ([]byte, error) {
	pub, ok := signer.Public().(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("jose: EdDSA signer must use an Ed25519 key, got %T", signer.Public())
	}
	if len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("jose: EdDSA requires a %d-byte Ed25519 public key, got %d", ed25519.PublicKeySize, len(pub))
	}
	// crypto.Hash(0) tells an ed25519.PrivateKey (and any conforming
	// crypto.Signer) that message is the actual signing input, not a
	// digest — passing a real hash algorithm here would make Go's
	// stdlib implementation return an error, since Ed25519 always signs
	// the message itself.
	sig, err := signer.Sign(rand.Reader, message, crypto.Hash(0))
	if err != nil {
		return nil, fmt.Errorf("jose: eddsa sign: %w", err)
	}
	return sig, nil
}

func verifyEdDSA(pubKey crypto.PublicKey, message, sig []byte) error {
	pub, ok := pubKey.(ed25519.PublicKey)
	if !ok {
		return fmt.Errorf("%w: EdDSA requires an Ed25519 public key, got %T", ErrInvalidSignature, pubKey)
	}
	if err := checkEd25519PublicKey(pub); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidSignature, err)
	}
	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("%w: malformed EdDSA signature length %d", ErrInvalidSignature, len(sig))
	}
	if !ed25519.Verify(pub, message, sig) {
		return ErrInvalidSignature
	}
	return nil
}

// ed25519P is the field prime 2^255 - 19.
var ed25519P = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))

// ed25519SmallOrderY holds the y-coordinates of the eight points of
// small order (the torsion subgroup: the identity, one point of order
// 2, two of order 4 and four of order 8). An encoding is y with x's
// sign in the top bit, so blocking these y values blocks all eight
// whatever that bit says.
var ed25519SmallOrderY = func() []*big.Int {
	order8 := leInt("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05")
	return []*big.Int{
		big.NewInt(0), // order 4
		big.NewInt(1), // the identity
		new(big.Int).Sub(ed25519P, big.NewInt(1)), // order 2
		order8,                             // order 8
		new(big.Int).Sub(ed25519P, order8), // order 8
	}
}()

// checkEd25519PublicKey refuses an Ed25519 public key that isn't a
// canonical encoding (y must be below the field prime) or is a point
// of small order. crypto/ed25519 accepts both: for the identity point,
// for one, the signature R = identity, s = 0 verifies over every
// message, so anyone can produce a "proof of possession" for it.
func checkEd25519PublicKey(pub []byte) error {
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("EdDSA requires a %d-byte Ed25519 public key, got %d", ed25519.PublicKeySize, len(pub))
	}
	le := make([]byte, len(pub))
	copy(le, pub)
	le[len(le)-1] &= 0x7f // drop x's sign bit
	y := new(big.Int).SetBytes(reverse(le))
	if y.Cmp(ed25519P) >= 0 {
		return fmt.Errorf("Ed25519 public key is not a canonical encoding")
	}
	for _, small := range ed25519SmallOrderY {
		if y.Cmp(small) == 0 {
			return fmt.Errorf("Ed25519 public key is a point of small order")
		}
	}
	return nil
}

func leInt(h string) *big.Int {
	b, err := hex.DecodeString(h)
	if err != nil {
		panic(err)
	}
	return new(big.Int).SetBytes(reverse(b))
}

func reverse(b []byte) []byte {
	out := make([]byte, len(b))
	for i, v := range b {
		out[len(b)-1-i] = v
	}
	return out
}
