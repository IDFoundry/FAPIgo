package jose

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
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
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: EdDSA requires a %d-byte Ed25519 public key, got %d", ErrInvalidSignature, ed25519.PublicKeySize, len(pub))
	}
	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("%w: malformed EdDSA signature length %d", ErrInvalidSignature, len(sig))
	}
	if !ed25519.Verify(pub, message, sig) {
		return ErrInvalidSignature
	}
	return nil
}
