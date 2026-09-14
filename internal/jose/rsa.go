package jose

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
)

// maxRSAModulusBits caps every RSA key this package accepts, for signing
// or verification alike. RFC 7518 sets no ceiling, but an unbounded one
// invites a trivial resource-exhaustion vector: RSA operations scale
// worse than linearly with modulus size, so a maliciously (or just
// carelessly) oversized key advertised in a JWKS or presented as a
// signer costs this server far more CPU per operation than any
// legitimate key would ever need to. 8192 bits is already twice the
// largest modulus any mainstream CA or HSM issues for TLS/JOSE use
// today, so no real deployment should ever hit this ceiling.
const maxRSAModulusBits = 8192

func pssOptions() *rsa.PSSOptions {
	return &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256}
}

func signRSAPSS(signer crypto.Signer, hash []byte) ([]byte, error) {
	pub, ok := signer.Public().(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("jose: PS256 signer must use an RSA key, got %T", signer.Public())
	}
	if pub.N.BitLen() < 2048 {
		return nil, fmt.Errorf("jose: PS256 requires an RSA key of at least 2048 bits, got %d", pub.N.BitLen())
	}
	if pub.N.BitLen() > maxRSAModulusBits {
		return nil, fmt.Errorf("jose: PS256 requires an RSA key of at most %d bits, got %d", maxRSAModulusBits, pub.N.BitLen())
	}
	sig, err := signer.Sign(rand.Reader, hash, pssOptions())
	if err != nil {
		return nil, fmt.Errorf("jose: rsa-pss sign: %w", err)
	}
	return sig, nil
}

func verifyRSAPSS(pubKey crypto.PublicKey, hash, sig []byte) error {
	pub, ok := pubKey.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("%w: PS256 requires an RSA public key, got %T", ErrInvalidSignature, pubKey)
	}
	if pub.N == nil || pub.N.BitLen() < 2048 {
		return fmt.Errorf("%w: PS256 requires an RSA key of at least 2048 bits", ErrInvalidSignature)
	}
	if pub.N.BitLen() > maxRSAModulusBits {
		return fmt.Errorf("%w: PS256 requires an RSA key of at most %d bits", ErrInvalidSignature, maxRSAModulusBits)
	}
	if err := rsa.VerifyPSS(pub, crypto.SHA256, hash, sig, pssOptions()); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidSignature, err)
	}
	return nil
}
