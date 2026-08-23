package jose

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
)

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
	if err := rsa.VerifyPSS(pub, crypto.SHA256, hash, sig, pssOptions()); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidSignature, err)
	}
	return nil
}
