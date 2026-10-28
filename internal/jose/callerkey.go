package jose

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"

	fapi "github.com/idfoundry/fapigo"
)

// ValidateCallerVerificationKey checks pub, a key a caller (a client)
// supplied as a crypto.PublicKey rather than as a JWK, against the same
// rules ParseJWK applies to one it parses: the key type, curve and size
// alg requires, an RSA modulus of at most 4096 bits
// (maxCallerRSAModulusBits) and exponent 65537, and an ECDSA point on
// its curve.
func ValidateCallerVerificationKey(pub crypto.PublicKey, alg fapi.SignatureAlgorithm) error {
	if err := checkCallerKeyMaterial(pub); err != nil {
		return err
	}
	return validateKeyForAlgorithm(pub, alg)
}

// ValidateCallerEncryptionKey is ValidateCallerVerificationKey for a
// key to encrypt to, with the rules ParseEncryptionJWKSet applies.
func ValidateCallerEncryptionKey(pub crypto.PublicKey, alg fapi.KeyManagementAlgorithm) error {
	if err := checkCallerKeyMaterial(pub); err != nil {
		return err
	}
	return validateKeyForKeyManagementAlgorithm(pub, alg)
}

// checkCallerKeyMaterial applies the checks parsing a JWK applies
// before the algorithm-specific ones: the caller RSA modulus ceiling,
// the one accepted RSA exponent, and an ECDSA point on its curve (an
// *ecdh.PublicKey is validated when it is constructed).
func checkCallerKeyMaterial(pub crypto.PublicKey) error {
	switch key := pub.(type) {
	case *rsa.PublicKey:
		if key == nil || key.N == nil {
			return fmt.Errorf("jose: rsa public key is empty")
		}
		if err := checkRSAModulusCeiling(key, maxCallerRSAModulusBits); err != nil {
			return err
		}
		if key.E != rsaPublicExponent {
			return fmt.Errorf("%w: only %d is accepted", ErrUnsupportedRSAExponent, rsaPublicExponent)
		}
	case *ecdsa.PublicKey:
		if key == nil || key.Curve == nil || key.X == nil || key.Y == nil {
			return fmt.Errorf("jose: ecdsa public key is empty")
		}
		if _, err := key.ECDH(); err != nil {
			return fmt.Errorf("jose: ecdsa public key: %w", err)
		}
	}
	return nil
}
