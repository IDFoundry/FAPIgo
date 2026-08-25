package keys

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"

	fapi "github.com/idfoundry/fapigo"
)

// minRSAModulusBits mirrors the same RSAOAEP256 floor internal/jwe
// enforces (2048 bits). A KMS- or HSM-backed KeyDecrypter can't be
// checked this way — it never hands over the key to measure — but an
// in-memory backend holds the key it's validating, so it can and should
// fail at construction rather than at first use.
const minRSAModulusBits = 2048

// inMemoryECDH is an ECDHAgreer backed by a raw *ecdh.PrivateKey held in
// process — for a deployment that loads its decryption key from a
// secrets manager rather than an HSM/KMS, or a test fixture built
// against a known, fixed key. See keys/ephemeral for a decrypter that
// generates its own key instead of taking one; that package is
// development/testing only for exactly the reason this one exists —
// production and fixture-replay tests alike need to decrypt artifacts
// wrapped to a specific, pre-registered key, not a fresh one.
type inMemoryECDH struct {
	priv *ecdh.PrivateKey
	kid  string
}

// NewInMemoryECDH returns an ECDHAgreer over priv, which must be a
// P-256 key — the only curve ECDHESA256KW supports today. kid, if
// non-empty, is reported as the key's PublicKeyInfo.KeyID.
func NewInMemoryECDH(priv *ecdh.PrivateKey, kid string) (ECDHAgreer, error) {
	if priv == nil {
		return nil, fmt.Errorf("keys: NewInMemoryECDH requires a non-nil private key")
	}
	if priv.Curve() != ecdh.P256() {
		return nil, fmt.Errorf("keys: NewInMemoryECDH requires a P-256 key, got curve %v", priv.Curve())
	}
	return &inMemoryECDH{priv: priv, kid: kid}, nil
}

// PublicKey implements RecipientKey.
func (k *inMemoryECDH) PublicKey(_ context.Context) (PublicKeyInfo, error) {
	return PublicKeyInfo{KeyID: k.kid, PublicKey: k.priv.PublicKey()}, nil
}

// AgreeSharedSecret implements ECDHAgreer.
func (k *inMemoryECDH) AgreeSharedSecret(_ context.Context, epk *ecdh.PublicKey) ([]byte, error) {
	if epk == nil {
		return nil, fmt.Errorf("keys: AgreeSharedSecret requires a non-nil ephemeral public key")
	}
	return k.priv.ECDH(epk)
}

// inMemoryRSA is a KeyDecrypter backed by a raw *rsa.PrivateKey held in
// process. See inMemoryECDH's doc comment for when this is (and isn't)
// the right choice over an HSM/KMS-backed KeyDecrypter.
type inMemoryRSA struct {
	priv *rsa.PrivateKey
	kid  string
}

// NewInMemoryRSA returns a KeyDecrypter over priv, which must be at
// least 2048 bits — the same floor RSAOAEP256 enforces everywhere else
// in this module. kid, if non-empty, is reported as the key's
// PublicKeyInfo.KeyID.
func NewInMemoryRSA(priv *rsa.PrivateKey, kid string) (KeyDecrypter, error) {
	if priv == nil {
		return nil, fmt.Errorf("keys: NewInMemoryRSA requires a non-nil private key")
	}
	if priv.N == nil || priv.N.BitLen() < minRSAModulusBits {
		return nil, fmt.Errorf("keys: NewInMemoryRSA requires an RSA key of at least %d bits", minRSAModulusBits)
	}
	return &inMemoryRSA{priv: priv, kid: kid}, nil
}

// PublicKey implements RecipientKey.
func (k *inMemoryRSA) PublicKey(_ context.Context) (PublicKeyInfo, error) {
	return PublicKeyInfo{KeyID: k.kid, PublicKey: &k.priv.PublicKey}, nil
}

// DecryptKey implements KeyDecrypter.
func (k *inMemoryRSA) DecryptKey(_ context.Context, alg fapi.KeyManagementAlgorithm, wrapped []byte) ([]byte, error) {
	if alg != fapi.RSAOAEP256 {
		return nil, fmt.Errorf("keys: inMemoryRSA only supports RSAOAEP256, got %v", alg)
	}
	cek, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, k.priv, wrapped, nil)
	if err != nil {
		return nil, fmt.Errorf("keys: rsa-oaep-256 decrypt: %w", err)
	}
	return cek, nil
}
