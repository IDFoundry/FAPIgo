package keys

import (
	"context"
	"crypto/ecdh"
	"fmt"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/jwe"
)

// RecipientKey exposes the registered public key one decryption backend
// currently uses, so FAPIgo can publish the JWKS entry and validate the
// sender's "epk" curve. It never exposes private material — the shared
// base every capability interface below embeds.
type RecipientKey interface {
	PublicKey(ctx context.Context) (PublicKeyInfo, error)
}

// ECDHAgreer delegates only the ECDH key-agreement step of ECDHESA256KW
// key management: given the sender's ephemeral public key, it returns
// the raw shared secret Z. FAPIgo applies the JOSE Concat-KDF (RFC 7518
// Appendix B) and RFC-3394 AES-Unwrap itself — see
// jwe.UnwrapCEKFromSharedSecret — so those spec-precise invariants
// live in one place rather than being reimplemented by every backend.
// This is the primitive an HSM's CKM_ECDH1_DERIVE or AWS KMS's
// DeriveSharedSecret exposes; a backend implements it without ever
// handing its private key to this process. keyID is the JWE header's
// "kid" (see UnwrapRequest.KeyID) — a backend that only ever holds one
// key can ignore it; one holding more than one (e.g. mid-rotation) uses
// it to select which private key to agree with.
type ECDHAgreer interface {
	RecipientKey
	AgreeSharedSecret(ctx context.Context, keyID string, epk *ecdh.PublicKey) (z []byte, err error)
}

// KeyDecrypter delegates the RSAOAEP256 asymmetric key-transport
// decrypt. The returned plaintext *is* the content-encryption key —
// unlike ECDHAgreer, FAPIgo performs no further key-management step,
// since RSA-OAEP's decrypt output is the CEK directly. This is the
// primitive a PKCS#11 CKM_RSA_PKCS_OAEP call or a managed KMS's
// asymmetric decrypt operation (AWS, GCP, Azure all support RSA-OAEP
// non-exportably) exposes. keyID is the JWE header's "kid" — see
// ECDHAgreer.AgreeSharedSecret's doc comment for the same contract.
type KeyDecrypter interface {
	RecipientKey
	DecryptKey(ctx context.Context, keyID string, alg fapi.KeyManagementAlgorithm, wrapped []byte) (cek []byte, err error)
}

// capabilityDecrypter implements Decrypter over one RecipientKey per
// DecryptionPurpose, dispatching UnwrapContentEncryptionKey to whichever
// of ECDHAgreer or KeyDecrypter the request's algorithm requires. See
// NewDecrypter.
type capabilityDecrypter struct {
	backends map[DecryptionPurpose]RecipientKey
}

// NewDecrypter builds a Decrypter from backends, one entry per
// DecryptionPurpose it should serve. Each backend must implement
// ECDHAgreer, KeyDecrypter, or both — whichever key-management
// algorithm(s) it needs to support — so this constructor can fail at
// setup time rather than on the first request. Use NewSingleKeyDecrypter
// for the common case where one backend serves every purpose.
func NewDecrypter(backends map[DecryptionPurpose]RecipientKey) (Decrypter, error) {
	if len(backends) == 0 {
		return nil, fmt.Errorf("keys: NewDecrypter requires at least one backend")
	}
	for purpose, backend := range backends {
		if backend == nil {
			return nil, fmt.Errorf("keys: nil backend for decryption purpose %v", purpose)
		}
		_, agreer := backend.(ECDHAgreer)
		_, decrypter := backend.(KeyDecrypter)
		if !agreer && !decrypter {
			return nil, fmt.Errorf("keys: backend for decryption purpose %v implements neither ECDHAgreer nor KeyDecrypter", purpose)
		}
	}
	return &capabilityDecrypter{backends: backends}, nil
}

// NewSingleKeyDecrypter is NewDecrypter for the common case where one
// backend serves both IDTokenDecryption and UserInfoDecryption — the
// only two DecryptionPurpose values this module defines today.
func NewSingleKeyDecrypter(backend RecipientKey) (Decrypter, error) {
	return NewDecrypter(map[DecryptionPurpose]RecipientKey{
		IDTokenDecryption:  backend,
		UserInfoDecryption: backend,
	})
}

// UnwrapContentEncryptionKey implements Decrypter.
func (d *capabilityDecrypter) UnwrapContentEncryptionKey(ctx context.Context, req UnwrapRequest) ([]byte, error) {
	backend, ok := d.backends[req.Purpose]
	if !ok {
		return nil, fmt.Errorf("keys: no backend configured for decryption purpose %v", req.Purpose)
	}

	switch req.Algorithm {
	case fapi.ECDHESA256KW:
		agreer, ok := backend.(ECDHAgreer)
		if !ok {
			return nil, fmt.Errorf("keys: backend for decryption purpose %v does not support %v", req.Purpose, req.Algorithm)
		}
		if req.EphemeralPublicKey == nil {
			return nil, fmt.Errorf("keys: %v requires an ephemeral public key", req.Algorithm)
		}
		z, err := agreer.AgreeSharedSecret(ctx, req.KeyID, req.EphemeralPublicKey)
		if err != nil {
			return nil, fmt.Errorf("keys: ecdh agreement: %w", err)
		}
		return jwe.UnwrapCEKFromSharedSecret(req.Algorithm, z, req.EncryptedKey)

	case fapi.RSAOAEP256:
		decrypter, ok := backend.(KeyDecrypter)
		if !ok {
			return nil, fmt.Errorf("keys: backend for decryption purpose %v does not support %v", req.Purpose, req.Algorithm)
		}
		return decrypter.DecryptKey(ctx, req.KeyID, req.Algorithm, req.EncryptedKey)

	default:
		return nil, fmt.Errorf("keys: unsupported key management algorithm %v", req.Algorithm)
	}
}

// EncryptionPublicKey implements Decrypter.
func (d *capabilityDecrypter) EncryptionPublicKey(ctx context.Context, purpose DecryptionPurpose, _ fapi.KeyManagementAlgorithm) (PublicKeyInfo, error) {
	backend, ok := d.backends[purpose]
	if !ok {
		return PublicKeyInfo{}, fmt.Errorf("keys: no backend configured for decryption purpose %v", purpose)
	}
	return backend.PublicKey(ctx)
}
