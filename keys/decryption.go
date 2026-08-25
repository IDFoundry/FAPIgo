package keys

import (
	"context"
	"crypto/ecdh"

	fapi "github.com/idfoundry/fapigo"
)

// DecryptionPurpose is a closed set of reasons a party might need to
// decrypt something with its own key, mirroring SigningPurpose's own
// per-use-case key selection but for the decryption side: a client
// receiving an encrypted (or encrypted-then-signed) ID token needs to
// recover the content-encryption key an authorization server wrapped to
// its public key, without this module — or its caller — ever holding
// the corresponding private key.
type DecryptionPurpose uint8

const (
	_ DecryptionPurpose = iota

	// IDTokenDecryption unwraps the content-encryption key of an
	// encrypted ID token (OIDC Core §10.2).
	IDTokenDecryption

	// UserInfoDecryption unwraps the content-encryption key of a
	// signed-then-encrypted UserInfo response (OIDC Core §5.3.2).
	UserInfoDecryption
)

// UnwrapRequest describes one content-encryption key to recover.
// EncryptedKey, EphemeralPublicKey, and KeyID come from the unverified
// header of the JWE being opened — safe to use only as inputs to the
// unwrap operation itself, never as something to trust ahead of it.
type UnwrapRequest struct {
	Purpose   DecryptionPurpose
	Algorithm fapi.KeyManagementAlgorithm

	// KeyID is the JWE header's "kid", or "" if the header didn't carry
	// one. An implementation holding more than one registered key for
	// Purpose — e.g. mid-rotation, an outgoing key kept alongside an
	// incoming one — uses it to select which key to attempt; an
	// implementation with exactly one key can ignore it. Like every
	// other header value it's a routing hint only, never proof by
	// itself of which key produced this ciphertext — only a successful
	// unwrap confirms that.
	KeyID string

	// EncryptedKey is the JWE's "encrypted_key" — the wire-format
	// wrapped content-encryption key.
	EncryptedKey []byte

	// EphemeralPublicKey is the JWE header's "epk", required for
	// ECDHESA256KW and nil for RSAOAEP256.
	EphemeralPublicKey *ecdh.PublicKey
}

// Decrypter performs the client's own content-encryption-key recovery.
// Like KeyManager, it never returns a private key — only the unwrapped
// CEK bytes and the corresponding public key — so an HSM- or remote-
// signing-service-backed implementation never has to hand private key
// material into this process. It is a separate interface from
// KeyManager, not an addition to it, so an embedder that never needs
// encrypted ID token support isn't forced to implement a method it will
// never call.
type Decrypter interface {
	// UnwrapContentEncryptionKey recovers the content-encryption key
	// req describes, using the key currently designated for req.Purpose
	// and req.Algorithm.
	UnwrapContentEncryptionKey(ctx context.Context, req UnwrapRequest) ([]byte, error)

	// EncryptionPublicKey returns the public key (and its kid) currently
	// designated for purpose and algorithm — *rsa.PublicKey for
	// RSAOAEP256, *ecdh.PublicKey for ECDHESA256KW — so an embedder can
	// register it with an authorization server out of band (this module
	// has no dynamic client registration flow of its own) without ever
	// holding the private key itself.
	EncryptionPublicKey(ctx context.Context, purpose DecryptionPurpose, algorithm fapi.KeyManagementAlgorithm) (PublicKeyInfo, error)
}
