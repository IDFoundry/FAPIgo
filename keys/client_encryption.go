package keys

import (
	"context"
	"crypto"

	fapi "github.com/idfoundry/fapigo"
)

// ClientEncryptionPurpose is a closed set of reasons a client's
// encryption key might be resolved — the encryption-side counterpart of
// VerificationPurpose. Encrypting something *to* a client is a
// different operation from verifying something *from* it (a different
// algorithm type, a different key), so this is a sibling set, not an
// addition to VerificationPurpose.
type ClientEncryptionPurpose uint8

const (
	_ ClientEncryptionPurpose = iota

	// IDTokenEncryption resolves a key to encrypt an ID token to the
	// client (OIDC Core §2).
	IDTokenEncryption
)

// ClientEncryptionKeyRequest describes which of a client's encryption
// keys is needed.
type ClientEncryptionKeyRequest struct {
	ClientID  fapi.ClientID
	Purpose   ClientEncryptionPurpose
	Algorithm fapi.KeyManagementAlgorithm
	KeyID     string // "" if the client did not pin a specific key
}

// ClientEncryptionKey is one candidate encryption key for a client. It
// deliberately holds a crypto.PublicKey rather than any JOSE-specific
// type, so an external implementation of ClientEncryptionKeySource
// never needs to depend on this module's internal JWK representation —
// the same reasoning VerificationKey already applies.
type ClientEncryptionKey struct {
	KeyID     string
	Algorithm fapi.KeyManagementAlgorithm
	PublicKey crypto.PublicKey
}

// ClientEncryptionKeySet is the set of keys ResolveEncryptionKeys
// returned. Ordinarily this holds exactly one key (selected by KeyID),
// but an implementation may return more than one when a client is
// mid-rotation.
type ClientEncryptionKeySet struct {
	Keys []ClientEncryptionKey
}

// ClientEncryptionKeySource resolves a registered client's encryption
// keys — the encryption-side counterpart of ClientKeySource.
// Implementations should prefer administratively pre-resolved or
// registered keys over a live JWKS fetch in the request-handling path;
// see the package doc comment for the protections a live fetch must
// apply if one is unavoidable.
type ClientEncryptionKeySource interface {
	ResolveEncryptionKeys(ctx context.Context, req ClientEncryptionKeyRequest) (ClientEncryptionKeySet, error)
}
