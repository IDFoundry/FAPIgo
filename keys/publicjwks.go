package keys

import (
	"context"
	"fmt"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/jose"
)

// PublicJWK is one published public key, in JWK format (RFC 7517). Its
// only exported surface is KeyID and MarshalJSON — there is no exported
// way to construct one, and no way to extract the private key it
// corresponds to, because there never was one available to whatever
// resolved it: a KeyManager or Decrypter hands back a public key only.
type PublicJWK struct {
	jwk   jose.JWK
	keyID string
}

// KeyID returns the key's "kid".
func (k PublicJWK) KeyID() string { return k.keyID }

// MarshalJSON encodes k as a JWK JSON object.
func (k PublicJWK) MarshalJSON() ([]byte, error) {
	return k.jwk.MarshalJSON()
}

// PublicKeySet is a JWK Set (RFC 7517 §5). client.PublicKeySet and
// server.PublicKeySet are both type aliases of this — a JWK Set's wire
// shape doesn't differ by which role publishes it, unlike the concepts
// this module otherwise keeps deliberately separate per role (see
// ARCHITECTURE.md's "no shared role-level types" rule); building one is
// the actual duplicated logic worth sharing, not something either
// role's own concern.
type PublicKeySet struct {
	Keys []PublicJWK `json:"keys"`
}

// SigningKeyUse names one public signing key to resolve and publish:
// which KeyManager holds it, under which purpose and algorithm.
// Manager is per-use, not one shared across every use, because a
// caller may genuinely hold different purposes in different managers
// — e.g. a server's JWT access-token issuer may own a signing key
// distinct from its ID-token signing key.
type SigningKeyUse struct {
	Manager   KeyManager
	Purpose   SigningPurpose
	Algorithm fapi.SignatureAlgorithm
}

// EncryptionKeyUse names one public encryption key to resolve and
// publish the public half of, mirroring SigningKeyUse for Decrypter.
type EncryptionKeyUse struct {
	Decrypter Decrypter
	Purpose   DecryptionPurpose
	Algorithm fapi.KeyManagementAlgorithm
}

// PublicJWKS resolves every use in signing and encryption into a single
// JWK Set, deduplicated by kid. It has no profile or role logic of its
// own — the caller decides which purposes belong in the set — which is
// what lets client.PublicJWKS and server.PublicJWKS both be thin
// callers over this, and lets any other caller assemble a JWKS from key
// material and a declared algorithm alone, before either role's engine
// exists (e.g. to publish a JWKS at onboarding, ahead of a client_id or
// discovery document).
//
// A SigningKeyUse.Manager implementing RotatingKeyManager has every key
// it reports as currently valid for that purpose published — not just
// the one Sign currently uses — so a signature made just before a key
// rotation's cutover stays verifiable through the rotation's overlap
// window (see RotatingKeyManager's own doc comment). A plain KeyManager
// publishes exactly the one key PublicKey returns, as before.
func PublicJWKS(ctx context.Context, signing []SigningKeyUse, encryption []EncryptionKeyUse) (PublicKeySet, error) {
	seen := make(map[string]bool, len(signing)+len(encryption))
	var result PublicKeySet

	for _, use := range signing {
		if use.Manager == nil {
			return PublicKeySet{}, fmt.Errorf("keys: PublicJWKS: nil KeyManager for signing purpose %v", use.Purpose)
		}
		infos, err := resolveSigningKeys(ctx, use)
		if err != nil {
			return PublicKeySet{}, fmt.Errorf("keys: resolve signing public key: %w", err)
		}
		for _, info := range infos {
			if err := appendPublicJWK(&result, seen, info.KeyID, "key manager returned an empty kid", func() (jose.JWK, error) {
				return jose.NewJWK(info.PublicKey, use.Algorithm)
			}); err != nil {
				return PublicKeySet{}, err
			}
		}
	}

	for _, use := range encryption {
		if use.Decrypter == nil {
			return PublicKeySet{}, fmt.Errorf("keys: PublicJWKS: nil Decrypter for decryption purpose %v", use.Purpose)
		}
		info, err := use.Decrypter.EncryptionPublicKey(ctx, use.Purpose, use.Algorithm)
		if err != nil {
			return PublicKeySet{}, fmt.Errorf("keys: resolve encryption public key: %w", err)
		}
		if err := appendPublicJWK(&result, seen, info.KeyID, "decrypter returned an empty kid", func() (jose.JWK, error) {
			return jose.NewEncryptionJWK(info.PublicKey, use.Algorithm)
		}); err != nil {
			return PublicKeySet{}, err
		}
	}

	return result, nil
}

// appendPublicJWK dedupes by keyID (a no-op, not an error, if already
// seen) then builds and appends the JWK via build — the shared
// "validate kid, dedup, build, append" tail PublicJWKS's signing and
// encryption loops both need, identically apart from which jose
// constructor builds the JWK.
func appendPublicJWK(result *PublicKeySet, seen map[string]bool, keyID string, emptyKidMsg string, build func() (jose.JWK, error)) error {
	if keyID == "" {
		return fmt.Errorf("keys: %s", emptyKidMsg)
	}
	if seen[keyID] {
		return nil
	}
	seen[keyID] = true
	jwk, err := build()
	if err != nil {
		return fmt.Errorf("keys: build jwk: %w", err)
	}
	result.Keys = append(result.Keys, PublicJWK{jwk: jwk.WithKeyID(keyID), keyID: keyID})
	return nil
}

// resolveSigningKeys returns every key currently valid for use: the
// single key PublicKey returns, or, when use.Manager implements
// RotatingKeyManager, every key PublicKeys returns instead.
func resolveSigningKeys(ctx context.Context, use SigningKeyUse) ([]PublicKeyInfo, error) {
	if rotating, ok := use.Manager.(RotatingKeyManager); ok {
		set, err := rotating.PublicKeys(ctx, use.Purpose, use.Algorithm)
		if err != nil {
			return nil, err
		}
		return set.Keys, nil
	}
	info, err := use.Manager.PublicKey(ctx, use.Purpose, use.Algorithm)
	if err != nil {
		return nil, err
	}
	return []PublicKeyInfo{info}, nil
}
