package client

import (
	"context"
	"fmt"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/jose"
	"github.com/idfoundry/fapigo/keys"
)

// PublicJWK is one of this client's public keys, in JWK format (RFC
// 7517). Its only exported surface is KeyID and MarshalJSON — there is
// no exported way to construct one, and no way to extract the private
// key it corresponds to, because there never was one available to this
// package: Dependencies.Keys/Dependencies.Decryption each hand back a
// public key only.
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

// PublicKeySet is a JWK Set (RFC 7517 §5) of this client's own public
// keys. This module has no dynamic client registration flow of its
// own, so publishing the result — at whatever jwks_uri (or static jwks
// value) was registered with the authorization server out of band —
// stays this integrator's own concern, the same way server.PublicJWKS's
// result is never itself served by that package either.
type PublicKeySet struct {
	Keys []PublicJWK `json:"keys"`
}

// signingKeyUse names one signing purpose PublicJWKS should publish.
type signingKeyUse struct {
	purpose   keys.SigningPurpose
	algorithm fapi.SignatureAlgorithm
}

// encryptionKeyUse names one decryption purpose PublicJWKS should
// publish the public (encryption) half of.
type encryptionKeyUse struct {
	purpose   keys.DecryptionPurpose
	algorithm fapi.KeyManagementAlgorithm
}

// PublicJWKS returns this client's current public keys: its
// ClientAuthentication signing key (always — every profile this module
// supports authenticates via private_key_jwt), its RequestObjectSigning
// key (only under ProfileFAPISecurityWithMessageSigning), and its
// IDTokenDecryption/UserInfoDecryption encryption key(s) — whichever of
// Config.Algorithms.IDTokenKeyManagement/UserInfoKeyManagement are set
// — deduplicated by kid. DPoPProofSigning is deliberately excluded: RFC
// 9449 embeds a DPoP proof's public key directly in the proof's own
// "jwk" header, never via a discoverable JWKS, so there is nothing to
// publish for it here.
//
// If Dependencies.Keys implements keys.RotatingKeyManager, every key it
// reports as currently valid for a signing purpose is published — not
// just the one Sign currently uses — so a signature made just before a
// key rotation's cutover stays verifiable through the rotation's
// overlap window, the same as server.PublicJWKS already does.
func (c *Client) PublicJWKS(ctx context.Context) (PublicKeySet, error) {
	signingUses := []signingKeyUse{
		{purpose: keys.ClientAuthentication, algorithm: c.cfg.Algorithms.ClientAuthentication},
	}
	if c.cfg.Profile == ProfileFAPISecurityWithMessageSigning {
		signingUses = append(signingUses, signingKeyUse{purpose: keys.RequestObjectSigning, algorithm: c.cfg.Algorithms.RequestObject})
	}

	var encryptionUses []encryptionKeyUse
	if c.cfg.Algorithms.IDTokenKeyManagement != 0 {
		encryptionUses = append(encryptionUses, encryptionKeyUse{purpose: keys.IDTokenDecryption, algorithm: c.cfg.Algorithms.IDTokenKeyManagement})
	}
	if c.cfg.Algorithms.UserInfoKeyManagement != 0 {
		encryptionUses = append(encryptionUses, encryptionKeyUse{purpose: keys.UserInfoDecryption, algorithm: c.cfg.Algorithms.UserInfoKeyManagement})
	}

	seen := make(map[string]bool, len(signingUses)+len(encryptionUses))
	var result PublicKeySet

	for _, use := range signingUses {
		infos, err := resolveClientSigningKeys(ctx, c.deps.Keys, use)
		if err != nil {
			return PublicKeySet{}, fmt.Errorf("client: resolve signing public key: %w", err)
		}
		for _, info := range infos {
			if info.KeyID == "" {
				return PublicKeySet{}, fmt.Errorf("client: key manager returned an empty kid")
			}
			if seen[info.KeyID] {
				continue
			}
			seen[info.KeyID] = true
			jwk, err := jose.NewJWK(info.PublicKey, use.algorithm)
			if err != nil {
				return PublicKeySet{}, fmt.Errorf("client: build jwk: %w", err)
			}
			result.Keys = append(result.Keys, PublicJWK{jwk: jwk.WithKeyID(info.KeyID), keyID: info.KeyID})
		}
	}

	for _, use := range encryptionUses {
		info, err := c.deps.Decryption.EncryptionPublicKey(ctx, use.purpose, use.algorithm)
		if err != nil {
			return PublicKeySet{}, fmt.Errorf("client: resolve encryption public key: %w", err)
		}
		if info.KeyID == "" {
			return PublicKeySet{}, fmt.Errorf("client: decrypter returned an empty kid")
		}
		if seen[info.KeyID] {
			continue
		}
		seen[info.KeyID] = true
		jwk, err := jose.NewEncryptionJWK(info.PublicKey, use.algorithm)
		if err != nil {
			return PublicKeySet{}, fmt.Errorf("client: build jwk: %w", err)
		}
		result.Keys = append(result.Keys, PublicJWK{jwk: jwk.WithKeyID(info.KeyID), keyID: info.KeyID})
	}

	return result, nil
}

// resolveClientSigningKeys returns every key currently valid for use:
// the single key KeyManager.PublicKey returns, or, when manager
// implements keys.RotatingKeyManager, every key PublicKeys returns
// instead (see PublicJWKS's own doc comment).
func resolveClientSigningKeys(ctx context.Context, manager keys.KeyManager, use signingKeyUse) ([]keys.PublicKeyInfo, error) {
	if rotating, ok := manager.(keys.RotatingKeyManager); ok {
		set, err := rotating.PublicKeys(ctx, use.purpose, use.algorithm)
		if err != nil {
			return nil, err
		}
		return set.Keys, nil
	}
	info, err := manager.PublicKey(ctx, use.purpose, use.algorithm)
	if err != nil {
		return nil, err
	}
	return []keys.PublicKeyInfo{info}, nil
}
