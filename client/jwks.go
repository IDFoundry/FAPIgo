package client

import (
	"context"

	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/storage"
)

// PublicJWK is one of this client's public keys, in JWK format (RFC
// 7517). See keys.PublicJWK's own doc comment.
type PublicJWK = keys.PublicJWK

// PublicKeySet is a JWK Set (RFC 7517 §5) of this client's own public
// keys. This module has no dynamic client registration flow of its
// own, so publishing the result — at whatever jwks_uri (or static jwks
// value) was registered with the authorization server out of band —
// stays this integrator's own concern, the same way server.PublicJWKS's
// result is never itself served by that package either. A type alias
// for keys.PublicKeySet — see that type's own doc comment for why this
// package doesn't define its own.
type PublicKeySet = keys.PublicKeySet

// PublicJWKS returns this client's current public keys: its
// ClientAuthentication signing key (only under
// storage.ClientAuthMethodPrivateKeyJWT — the two RFC 8705 mTLS client
// authentication methods have no assertion-signing key to publish at
// all), its RequestObjectSigning key (only under
// ProfileFAPISecurityWithMessageSigning), and its
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
// overlap window, the same as server.PublicJWKS already does. See
// keys.PublicJWKS for the shared implementation.
func (c *Client) PublicJWKS(ctx context.Context) (PublicKeySet, error) {
	var signing []keys.SigningKeyUse
	if c.cfg.ClientAuthMethod == storage.ClientAuthMethodPrivateKeyJWT {
		signing = append(signing, keys.SigningKeyUse{Manager: c.deps.Keys, Purpose: keys.ClientAuthentication, Algorithm: c.cfg.Algorithms.ClientAuthentication})
	}
	if c.cfg.Profile == ProfileFAPISecurityWithMessageSigning {
		signing = append(signing, keys.SigningKeyUse{Manager: c.deps.Keys, Purpose: keys.RequestObjectSigning, Algorithm: c.cfg.Algorithms.RequestObject})
	}

	var encryption []keys.EncryptionKeyUse
	if c.cfg.Algorithms.IDTokenKeyManagement != 0 {
		encryption = append(encryption, keys.EncryptionKeyUse{
			Decrypter: c.deps.Decryption, Purpose: keys.IDTokenDecryption, Algorithm: c.cfg.Algorithms.IDTokenKeyManagement,
		})
	}
	if c.cfg.Algorithms.UserInfoKeyManagement != 0 {
		encryption = append(encryption, keys.EncryptionKeyUse{
			Decrypter: c.deps.Decryption, Purpose: keys.UserInfoDecryption, Algorithm: c.cfg.Algorithms.UserInfoKeyManagement,
		})
	}

	return keys.PublicJWKS(ctx, signing, encryption)
}
