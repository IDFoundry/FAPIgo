package server

import (
	"context"
	"fmt"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/jwe"
	"github.com/idfoundry/fapigo/keys"
)

// encryptIDToken wraps signedJWT in a JWE (sign-then-encrypt, OIDC Core
// §2/§10.2) for a client that registered for encrypted ID tokens.
// keyManagement/contentEncryption are the client's own registered
// algorithms (storage.RegisteredClient.IDTokenEncryption) — a client's
// own registration is not itself authority to use an algorithm the
// operator hasn't enabled server-wide, the same relationship
// ClientAssertion/RequestObject have with their own allow-lists, so
// both are checked against Config.Algorithms here before anything is
// resolved or encrypted.
func (s *Server) encryptIDToken(ctx context.Context, clientID fapi.ClientID, keyManagement fapi.KeyManagementAlgorithm, contentEncryption fapi.ContentEncryptionAlgorithm, signedJWT string) (string, error) {
	if !s.cfg.Algorithms.IDTokenEncryptionKeyManagement.Contains(keyManagement) {
		return "", fmt.Errorf("server: id token encryption key management algorithm %v is not permitted", keyManagement)
	}
	if !s.cfg.Algorithms.IDTokenEncryptionContentEncryption.Contains(contentEncryption) {
		return "", fmt.Errorf("server: id token encryption content encryption algorithm %v is not permitted", contentEncryption)
	}

	key, err := s.resolveClientEncryptionKey(ctx, clientID, keys.IDTokenEncryption, keyManagement)
	if err != nil {
		return "", fmt.Errorf("resolve client encryption key: %w", err)
	}

	compact, err := jwe.Encrypt(jwe.EncryptRequest{
		Algorithm: keyManagement, Encryption: contentEncryption,
		RecipientKey: key.PublicKey, KeyID: key.KeyID,
		// "JWT" (RFC 7519 §5.2's canonical form) — the nested payload is
		// itself a signed JWT, not the ID token's own claims re-encoded.
		ContentType: "JWT",
		Random:      s.deps.Random, Plaintext: []byte(signedJWT),
	})
	if err != nil {
		return "", fmt.Errorf("encrypt id token: %w", err)
	}
	return compact, nil
}

// resolveClientEncryptionKey resolves clientID's encryption key for
// purpose/alg — the encryption-side counterpart of resolveClientKey
// (par.go). The server never pins a specific kid of its own accord
// (unlike verifying a client-presented assertion/proof, there is no
// incoming header to read one from), so it accepts the first key
// ResolveEncryptionKeys returns for the requested algorithm.
func (s *Server) resolveClientEncryptionKey(ctx context.Context, clientID fapi.ClientID, purpose keys.ClientEncryptionPurpose, alg fapi.KeyManagementAlgorithm) (keys.ClientEncryptionKey, error) {
	set, err := s.deps.ClientEncryptionKeys.ResolveEncryptionKeys(ctx, keys.ClientEncryptionKeyRequest{
		ClientID: clientID, Purpose: purpose, Algorithm: alg,
	})
	if err != nil {
		return keys.ClientEncryptionKey{}, err
	}
	for _, k := range set.Keys {
		if k.Algorithm != alg {
			continue
		}
		return k, nil
	}
	return keys.ClientEncryptionKey{}, fmt.Errorf("no encryption key found for algorithm=%v", alg)
}
