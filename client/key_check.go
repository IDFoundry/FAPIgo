package client

import (
	"context"
	"fmt"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/jose"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/storage"
)

// keyCheckTimeout bounds New's check of the client's own keys (see
// checkOwnKeys): a KeyManager or Decrypter backed by a remote KMS
// answers over the network, and New has no context of its own.
const keyCheckTimeout = 10 * time.Second

// signingKeyCheck names one signing key New resolves.
type signingKeyCheck struct {
	purpose   keys.SigningPurpose
	algorithm fapi.SignatureAlgorithm
}

// signingKeysNeeded lists the signing keys cfg makes this client use.
func signingKeysNeeded(cfg Config) []signingKeyCheck {
	var needed []signingKeyCheck
	switch cfg.ClientAuthMethod {
	case storage.ClientAuthMethodPrivateKeyJWT:
		needed = append(needed, signingKeyCheck{keys.ClientAuthentication, cfg.Algorithms.ClientAuthentication})
	case storage.ClientAuthMethodAttestation:
		needed = append(needed, signingKeyCheck{keys.ClientAttestationPoPSigning, cfg.Algorithms.ClientAttestationPoP})
	}
	if cfg.SenderConstrain == storage.SenderConstrainDPoP {
		needed = append(needed, signingKeyCheck{keys.DPoPProofSigning, cfg.Algorithms.DPoP})
	}
	if cfg.Profile == ProfileFAPISecurityWithMessageSigning || cfg.PushedRequestEncoding == PushedRequestEncodingRequestObject {
		needed = append(needed, signingKeyCheck{keys.RequestObjectSigning, cfg.Algorithms.RequestObject})
	}
	if !cfg.Endpoints.BackchannelAuthentication.IsZero() {
		needed = append(needed, signingKeyCheck{keys.BackchannelAuthenticationRequestSigning, cfg.Algorithms.BackchannelAuthenticationRequest})
	}
	if cfg.Federation.EntityID != "" {
		needed = append(needed, signingKeyCheck{keys.FederationEntitySigning, cfg.Federation.Algorithm})
	}
	return needed
}

// checkOwnKeys resolves, at New, every key of its own this client will
// use — each signing key cfg calls for from deps.Keys, and the ID token
// and UserInfo decryption keys from deps.Decryption — so a KeyManager
// missing a purpose, or holding a key that doesn't suit the configured
// algorithm, fails at startup, naming the purpose and algorithm, rather
// than at the first request that needs the key. Only the federation key
// must also carry a kid, since it's published in the Entity
// Configuration's JWK Set.
func checkOwnKeys(cfg Config, deps Dependencies) error {
	ctx, cancel := context.WithTimeout(context.Background(), keyCheckTimeout)
	defer cancel()
	if deps.Keys != nil {
		for _, need := range signingKeysNeeded(cfg) {
			if err := checkSigningKey(ctx, deps.Keys, need); err != nil {
				return fmt.Errorf("client: dependencies: keys has no usable %v key for %v: %w", need.purpose, need.algorithm, err)
			}
		}
	}
	if deps.Decryption == nil {
		return nil
	}
	for _, need := range []struct {
		name      string
		purpose   keys.DecryptionPurpose
		algorithm fapi.KeyManagementAlgorithm
	}{
		{"id_token_decryption", keys.IDTokenDecryption, cfg.Algorithms.IDTokenKeyManagement},
		{"userinfo_decryption", keys.UserInfoDecryption, cfg.Algorithms.UserInfoKeyManagement},
	} {
		if need.algorithm == 0 {
			continue
		}
		info, err := deps.Decryption.EncryptionPublicKey(ctx, need.purpose, need.algorithm)
		if err == nil {
			_, err = jose.NewEncryptionJWK(info.PublicKey, need.algorithm)
		}
		if err != nil {
			return fmt.Errorf("client: dependencies: decryption has no usable %s key for %v: %w", need.name, need.algorithm, err)
		}
	}
	return nil
}

// checkSigningKey resolves need's key from manager and checks it suits
// need.algorithm.
func checkSigningKey(ctx context.Context, manager keys.KeyManager, need signingKeyCheck) error {
	if need.purpose == keys.FederationEntitySigning {
		_, err := keys.PublicJWKS(ctx, []keys.SigningKeyUse{{Manager: manager, Purpose: need.purpose, Algorithm: need.algorithm}}, nil)
		return err
	}
	info, err := manager.PublicKey(ctx, need.purpose, need.algorithm)
	if err != nil {
		return err
	}
	_, err = jose.NewJWK(info.PublicKey, need.algorithm)
	return err
}
