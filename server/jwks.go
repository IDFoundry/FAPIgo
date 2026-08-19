package server

import (
	"context"
	"fmt"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/jose"
	"github.com/idfoundry/fapigo/keys"
)

// PublicJWK is one published public key, in JWK format (RFC 7517). Its
// only exported surface is KeyID and MarshalJSON — there is no exported
// way to construct one, and no way to extract the private key it
// corresponds to, because there never was one available to this
// package: Dependencies.Keys hands back a public key only.
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

// PublicKeySet is a JWK Set (RFC 7517 §5), suitable for publishing at
// Config.Endpoints.JWKS.
type PublicKeySet struct {
	Keys []PublicJWK `json:"keys"`
}

// signingKeyUse names one public key this server should publish:
// which KeyManager holds it (usually Dependencies.Keys, but
// JWTAccessTokens may own a separate one — see accessTokenKeyPublisher),
// under which purpose and algorithm.
type signingKeyUse struct {
	manager   keys.KeyManager
	purpose   keys.SigningPurpose
	algorithm fapi.SignatureAlgorithm
}

// accessTokenKeyPublisher is implemented by an AccessTokenIssuer that
// has a public verification key worth publishing at
// Config.Endpoints.JWKS — JWTAccessTokens does; OpaqueAccessTokens
// doesn't (an opaque token has no signature, so there's nothing for a
// resource server to verify against a published key).
// PublicJWKS type-asserts Dependencies.AccessTokens against this
// rather than making it part of AccessTokenIssuer itself, so a
// non-JWT issuer never needs a meaningless stub implementation.
type accessTokenKeyPublisher interface {
	accessTokenSigningKeyUse() signingKeyUse
}

// accessTokenSigningKeyUse implements accessTokenKeyPublisher.
func (j JWTAccessTokens) accessTokenSigningKeyUse() signingKeyUse {
	return signingKeyUse{manager: j.Keys, purpose: keys.AccessTokenSigning, algorithm: j.Algorithm}
}

// PublicJWKS returns this server's current public keys: the union,
// deduplicated by kid, of whatever key manager(s) are active for every
// signing purpose Config/Dependencies declares in use — ID token and
// (under ProfileFAPISecurityWithMessageSigning) JARM from
// Dependencies.Keys, plus an access-token signing key from
// Dependencies.AccessTokens if it has one to publish (see
// accessTokenKeyPublisher). Publishing the result at
// Config.Endpoints.JWKS is what lets clients verify a JARM response or
// ID token, and what lets a JWT-verifying resource server verify an
// access token.
func (s *Server) PublicJWKS(ctx context.Context) (PublicKeySet, error) {
	active := []signingKeyUse{
		{manager: s.deps.Keys, purpose: keys.IDTokenSigning, algorithm: s.cfg.Algorithms.IDToken},
	}
	if s.cfg.Profile == ProfileFAPISecurityWithMessageSigning {
		active = append(active, signingKeyUse{manager: s.deps.Keys, purpose: keys.JARMSigning, algorithm: s.cfg.Algorithms.JARM})
	}
	if publisher, ok := s.deps.AccessTokens.(accessTokenKeyPublisher); ok {
		active = append(active, publisher.accessTokenSigningKeyUse())
	}

	seen := make(map[string]bool, len(active))
	var result PublicKeySet
	for _, use := range active {
		info, err := use.manager.PublicKey(ctx, use.purpose, use.algorithm)
		if err != nil {
			return PublicKeySet{}, fmt.Errorf("server: resolve public key: %w", err)
		}
		if info.KeyID == "" {
			return PublicKeySet{}, fmt.Errorf("server: key manager returned an empty kid")
		}
		if seen[info.KeyID] {
			continue
		}
		seen[info.KeyID] = true

		jwk, err := jose.NewJWK(info.PublicKey, use.algorithm)
		if err != nil {
			return PublicKeySet{}, fmt.Errorf("server: build jwk: %w", err)
		}
		result.Keys = append(result.Keys, PublicJWK{jwk: jwk.WithKeyID(info.KeyID), keyID: info.KeyID})
	}
	return result, nil
}
