package server

import (
	"context"

	"github.com/idfoundry/fapigo/keys"
)

// PublicJWK is one published public key, in JWK format (RFC 7517). See
// keys.PublicJWK's own doc comment.
type PublicJWK = keys.PublicJWK

// PublicKeySet is a JWK Set (RFC 7517 §5), suitable for publishing at
// Config.Endpoints.JWKS. A type alias for keys.PublicKeySet — see that
// type's own doc comment for why this package doesn't define its own.
type PublicKeySet = keys.PublicKeySet

// accessTokenKeyPublisher is implemented by an AccessTokenIssuer that
// has a public verification key worth publishing at
// Config.Endpoints.JWKS — JWTAccessTokens does; OpaqueAccessTokens
// doesn't (an opaque token has no signature, so there's nothing for a
// resource server to verify against a published key).
// PublicJWKS type-asserts Dependencies.AccessTokens against this
// rather than making it part of AccessTokenIssuer itself, so a
// non-JWT issuer never needs a meaningless stub implementation.
type accessTokenKeyPublisher interface {
	accessTokenSigningKeyUse() keys.SigningKeyUse
}

// accessTokenSigningKeyUse implements accessTokenKeyPublisher.
func (j JWTAccessTokens) accessTokenSigningKeyUse() keys.SigningKeyUse {
	return keys.SigningKeyUse{Manager: j.Keys, Purpose: keys.AccessTokenSigning, Algorithm: j.Algorithm}
}

// PublicJWKS returns this server's current public keys: the union,
// deduplicated by kid, of whatever key manager(s) are active for every
// signing purpose Config/Dependencies declares in use — ID token,
// (under ProfileFAPISecurityWithMessageSigning) JARM, and (when
// Config.Algorithms.UserInfo is set) UserInfo signing, all from
// Dependencies.Keys, plus an access-token signing key from
// Dependencies.AccessTokens if it has one to publish (see
// accessTokenKeyPublisher). Publishing the result at
// Config.Endpoints.JWKS is what lets clients verify a JARM response,
// ID token or signed UserInfo response, and what lets a JWT-verifying
// resource server verify an access token.
//
// A manager implementing keys.RotatingKeyManager can publish more than
// one key for a purpose — normally still one, but two during a
// rotation's overlap window, so a signature made just before the
// rotation stays verifiable until it expires (see
// keys.RotatingKeyManager's own doc comment). A plain keys.KeyManager
// publishes exactly the one key PublicKey returns, as before. See
// keys.PublicJWKS for the shared implementation.
func (s *Server) PublicJWKS(ctx context.Context) (PublicKeySet, error) {
	active := []keys.SigningKeyUse{
		{Manager: s.deps.Keys, Purpose: keys.IDTokenSigning, Algorithm: s.cfg.Algorithms.IDToken},
	}
	if s.cfg.Profile == ProfileFAPISecurityWithMessageSigning {
		active = append(active, keys.SigningKeyUse{Manager: s.deps.Keys, Purpose: keys.JARMSigning, Algorithm: s.cfg.Algorithms.JARM})
	}
	if s.cfg.Algorithms.UserInfo != 0 {
		active = append(active, keys.SigningKeyUse{Manager: s.deps.Keys, Purpose: keys.UserInfoSigning, Algorithm: s.cfg.Algorithms.UserInfo})
	}
	if publisher, ok := s.deps.AccessTokens.(accessTokenKeyPublisher); ok {
		active = append(active, publisher.accessTokenSigningKeyUse())
	}
	return keys.PublicJWKS(ctx, active, nil)
}
