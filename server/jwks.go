package server

import (
	"context"
	"fmt"
	"time"

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

// PublicJWKS returns this server's current public keys: the union (one
// key published for several purposes appears once, and a kid naming
// two different keys is an error) of whatever key manager(s) are active for every
// signing purpose Config/Dependencies declares in use — ID token
// (unless Config.OAuthOnly is set — this server never signs one),
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
	active := make([]keys.SigningKeyUse, 0, 4)
	for _, use := range s.publishedSigningKeys() {
		active = append(active, use.SigningKeyUse)
	}
	return keys.PublicJWKS(ctx, active, nil)
}

// namedSigningKeyUse is a keys.SigningKeyUse with the Dependencies
// field its Manager came from, for New's error messages.
type namedSigningKeyUse struct {
	keys.SigningKeyUse
	field string
}

// publishedSigningKeys lists the signing keys PublicJWKS publishes —
// every purpose Config/Dependencies declares in use; see PublicJWKS.
func (s *Server) publishedSigningKeys() []namedSigningKeyUse {
	var active []namedSigningKeyUse
	if !s.cfg.OAuthOnly {
		active = append(active, namedSigningKeyUse{keys.SigningKeyUse{Manager: s.deps.Keys, Purpose: keys.IDTokenSigning, Algorithm: s.cfg.Algorithms.IDToken}, "keys"})
	}
	if s.cfg.Profile == ProfileFAPISecurityWithMessageSigning {
		active = append(active, namedSigningKeyUse{keys.SigningKeyUse{Manager: s.deps.Keys, Purpose: keys.JARMSigning, Algorithm: s.cfg.Algorithms.JARM}, "keys"})
	}
	if s.cfg.Algorithms.UserInfo != 0 {
		active = append(active, namedSigningKeyUse{keys.SigningKeyUse{Manager: s.deps.Keys, Purpose: keys.UserInfoSigning, Algorithm: s.cfg.Algorithms.UserInfo}, "keys"})
	}
	if publisher, ok := s.deps.AccessTokens.(accessTokenKeyPublisher); ok {
		active = append(active, namedSigningKeyUse{publisher.accessTokenSigningKeyUse(), "access_tokens keys"})
	}
	return active
}

// keyCheckTimeout bounds New's check of the server's signing keys (see
// checkSigningKeys): a KeyManager backed by a remote KMS answers
// PublicKey over the network, and New has no context of its own.
const keyCheckTimeout = 10 * time.Second

// checkSigningKeys resolves, at New, every signing key the server will
// use — each key PublicJWKS publishes, and the federation signing key
// when Config.Federation.EntityID is set — so a KeyManager missing a
// purpose, holding a key that doesn't suit the configured algorithm, or
// reporting an empty kid fails at startup, naming the purpose and
// algorithm, instead of as a server_error at the first token request or
// a failing /jwks. It then builds the whole published JWK Set once, so
// a kid naming two different keys across purposes or managers is
// refused too.
func (s *Server) checkSigningKeys() error {
	ctx, cancel := context.WithTimeout(context.Background(), keyCheckTimeout)
	defer cancel()
	published := s.publishedSigningKeys()
	uses := published
	if s.cfg.Federation.EntityID != "" {
		uses = append(uses[:len(uses):len(uses)], namedSigningKeyUse{keys.SigningKeyUse{Manager: s.deps.Keys, Purpose: keys.FederationEntitySigning, Algorithm: s.cfg.Federation.Algorithm}, "keys"})
	}
	for _, use := range uses {
		if _, err := keys.PublicJWKS(ctx, []keys.SigningKeyUse{use.SigningKeyUse}, nil); err != nil {
			return fmt.Errorf("server: dependencies: %s has no usable %v key for %v: %w", use.field, use.Purpose, use.Algorithm, err)
		}
	}
	if _, err := s.PublicJWKS(ctx); err != nil {
		return fmt.Errorf("server: dependencies: the JWK Set at endpoints.jwks can't be built: %w", err)
	}
	return nil
}
