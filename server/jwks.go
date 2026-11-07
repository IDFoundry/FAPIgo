package server

import (
	"context"
	"crypto"
	"fmt"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/jose"
	"github.com/idfoundry/fapigo/keys"
)

// PublicJWK is one published public key, in JWK format (RFC 7517). See
// keys.PublicJWK's own doc comment.
type PublicJWK = keys.PublicJWK

// PublicKeySet is a JWK Set (RFC 7517 §5), suitable for publishing at
// Config.Endpoints.JWKS. A type alias for keys.PublicKeySet — see that
// type's own doc comment for why this package doesn't define its own.
type PublicKeySet = keys.PublicKeySet

// AccessTokenKeyPublisher is implemented by an AccessTokenIssuer of the
// application's own to name the keys its JWT access tokens are signed
// with, so PublicJWKS publishes them (letting a JWT-verifying resource
// server verify those tokens) and RevokeToken recognises a live one, as
// it does JWTAccessTokens'. AccessTokenSigningKeys returns the key
// manager and algorithm the issuer signs with, or a nil key manager when
// it signs no access tokens (an opaque-only issuer), in which case
// nothing is published.
//
// JWTAccessTokens and *JWTAccessTokens don't implement it: the server
// reads their Keys and Algorithm directly. A type embedding
// JWTAccessTokens must implement it, and New refuses one that doesn't,
// whatever Config.Assurance is. The embedded Keys describe what
// JWTAccessTokens.IssueAccessToken signs with, which only the wrapper
// knows to be still true once it overrides IssueAccessToken — it may
// sign with other keys, or issue opaque tokens kept somewhere else
// entirely — so the server never publishes or relies on keys only
// because they were embedded. A wrapper that still signs with the
// embedded keys declares exactly that:
//
//	func (w Wrapper) AccessTokenSigningKeys() (keys.KeyManager, fapi.SignatureAlgorithm) {
//		return w.Keys, w.Algorithm
//	}
//
// Under AssuranceProduction such a wrapper must also implement
// AccessTokenIssuerAssurance; publishing keys is not a declaration of
// what the issuer relies on.
type AccessTokenKeyPublisher interface {
	AccessTokenSigningKeys() (keys.KeyManager, fapi.SignatureAlgorithm)
}

// embeddedJWTAccessTokens is promoted to any type embedding
// JWTAccessTokens or *JWTAccessTokens. It's never used to read the
// embedded keys: New uses it only to refuse a wrapper that hasn't
// declared its own (see AccessTokenKeyPublisher).
type embeddedJWTAccessTokens interface {
	isJWTAccessTokens()
}

// isJWTAccessTokens implements embeddedJWTAccessTokens.
func (JWTAccessTokens) isJWTAccessTokens() {}

// accessTokenSigningKeys returns the keys issuer signs its access tokens
// with: JWTAccessTokens' own, by value or pointer, or what an
// AccessTokenKeyPublisher declares. ok is false for an issuer that signs
// none, or doesn't say: OpaqueAccessTokens, a nil *JWTAccessTokens, an
// issuer that doesn't implement AccessTokenKeyPublisher, or one
// declaring a nil key manager.
func accessTokenSigningKeys(issuer AccessTokenIssuer) (use keys.SigningKeyUse, ok bool) {
	var manager keys.KeyManager
	var algorithm fapi.SignatureAlgorithm
	switch t := issuer.(type) {
	case JWTAccessTokens:
		manager, algorithm = t.Keys, t.Algorithm
	case *JWTAccessTokens:
		if t == nil {
			return keys.SigningKeyUse{}, false
		}
		manager, algorithm = t.Keys, t.Algorithm
	case AccessTokenKeyPublisher:
		manager, algorithm = t.AccessTokenSigningKeys()
	}
	if manager == nil {
		return keys.SigningKeyUse{}, false
	}
	return keys.SigningKeyUse{Manager: manager, Purpose: keys.AccessTokenSigning, Algorithm: algorithm}, true
}

// checkEmbeddedJWTAccessTokens refuses an issuer that embeds
// JWTAccessTokens without implementing AccessTokenKeyPublisher; see
// that interface's doc comment.
func checkEmbeddedJWTAccessTokens(issuer AccessTokenIssuer) error {
	switch issuer.(type) {
	case JWTAccessTokens, *JWTAccessTokens, AccessTokenKeyPublisher:
		return nil
	case embeddedJWTAccessTokens:
		return fmt.Errorf("server: dependencies: access_tokens %T embeds JWTAccessTokens, so it must implement server.AccessTokenKeyPublisher, naming the keys its access tokens are signed with (a nil key manager when it signs none); its embedded keys aren't published or checked on its behalf", issuer)
	}
	return nil
}

// PublicJWKS returns this server's current public keys: the union (one
// key published for several purposes appears once, and a kid naming
// two different keys is an error) of whatever key manager(s) are active for every
// signing purpose Config/Dependencies declares in use — ID token
// (unless Config.OAuthOnly is set — this server never signs one),
// (under ProfileFAPISecurityWithMessageSigning) JARM, and (when
// Config.Algorithms.UserInfo is set) UserInfo signing, all from
// Dependencies.Keys, plus an access-token signing key from
// Dependencies.AccessTokens if it signs its tokens (JWTAccessTokens, or
// an AccessTokenKeyPublisher). Publishing the result at
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
	if use, ok := accessTokenSigningKeys(s.deps.AccessTokens); ok {
		active = append(active, namedSigningKeyUse{use, "access_tokens keys"})
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
// a failing /jwks. Each key also signs a throwaway payload that is
// verified against its public key, so a signer that answers with the
// wrong key or a malformed signature (a misconfigured KMS) fails here
// too. It then builds the whole published JWK Set once, so a kid naming
// two different keys across purposes or managers is refused too.
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
		if err := probeSigningKey(ctx, use.SigningKeyUse); err != nil {
			return fmt.Errorf("server: dependencies: %s can't sign with its %v key for %v: %w", use.field, use.Purpose, use.Algorithm, err)
		}
	}
	if _, err := s.PublicJWKS(ctx); err != nil {
		return fmt.Errorf("server: dependencies: the JWK Set at endpoints.jwks can't be built: %w", err)
	}
	if s.cfg.Federation.EntityID != "" {
		return checkFederationKeyDistinct(ctx, uses[len(published)], published)
	}
	return nil
}

// checkFederationKeyDistinct refuses a federation entity signing key that
// is also one of the server's protocol signing keys. The entity key
// vouches for this server's whole Entity Configuration, its protocol
// keys included; one of those keys reused for it would let anything
// that key signs (an ID token, a JARM response) be presented as a
// statement of the entity itself, which is why Config.Federation says
// it is never reused.
func checkFederationKeyDistinct(ctx context.Context, federation namedSigningKeyUse, published []namedSigningKeyUse) error {
	entityKeys := signingPublicKeys(ctx, federation.SigningKeyUse)
	for _, use := range published {
		for _, protocolKey := range signingPublicKeys(ctx, use.SigningKeyUse) {
			for _, entityKey := range entityKeys {
				if equal, ok := entityKey.(interface{ Equal(crypto.PublicKey) bool }); ok && equal.Equal(protocolKey) {
					return fmt.Errorf("server: dependencies: the %v key is also the %s %v key: a federation entity key is never reused as a protocol key", keys.FederationEntitySigning, use.field, use.Purpose)
				}
			}
		}
	}
	return nil
}

// signingPublicKeys returns every public key use's manager currently
// holds for it: each one a keys.RotatingKeyManager reports, or the one
// PublicKey returns. checkSigningKeys has resolved each use already, so
// a key that can't be read now is simply left out.
func signingPublicKeys(ctx context.Context, use keys.SigningKeyUse) []crypto.PublicKey {
	if rotating, ok := use.Manager.(keys.RotatingKeyManager); ok {
		set, err := rotating.PublicKeys(ctx, use.Purpose, use.Algorithm)
		if err != nil {
			return nil
		}
		out := make([]crypto.PublicKey, 0, len(set.Keys))
		for _, info := range set.Keys {
			out = append(out, info.PublicKey)
		}
		return out
	}
	info, err := use.Manager.PublicKey(ctx, use.Purpose, use.Algorithm)
	if err != nil {
		return nil
	}
	return []crypto.PublicKey{info.PublicKey}
}

// probeSigningKey signs a throwaway payload with use's key, through the
// same path tokens take, and verifies it against the public key the
// manager reports. The result is discarded.
func probeSigningKey(ctx context.Context, use keys.SigningKeyUse) error {
	signer, kid, err := newSignerFromKeys(ctx, use.Manager, use.Purpose, use.Algorithm)
	if err != nil {
		return err
	}
	signed, err := jose.Sign(signer, jose.Header{Algorithm: use.Algorithm, KeyID: kid}, []byte(`{"fapigo_signing_key_check":true}`))
	if err != nil {
		return err
	}
	compact, err := jose.ParseCompact(signed)
	if err != nil {
		return err
	}
	if err := compact.Verify(signer.Public(), use.Algorithm); err != nil {
		return fmt.Errorf("its signature doesn't verify with the public key it reports: %w", err)
	}
	return nil
}
