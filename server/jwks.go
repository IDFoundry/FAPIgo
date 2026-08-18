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

type signingKeyUse struct {
	purpose   keys.SigningPurpose
	algorithm fapi.SignatureAlgorithm
}

// PublicJWKS returns this server's current public keys: the union,
// deduplicated by kid, of whatever Dependencies.Keys currently reports
// for every signing purpose and algorithm Config declares active.
// Publishing the result at Config.Endpoints.JWKS is what lets clients
// verify a JARM response or ID token, and what lets resource servers
// verify an access token.
func (s *Server) PublicJWKS(ctx context.Context) (PublicKeySet, error) {
	active := []signingKeyUse{
		{keys.AccessTokenSigning, s.cfg.Algorithms.AccessToken},
		{keys.IDTokenSigning, s.cfg.Algorithms.IDToken},
	}
	if s.cfg.Profile == ProfileFAPISecurityWithMessageSigning {
		active = append(active, signingKeyUse{keys.JARMSigning, s.cfg.Algorithms.JARM})
	}

	seen := make(map[string]bool, len(active))
	var result PublicKeySet
	for _, use := range active {
		info, err := s.deps.Keys.PublicKey(ctx, use.purpose, use.algorithm)
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
