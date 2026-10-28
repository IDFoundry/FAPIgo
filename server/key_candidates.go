package server

import (
	"context"
	"crypto"
	"errors"
	"fmt"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/jose"
	"github.com/idfoundry/fapigo/keys"
)

// maxKeyCandidates bounds how many keys a client- or attester-signed JWT
// is tried against: every key with its algorithm when it names no
// "kid", or every key sharing the "kid" it names. A rotation without
// distinct kids — the old and new key both published until clients
// switch — needs more than one; a key set listing many keys for one
// algorithm costs a signature verification each, so the rest are never
// tried. resource.JWTAccessTokens.MaxKeyCandidates and the client's
// issuer-key lookup try several the same way.
const maxKeyCandidates = 8

// resolveClientKeys returns the verification keys matching kid/alg
// from whatever ClientKeys returns for the client (see
// verificationKeyCandidates).
func (s *Server) resolveClientKeys(ctx context.Context, id fapi.ClientID, purpose keys.VerificationPurpose, alg fapi.SignatureAlgorithm, kid string) ([]crypto.PublicKey, error) {
	set, err := s.deps.ClientKeys.ResolveVerificationKeys(ctx, keys.ClientKeyRequest{
		ClientID: id, Purpose: purpose, Algorithm: alg, KeyID: kid,
	})
	if err != nil {
		return nil, err
	}
	return verificationKeyCandidates(set, alg, kid)
}

// verificationKeyCandidates returns the keys in set with algorithm alg
// and, when kid is set, that key ID, in set's order — at most
// maxKeyCandidates of them. It fails when there are none.
func verificationKeyCandidates(set keys.VerificationKeySet, alg fapi.SignatureAlgorithm, kid string) ([]crypto.PublicKey, error) {
	var candidates []crypto.PublicKey
	for _, k := range set.Keys {
		if kid != "" && k.KeyID != kid {
			continue
		}
		if k.Algorithm != alg {
			continue
		}
		candidates = append(candidates, k.PublicKey)
		if len(candidates) == maxKeyCandidates {
			break
		}
	}
	if len(candidates) == 0 {
		return nil, fmt.Errorf("no verification key found for kid=%q algorithm=%v", kid, alg)
	}
	return candidates, nil
}

// verifyWithCandidates calls verify with each of candidates in turn and
// returns the first result whose failure, if any, isn't the signature's
// (jose.ErrInvalidSignature): once a key has verified the signature,
// another key can't change the verdict on the claims, and the signature
// check comes before any replay record is written, so a key that
// doesn't fit records nothing. When no candidate verifies the
// signature, it returns the last one's error.
func verifyWithCandidates[T any](candidates []crypto.PublicKey, verify func(crypto.PublicKey) (T, error)) (T, error) {
	var (
		result T
		err    = errors.New("no candidate verification key")
	)
	for _, pub := range candidates {
		result, err = verify(pub)
		if !errors.Is(err, jose.ErrInvalidSignature) {
			return result, err
		}
	}
	var zero T
	return zero, err
}
