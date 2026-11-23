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
// "kid", or every key answering to the "kid" it names (see
// clientKeyCandidates and verificationKeyCandidates). A rotation without
// distinct kids — the old and new key both published until clients
// switch — needs more than one; a key set listing many keys for one
// algorithm costs a signature verification each, so the rest are never
// tried. An authorization server's keys are tried the same way, up to a
// bound of their own: at most eight by package client, and at most
// MaxKeyCandidates by resource.JWTAccessTokens.
const maxKeyCandidates = 8

// resolveClientKeys returns the verification keys matching kid/alg
// from whatever ClientKeys returns for the client (see
// clientKeyCandidates).
func (s *Server) resolveClientKeys(ctx context.Context, id fapi.ClientID, purpose keys.VerificationPurpose, alg fapi.SignatureAlgorithm, kid string) ([]crypto.PublicKey, error) {
	set, err := s.deps.ClientKeys.ResolveVerificationKeys(ctx, keys.ClientKeyRequest{
		ClientID: id, Purpose: purpose, Algorithm: alg, KeyID: kid,
	})
	if err != nil {
		return nil, err
	}
	return clientKeyCandidates(set, alg, kid)
}

// verificationKeyCandidates returns the keys in set with algorithm alg
// and, when kid is set, that key ID exactly, in set's order — at most
// maxKeyCandidates of them. It fails when there are none. An attester's
// keys are matched this way: unlike a client's (clientKeyCandidates), a
// key registered without a kid matches no request that names one.
func verificationKeyCandidates(set keys.VerificationKeySet, alg fapi.SignatureAlgorithm, kid string) ([]crypto.PublicKey, error) {
	return keyCandidates(set, alg, kid, hasKeyID)
}

// clientKeyCandidates is verificationKeyCandidates for a client's own
// keys, with the rule keys.VerificationKey.KeyID sets out: a key given
// without a kid also answers to a kid that is its RFC 7638 thumbprint,
// the kid keys.NewKeyManagerFromSigners derives for such a key. A
// client's keys are its own (keys.ClientKeySource), so the rule never
// lets one client's key stand for another's.
func clientKeyCandidates(set keys.VerificationKeySet, alg fapi.SignatureAlgorithm, kid string) ([]crypto.PublicKey, error) {
	return keyCandidates(set, alg, kid, answersToKeyID)
}

// keyCandidates returns the keys in set with algorithm alg and, when
// kid is set, that matches reports answer to it, in set's order — at
// most maxKeyCandidates of them. It fails when there are none.
func keyCandidates(set keys.VerificationKeySet, alg fapi.SignatureAlgorithm, kid string, matches func(keys.VerificationKey, string) bool) ([]crypto.PublicKey, error) {
	var candidates []crypto.PublicKey
	for _, k := range set.Keys {
		if k.Algorithm != alg {
			continue
		}
		if kid != "" && !matches(k, kid) {
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

// hasKeyID reports whether k's KeyID is kid.
func hasKeyID(k keys.VerificationKey, kid string) bool { return k.KeyID == kid }

// answersToKeyID reports whether k, a client's key, answers to kid: its
// KeyID is kid, or it has none and kid is its RFC 7638 thumbprint,
// computed as keys.NewKeyManagerFromSigners computes it. A key whose
// thumbprint can't be computed answers to no kid.
func answersToKeyID(k keys.VerificationKey, kid string) bool {
	if k.KeyID != "" {
		return k.KeyID == kid
	}
	thumbprint, err := jose.ThumbprintKeyID(k.PublicKey, k.Algorithm)
	return err == nil && thumbprint == kid
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
