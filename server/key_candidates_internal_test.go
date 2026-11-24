package server

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"math/big"
	"testing"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/jose"
	"github.com/idfoundry/fapigo/keys"
)

func newTestPublicKey(t *testing.T) *ecdsa.PublicKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &key.PublicKey
}

// TestVerificationKeyCandidatesReturnsEveryMatch: mid-rotation, a JWS
// with no "kid" matches both same-algorithm keys, and one whose "kid"
// two keys share matches both, so a JWS signed with the second key can
// still verify.
func TestVerificationKeyCandidatesReturnsEveryMatch(t *testing.T) {
	old, cur := newTestPublicKey(t), newTestPublicKey(t)
	for _, tc := range []struct {
		name string
		set  []keys.VerificationKey
		kid  string
	}{
		{"no kid", []keys.VerificationKey{
			{KeyID: "old", Algorithm: fapi.ES256, PublicKey: old},
			{KeyID: "new", Algorithm: fapi.ES256, PublicKey: cur},
		}, ""},
		{"duplicate kid", []keys.VerificationKey{
			{KeyID: "k", Algorithm: fapi.ES256, PublicKey: old},
			{KeyID: "other", Algorithm: fapi.ES256, PublicKey: newTestPublicKey(t)},
			{KeyID: "k", Algorithm: fapi.ES256, PublicKey: cur},
		}, "k"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := verificationKeyCandidates(keys.VerificationKeySet{Keys: tc.set}, fapi.ES256, tc.kid)
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != 2 || !got[0].(*ecdsa.PublicKey).Equal(old) || !got[1].(*ecdsa.PublicKey).Equal(cur) {
				t.Fatalf("candidates = %v, want the old key then the new one", got)
			}
		})
	}
}

func TestVerificationKeyCandidatesCapsAndFiltersAlgorithm(t *testing.T) {
	set := keys.VerificationKeySet{Keys: []keys.VerificationKey{{Algorithm: fapi.PS256, PublicKey: newTestPublicKey(t)}}}
	if _, err := verificationKeyCandidates(set, fapi.ES256, ""); err == nil {
		t.Fatal("verificationKeyCandidates(no key for the algorithm) = nil error, want error")
	}
	for range maxKeyCandidates + 3 {
		set.Keys = append(set.Keys, keys.VerificationKey{Algorithm: fapi.ES256, PublicKey: newTestPublicKey(t)})
	}
	got, err := verificationKeyCandidates(set, fapi.ES256, "")
	if err != nil || len(got) != maxKeyCandidates {
		t.Fatalf("verificationKeyCandidates = %d keys, %v; want %d", len(got), err, maxKeyCandidates)
	}
}

// TestVerifyWithCandidates: a signature failure moves on to the next
// key; any other outcome, success or a claims failure, is final.
func TestVerifyWithCandidates(t *testing.T) {
	a, b, c := newTestPublicKey(t), newTestPublicKey(t), newTestPublicKey(t)
	errClaims := errors.New("expired")
	verify := func(signedBy crypto.PublicKey, claimsErr error) func(crypto.PublicKey) (string, error) {
		return func(pub crypto.PublicKey) (string, error) {
			if !pub.(*ecdsa.PublicKey).Equal(signedBy) {
				return "", fmt.Errorf("wrapped: %w", jose.ErrInvalidSignature)
			}
			return "ok", claimsErr
		}
	}
	candidates := []crypto.PublicKey{a, b, c}

	if got, err := verifyWithCandidates(candidates, verify(b, nil)); err != nil || got != "ok" {
		t.Errorf("signed by the second key: %q, %v; want ok", got, err)
	}
	if _, err := verifyWithCandidates(candidates, verify(b, errClaims)); !errors.Is(err, errClaims) {
		t.Errorf("claims failure with the second key: %v; want that failure", err)
	}
	if _, err := verifyWithCandidates(candidates, verify(newTestPublicKey(t), nil)); !errors.Is(err, jose.ErrInvalidSignature) {
		t.Errorf("no key fits: %v; want a signature failure", err)
	}
	if _, err := verifyWithCandidates(nil, verify(a, nil)); err == nil {
		t.Error("no candidates: nil error, want error")
	}
}

// thumbprintOf is pub's RFC 7638 thumbprint kid as a key for alg.
func thumbprintOf(t *testing.T, pub crypto.PublicKey, alg fapi.SignatureAlgorithm) string {
	t.Helper()
	thumbprint, err := jose.ThumbprintKeyID(pub, alg)
	if err != nil {
		t.Fatalf("ThumbprintKeyID(%v): %v", alg, err)
	}
	return thumbprint
}

// TestKeyCandidatesMatchKeyIDs: a client's key with no KeyID answers to
// its RFC 7638 thumbprint, computed for the key's own algorithm (ES256,
// PS256 or EdDSA), as well as to a request naming no kid; one with a
// KeyID answers to that alone, and one whose thumbprint can't be
// computed, for its algorithm or at all (an empty key, or a coordinate
// wider than its curve), to no kid. An attester's keys
// (verificationKeyCandidates) answer to their KeyID alone. Each key is
// asked for under its own algorithm.
func TestKeyCandidatesMatchKeyIDs(t *testing.T) {
	pub := newTestPublicKey(t)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	thumbprint := thumbprintOf(t, pub, fapi.ES256)
	edThumbprint := thumbprintOf(t, edPub, fapi.EdDSA)
	kidless := keys.VerificationKey{Algorithm: fapi.ES256, PublicKey: pub}
	named := keys.VerificationKey{KeyID: "named", Algorithm: fapi.ES256, PublicKey: pub}
	rsaKidless := keys.VerificationKey{Algorithm: fapi.PS256, PublicKey: &rsaKey.PublicKey}
	edKidless := keys.VerificationKey{Algorithm: fapi.EdDSA, PublicKey: edPub}
	unfit := keys.VerificationKey{Algorithm: fapi.ES256, PublicKey: edPub}
	// Keys a custom keys.ClientKeySource can hand over unchecked: one
	// with a coordinate too wide for P-256 and an empty one. Neither has
	// a thumbprint, so neither answers to a kid.
	wide := keys.VerificationKey{Algorithm: fapi.ES256, PublicKey: &ecdsa.PublicKey{
		Curve: elliptic.P256(), X: new(big.Int).Lsh(big.NewInt(1), 256), Y: pub.Y,
	}}
	empty := keys.VerificationKey{Algorithm: fapi.ES256, PublicKey: (*ecdsa.PublicKey)(nil)}
	for _, tc := range []struct {
		name             string
		key              keys.VerificationKey
		kid              string
		client, attester bool
	}{
		{"no KeyID, no kid named", kidless, "", true, true},
		{"no KeyID, its thumbprint", kidless, thumbprint, true, false},
		{"no KeyID, RSA, its thumbprint", rsaKidless, thumbprintOf(t, &rsaKey.PublicKey, fapi.PS256), true, false},
		{"no KeyID, Ed25519, its thumbprint", edKidless, edThumbprint, true, false},
		{"no KeyID, another kid", kidless, "other", false, false},
		{"KeyID, itself", named, "named", true, true},
		{"KeyID, its thumbprint", named, thumbprint, false, false},
		{"no KeyID, unfit for its algorithm", unfit, edThumbprint, false, false},
		{"no KeyID, a coordinate too wide for its curve", wide, thumbprint, false, false},
		{"no KeyID, an empty key", empty, thumbprint, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			set := keys.VerificationKeySet{Keys: []keys.VerificationKey{tc.key}}
			if _, err := clientKeyCandidates(set, tc.key.Algorithm, tc.kid); (err == nil) != tc.client {
				t.Errorf("clientKeyCandidates: %v, want a match %v", err, tc.client)
			}
			if _, err := verificationKeyCandidates(set, tc.key.Algorithm, tc.kid); (err == nil) != tc.attester {
				t.Errorf("verificationKeyCandidates: %v, want a match %v", err, tc.attester)
			}
		})
	}
}
