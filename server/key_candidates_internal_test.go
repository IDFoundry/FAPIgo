package server

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
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
