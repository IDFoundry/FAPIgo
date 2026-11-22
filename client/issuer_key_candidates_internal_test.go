package client

import (
	"context"
	"crypto"
	"errors"
	"slices"
	"strconv"
	"testing"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/jose"
	"github.com/idfoundry/fapigo/keys"
)

// TestResolveIssuerKeyCandidatesKeepsTheFirstEight: the candidates are
// the first maxIssuerKeyCandidates keys Dependencies.IssuerKeys returns,
// in its order, however many it returns.
func TestResolveIssuerKeyCandidatesKeepsTheFirstEight(t *testing.T) {
	for _, n := range []int{1, maxIssuerKeyCandidates, maxIssuerKeyCandidates + 1, 4096} {
		returned := make([]keys.IssuerKey, n)
		for i := range returned {
			returned[i] = keys.IssuerKey{KeyID: strconv.Itoa(i), Algorithm: fapi.ES256}
		}
		c := issuerJWSTestClient(t, multiKeyIssuerKeys{keys: returned})
		got, err := c.resolveIssuerKeyCandidates(context.Background(), "JWS", keys.UserInfoVerification, fapi.ES256, "")
		if err != nil {
			t.Fatalf("resolveIssuerKeyCandidates(%d keys): %v", n, err)
		}
		if want := returned[:min(n, maxIssuerKeyCandidates)]; !slices.Equal(got, want) {
			t.Errorf("resolveIssuerKeyCandidates(%d keys) = %d keys, want the first %d", n, len(got), len(want))
		}
	}
}

// TestResolveIssuerKeyCandidatesWithoutIssuerKeys: a Client without
// Dependencies.IssuerKeys, which New allows only when nothing the issuer
// signed is verified, refuses with an internal error rather than
// panicking.
func TestResolveIssuerKeyCandidatesWithoutIssuerKeys(t *testing.T) {
	c := issuerJWSTestClient(t, nil)
	_, err := c.resolveIssuerKeyCandidates(context.Background(), "JWS", keys.UserInfoVerification, fapi.ES256, "")
	if err == nil || err.Code() != ErrorInternal {
		t.Fatalf("resolveIssuerKeyCandidates(no IssuerKeys) = %v, want an internal error", err)
	}
}

// TestVerifyIssuerSignedStopsOnceTheContextIsDone: the context ending
// while one candidate is checked leaves the rest untried, and the check
// fails with the context's error rather than the candidate's.
func TestVerifyIssuerSignedStopsOnceTheContextIsDone(t *testing.T) {
	c := issuerJWSTestClient(t, multiKeyIssuerKeys{keys: make([]keys.IssuerKey, 3)})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	tried := 0
	err := c.verifyIssuerSigned(ctx, "JWS", keys.UserInfoVerification, fapi.ES256, "", func(crypto.PublicKey) error {
		tried++
		cancel()
		return jose.ErrInvalidSignature
	})
	if tried != 1 {
		t.Errorf("candidates tried = %d, want 1", tried)
	}
	if err == nil || err.Code() != ErrorInternal || !errors.Is(err, context.Canceled) {
		t.Errorf("verifyIssuerSigned = %v, want an internal error wrapping context.Canceled", err)
	}
}
