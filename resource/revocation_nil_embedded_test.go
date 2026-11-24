package resource_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/fapigo/resource"
)

// revocationEmbeddingUnrevocable embeds NoRevocationUntilExpiry by
// pointer, as a wrapper adding revocations of its own might.
type revocationEmbeddingUnrevocable struct {
	*resource.NoRevocationUntilExpiry
}

func (revocationEmbeddingUnrevocable) IsRevoked(context.Context, string) (bool, error) {
	return false, nil
}

// TestNewVerifierRefusesANilEmbeddedUnrevocable: a revocation checker
// embedding a nil *NoRevocationUntilExpiry is refused with an error,
// where NewVerifier used to panic reading its MaxTokenLifetime; one
// whose pointer is set is accepted.
func TestNewVerifierRefusesANilEmbeddedUnrevocable(t *testing.T) {
	f := newFixture(t)
	build := func(revocation resource.RevocationChecker) error {
		_, err := resource.NewVerifier(validConfig(t), resource.Dependencies{
			AccessTokens: f.accessTokens, Replay: &fakeReplayStore{},
			Revocation: revocation, Clock: fixedClock{now: f.now},
		})
		return err
	}
	if err := build(revocationEmbeddingUnrevocable{}); err == nil || !strings.Contains(err.Error(), "embeds a nil *NoRevocationUntilExpiry") {
		t.Fatalf("NewVerifier(nil embedded) = %v, want the nil embedding named", err)
	}
	set := revocationEmbeddingUnrevocable{&resource.NoRevocationUntilExpiry{MaxTokenLifetime: 5 * time.Minute}}
	if err := build(set); err != nil {
		t.Fatalf("NewVerifier(embedded, set): %v", err)
	}
}
