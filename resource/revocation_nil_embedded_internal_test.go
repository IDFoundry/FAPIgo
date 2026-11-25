package resource

import (
	"context"
	"testing"
	"time"
)

// embeddingUnrevocable embeds NoRevocationUntilExpiry by pointer.
type embeddingUnrevocable struct {
	*NoRevocationUntilExpiry
}

func (embeddingUnrevocable) IsRevoked(context.Context, string) (bool, error) { return false, nil }

// TestEmbedsNilUnrevocable: only a struct embedding a nil
// *NoRevocationUntilExpiry is reported. A nil *NoRevocationUntilExpiry
// itself is not: NewVerifier's typed-nil check refuses it first, and
// unrevocableLifetime reads it as no declaration.
func TestEmbedsNilUnrevocable(t *testing.T) {
	var nilPointer *NoRevocationUntilExpiry
	for name, tc := range map[string]struct {
		revocation RevocationChecker
		want       bool
	}{
		"embedded nil pointer":  {embeddingUnrevocable{}, true},
		"embedded set pointer":  {embeddingUnrevocable{&NoRevocationUntilExpiry{MaxTokenLifetime: time.Minute}}, false},
		"nil pointer itself":    {nilPointer, false},
		"by value":              {NoRevocationUntilExpiry{MaxTokenLifetime: time.Minute}, false},
		"no unrevocable at all": {NoRevocation{}, false},
	} {
		if got := embedsNilUnrevocable(tc.revocation); got != tc.want {
			t.Errorf("%s: embedsNilUnrevocable = %v, want %v", name, got, tc.want)
		}
	}
}
