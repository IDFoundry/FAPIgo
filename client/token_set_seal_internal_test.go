package client

import (
	"errors"
	"testing"
)

// TestTokenSetSealerOpenRefusesNonJSON covers a set that authenticates
// but isn't a sealed TokenSet's JSON — only something holding the key
// could make one: Open still refuses it as unreadable.
func TestTokenSetSealerOpenRefusesNonJSON(t *testing.T) {
	sealer, err := NewTokenSetSealer(&Client{}, [][]byte{[]byte("token-set-internal-test-seal-key")})
	if err != nil {
		t.Fatal(err)
	}
	sealed := sealer.keys.seal(tokenSetSealVersion, []byte("not json"), sealer.additionalData("user-1"))

	if _, _, err := sealer.Open(sealed, "user-1"); !errors.Is(err, ErrUnreadableTokenSet) {
		t.Errorf("Open(non-JSON plaintext) = %v, want ErrUnreadableTokenSet", err)
	}
}
