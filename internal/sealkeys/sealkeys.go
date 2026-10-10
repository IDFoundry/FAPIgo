// Package sealkeys checks the AES-256 key lists the sealers take
// (client.TokenSetSealer, client.BackchannelSessionSealer and the
// sealed cookies), so an obvious placeholder key is refused at
// construction instead of sealing everything under a key anyone can
// guess.
package sealkeys

import (
	"bytes"
	"fmt"
)

// Size is the length of every key: AES-256.
const Size = 32

// Check refuses keys unless it holds at least one key, each Size bytes,
// none of them a single byte repeated (all zeros, say: a placeholder,
// not a random key), and no key twice. what prefixes the errors. It
// can't tell a random key from any other: it only catches the keys
// that are certainly not random.
func Check(what string, keys [][]byte) error {
	if len(keys) == 0 {
		return fmt.Errorf("%s: at least one key is required", what)
	}
	for i, k := range keys {
		if len(k) != Size {
			return fmt.Errorf("%s: key %d is %d bytes, want %d", what, i, len(k), Size)
		}
		if bytes.Count(k, k[:1]) == Size {
			return fmt.Errorf("%s: key %d is one byte repeated, not a random key", what, i)
		}
		for j := range i {
			if bytes.Equal(keys[j], k) {
				return fmt.Errorf("%s: key %d repeats key %d", what, i, j)
			}
		}
	}
	return nil
}
