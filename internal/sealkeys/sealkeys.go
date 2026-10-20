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
// not a random key) or made entirely of printable text (a passphrase,
// or a hex or base64 key not yet decoded), and no key twice. what
// prefixes the errors. It can't tell a random key from any other: it
// only catches the keys that are certainly not random. 32 random bytes
// are all printable with probability (98/256)^32, about 4e-14, so a
// real key is never refused.
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
		if isText(k) {
			return fmt.Errorf("%s: key %d is all printable text (a passphrase, or a hex or base64 key not yet decoded), not %d random bytes: generate it with crypto/rand, and decode an encoded key before passing it", what, i, Size)
		}
		for j := range i {
			if bytes.Equal(keys[j], k) {
				return fmt.Errorf("%s: key %d repeats key %d", what, i, j)
			}
		}
	}
	return nil
}

// isText reports whether k is made entirely of printable ASCII and
// whitespace.
func isText(k []byte) bool {
	for _, c := range k {
		if (c < 0x20 || c > 0x7e) && c != '\t' && c != '\n' && c != '\r' {
			return false
		}
	}
	return true
}
