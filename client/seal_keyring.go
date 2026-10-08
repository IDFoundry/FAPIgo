package client

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

// sealKeyring is the AES-256-GCM key list TokenSetSealer and
// BackchannelSessionSealer seal with: keys[0] seals, any key opens, and
// each sealed value names its key by the first four bytes of the key's
// SHA-256, so rotating in a new key first keeps older values readable.
type sealKeyring struct {
	keys []sealKey
}

type sealKey struct {
	id   [4]byte
	aead cipher.AEAD
}

// newSealKeyring builds a keyring from keys, each 32 bytes; what names
// the keys in an error ("token set", say).
func newSealKeyring(what string, keys [][]byte) (sealKeyring, error) {
	if len(keys) == 0 {
		return sealKeyring{}, fmt.Errorf("client: a %s sealer needs at least one key", what)
	}
	var r sealKeyring
	for i, k := range keys {
		if len(k) != 32 {
			return sealKeyring{}, fmt.Errorf("client: %s key %d is %d bytes, want 32", what, i, len(k))
		}
		// A 32-byte key always makes an AES-256 block, and AES always
		// makes a GCM.
		block, _ := aes.NewCipher(k)
		aead, _ := cipher.NewGCM(block)
		sum := sha256.Sum256(k)
		r.keys = append(r.keys, sealKey{id: [4]byte(sum[:4]), aead: aead})
	}
	return r, nil
}

// seal encrypts plaintext with keys[0] under additionalData, as
// version, then the key's ID, the nonce and the ciphertext.
func (r sealKeyring) seal(version byte, plaintext, additionalData []byte) []byte {
	key := r.keys[0]
	nonce := make([]byte, key.aead.NonceSize())
	_, _ = rand.Read(nonce) // never fails: it crashes the program instead (Go 1.24+)
	out := append([]byte{version}, key.id[:]...)
	out = append(out, nonce...)
	return key.aead.Seal(out, nonce, plaintext, additionalData)
}

// open reverses seal: the plaintext, and the index of the key that
// opened it (above zero means an older key: seal again). ok is false
// for anything that isn't a value one of these keys sealed, as version,
// under additionalData.
func (r sealKeyring) open(version byte, sealed, additionalData []byte) (plaintext []byte, keyIndex int, ok bool) {
	if len(sealed) < 5 || sealed[0] != version {
		return nil, 0, false
	}
	id, rest := [4]byte(sealed[1:5]), sealed[5:]
	for i, key := range r.keys {
		if key.id != id || len(rest) < key.aead.NonceSize() {
			continue
		}
		plaintext, err := key.aead.Open(nil, rest[:key.aead.NonceSize()], rest[key.aead.NonceSize():], additionalData)
		if err != nil {
			return nil, 0, false
		}
		return plaintext, i, true
	}
	return nil, 0, false
}

// sealAdditionalData is domain, version and then each of parts
// length-prefixed, so no two bindings differ only in where one part
// ends and the next begins.
func sealAdditionalData(domain string, version byte, parts ...string) []byte {
	ad := append([]byte(domain), version)
	for _, part := range parts {
		ad = binary.BigEndian.AppendUint32(ad, uint32(len(part))) //nolint:gosec // G115: lengths of in-memory strings
		ad = append(ad, part...)
	}
	return ad
}
