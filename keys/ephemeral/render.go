package ephemeral

import (
	"fmt"
	"log/slog"

	"github.com/idfoundry/fapigo/internal/redact"
	"github.com/idfoundry/fapigo/keys"
)

// A KeyManager holds the private keys it generated, so it prints a
// shadow of itself in which each key is only [REDACTED], under every
// verb and flag and in log/slog (see package redact). Without it fmt
// prints an ed25519.PrivateKey, a byte slice, byte by byte.

type keyManagerShadow struct {
	Keys       map[keys.SigningPurpose]keyShadow
	Decryption map[keys.DecryptionPurpose]keyShadow
}

type keyShadow struct {
	Key   redact.Hidden
	KeyID string
}

func (m *KeyManager) shadow() keyManagerShadow {
	m.mu.Lock()
	defer m.mu.Unlock()
	var sh keyManagerShadow
	if m.keys != nil {
		sh.Keys = make(map[keys.SigningPurpose]keyShadow, len(m.keys))
		for purpose, held := range m.keys {
			sh.Keys[purpose] = keyShadow{Key: keyMask(held != nil && held.signer != nil), KeyID: m.kid[purpose]}
		}
	}
	if m.decryption != nil {
		sh.Decryption = make(map[keys.DecryptionPurpose]keyShadow, len(m.decryption.keys))
		for purpose, priv := range m.decryption.keys {
			sh.Decryption[purpose] = keyShadow{Key: keyMask(priv != nil), KeyID: m.decryption.kid[purpose]}
		}
	}
	return sh
}

// keyMask is the placeholder for a held key: [REDACTED], or "" for
// none.
func keyMask(present bool) redact.Hidden {
	if !present {
		return ""
	}
	return redact.Redacted
}

// Format implements fmt.Formatter: m prints each purpose's kid, and
// [REDACTED] for its key, signing and decryption keys alike, under
// every verb and flag.
func (m *KeyManager) Format(f fmt.State, verb rune) {
	redact.Format(f, verb, m.shadow(), "ephemeral.keyManagerShadow", "ephemeral.KeyManager")
}

// LogValue implements slog.LogValuer: each purpose's kid, and
// [REDACTED] for its key, signing and decryption keys alike.
func (m *KeyManager) LogValue() slog.Value {
	sh := m.shadow()
	signing := make([]any, 0, len(sh.Keys))
	for purpose, k := range sh.Keys {
		signing = append(signing, keyAttr(purpose.String(), k))
	}
	decryption := make([]any, 0, len(sh.Decryption))
	for purpose, k := range sh.Decryption {
		decryption = append(decryption, keyAttr(fmt.Sprint(purpose), k))
	}
	return slog.GroupValue(slog.Group("Keys", signing...), slog.Group("Decryption", decryption...))
}

func keyAttr(name string, k keyShadow) slog.Attr {
	return slog.Group(name, slog.String("Key", string(k.Key)), slog.String("KeyID", k.KeyID))
}
