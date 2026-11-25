package keys

import (
	"fmt"
	"log/slog"

	"github.com/idfoundry/fapigo/internal/redact"
)

// The KeyManager NewKeyManagerFromSigners builds, and the in-memory
// ECDHAgreer and KeyDecrypter, hold private keys, so each prints a
// shadow of itself in which a key is only [REDACTED], under every verb
// and flag and in log/slog (see package redact). Without it fmt prints
// an ed25519.PrivateKey, a byte slice, byte by byte, and a verb a
// pointer doesn't take, such as %s, makes it print what an
// *ecdh.PrivateKey points to. signerKeyManager also holds each backend
// behind a pointer, so fmt's reflection fallback (%w, say, which calls
// no method) prints only an address where the signer is.

type signerKeyManagerShadow struct {
	Backends map[SigningPurpose]signerBackendShadow
}

type signerBackendShadow struct {
	Signer    redact.Hidden
	Algorithm string
	KeyID     string
	Previous  []PublicKeyInfo
}

type custodyKeyManagerShadow struct {
	Backends map[SigningPurpose]signerBackendShadow
	Custody  KeyCustody
}

type inMemoryKeyShadow struct {
	Priv  redact.Hidden
	KeyID string
}

// keyMask is the placeholder for a held key: [REDACTED], or "" for
// none.
func keyMask(present bool) redact.Hidden {
	if !present {
		return ""
	}
	return redact.Redacted
}

func (m signerKeyManager) shadow() signerKeyManagerShadow {
	backends := make(map[SigningPurpose]signerBackendShadow, len(m.backends))
	for purpose, b := range m.backends {
		backends[purpose] = signerBackendShadow{Signer: keyMask(b.signer != nil), Algorithm: b.algorithm.String(), KeyID: b.kid, Previous: b.previous}
	}
	return signerKeyManagerShadow{Backends: backends}
}

// Format implements fmt.Formatter: m prints each purpose's algorithm,
// kid and previous public keys, and [REDACTED] for its signer, under
// every verb and flag.
func (m signerKeyManager) Format(f fmt.State, verb rune) {
	redact.Format(f, verb, m.shadow(), "keys.signerKeyManagerShadow", "keys.signerKeyManager", "keys.signerBackendShadow", "keys.signerBackend")
}

// LogValue implements slog.LogValuer: each purpose's algorithm, kid
// and previous public keys, and [REDACTED] for its signer.
func (m signerKeyManager) LogValue() slog.Value {
	return slog.GroupValue(backendsAttr(m.shadow().Backends))
}

// Format implements fmt.Formatter: m prints as its signerKeyManager
// does, with its declared custody.
func (m custodyKeyManager) Format(f fmt.State, verb rune) {
	var backends map[SigningPurpose]signerBackendShadow
	if m.signerKeyManager != nil {
		backends = m.shadow().Backends
	}
	redact.Format(f, verb, custodyKeyManagerShadow{Backends: backends, Custody: m.custody}, "keys.custodyKeyManagerShadow", "keys.custodyKeyManager", "keys.signerBackendShadow", "keys.signerBackend")
}

// LogValue implements slog.LogValuer: m logs as its signerKeyManager
// does, with its declared custody.
func (m custodyKeyManager) LogValue() slog.Value {
	var backends map[SigningPurpose]signerBackendShadow
	if m.signerKeyManager != nil {
		backends = m.shadow().Backends
	}
	return slog.GroupValue(backendsAttr(backends), slog.Any("Custody", m.custody))
}

// backendsAttr is a group of backends' shadows, one per purpose.
func backendsAttr(backends map[SigningPurpose]signerBackendShadow) slog.Attr {
	attrs := make([]any, 0, len(backends))
	for purpose, b := range backends {
		attrs = append(attrs, slog.Group(purpose.String(),
			slog.String("Signer", string(b.Signer)), slog.String("Algorithm", b.Algorithm),
			slog.String("KeyID", b.KeyID), slog.Any("Previous", b.Previous),
		))
	}
	return slog.Group("Backends", attrs...)
}

// Format implements fmt.Formatter: k prints its kid, and [REDACTED]
// for its private key, under every verb and flag.
func (k inMemoryECDH) Format(f fmt.State, verb rune) {
	redact.Format(f, verb, inMemoryKeyShadow{Priv: keyMask(k.priv != nil), KeyID: k.kid}, "keys.inMemoryKeyShadow", "keys.inMemoryECDH")
}

// LogValue implements slog.LogValuer: k's kid, and [REDACTED] for its
// private key.
func (k inMemoryECDH) LogValue() slog.Value {
	return inMemoryKeyLogValue(k.priv != nil, k.kid)
}

// Format implements fmt.Formatter: k prints its kid, and [REDACTED]
// for its private key, under every verb and flag.
func (k inMemoryRSA) Format(f fmt.State, verb rune) {
	redact.Format(f, verb, inMemoryKeyShadow{Priv: keyMask(k.priv != nil), KeyID: k.kid}, "keys.inMemoryKeyShadow", "keys.inMemoryRSA")
}

// LogValue implements slog.LogValuer: k's kid, and [REDACTED] for its
// private key.
func (k inMemoryRSA) LogValue() slog.Value {
	return inMemoryKeyLogValue(k.priv != nil, k.kid)
}

func inMemoryKeyLogValue(present bool, kid string) slog.Value {
	return slog.GroupValue(slog.String("Priv", string(keyMask(present))), slog.String("KeyID", kid))
}
