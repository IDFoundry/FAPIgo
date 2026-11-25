package keys

import (
	"errors"
	"fmt"
	"log/slog"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/redact"
)

// signerSpecShadow is what a SignerSpec prints (see package redact):
// its fields, with only [REDACTED] for Signer, which may be the private
// key itself.
type signerSpecShadow struct {
	Purpose   SigningPurpose
	Algorithm fapi.SignatureAlgorithm
	Signer    redact.Hidden
	KeyID     string
	Previous  []PublicKeyInfo
}

func (s SignerSpec) shadow() signerSpecShadow {
	signer := redact.Hidden("")
	if s.Signer != nil {
		signer = redact.Redacted
	}
	return signerSpecShadow{Purpose: s.Purpose, Algorithm: s.Algorithm, Signer: signer, KeyID: s.KeyID, Previous: s.Previous}
}

// Format implements fmt.Formatter: s prints its purpose, algorithm, kid
// and previous public keys, and [REDACTED] for its Signer, under every
// verb and flag. Signer is often the private key itself: an
// ed25519.PrivateKey, say, which fmt would otherwise print byte by
// byte. fmt's reflection fallback, for a SignerSpec in an unexported
// field, still sees Signer as the exported field it is. Encoders are
// refused outright: see MarshalText.
func (s SignerSpec) Format(f fmt.State, verb rune) {
	redact.Format(f, verb, s.shadow(), "keys.signerSpecShadow", "keys.SignerSpec")
}

// LogValue implements slog.LogValuer: s's purpose, algorithm, kid and
// previous public keys, and [REDACTED] for its Signer.
func (s SignerSpec) LogValue() slog.Value {
	sh := s.shadow()
	return slog.GroupValue(
		slog.String("Purpose", sh.Purpose.String()), slog.String("Algorithm", sh.Algorithm.String()),
		slog.String("Signer", string(sh.Signer)), slog.String("KeyID", sh.KeyID),
		slog.Any("Previous", sh.Previous),
	)
}

// ErrSignerSpecSerialization is returned by SignerSpec's MarshalText
// and MarshalJSON, so a SignerSpec, whose Signer is often the private
// key itself, is never serialized (into a JSON response, a config dump,
// a log line) by an encoder that doesn't know what it holds. Publish
// the public keys with PublicJWKS instead.
var ErrSignerSpecSerialization = errors.New("keys: a SignerSpec cannot be marshaled, since its Signer may be the private key")

// MarshalText implements encoding.TextMarshaler by refusing: see
// ErrSignerSpecSerialization.
func (SignerSpec) MarshalText() ([]byte, error) {
	return nil, ErrSignerSpecSerialization
}

// MarshalJSON implements json.Marshaler by refusing: see
// ErrSignerSpecSerialization. It's declared as well as MarshalText so
// that encoding/json refuses a SignerSpec, rather than a pointer to one
// only, whichever it's given.
func (SignerSpec) MarshalJSON() ([]byte, error) {
	return nil, ErrSignerSpecSerialization
}
