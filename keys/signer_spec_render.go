package keys

import (
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
// byte. fmt's
// reflection fallback, for a SignerSpec in an unexported field, and
// encoders such as encoding/json still see Signer as the exported field
// it is.
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
