package federation

import (
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/redact"
)

// The issuers' *IssueDependencies hold the Signer that signs the
// issuer's statements, often the private key itself, in an exported
// field. So each prints a shadow of itself in which Signer is only
// [REDACTED], under every fmt verb and flag and in log/slog (see
// package redact), and refuses encoding/json, encoding/xml and every
// other encoder that takes an encoding.TextMarshaler: see
// ErrIssueDependenciesSerialization. fmt's reflection fallback, for a
// value in an unexported field, still sees Signer as the exported field
// it is: an *ecdsa.PrivateKey or *rsa.PrivateKey sits behind a pointer
// it prints as an address, but an ed25519.PrivateKey is a byte slice.

// ErrIssueDependenciesSerialization is returned by the MarshalText and
// MarshalJSON methods of HistoricalKeysIssueDependencies,
// ResolveIssueDependencies, SelfIssueDependencies,
// SubordinateIssueDependencies and TrustMarkIssueDependencies, so a
// Signer, often the private key itself, is never serialized (into a
// JSON response, a config dump, a log line) by an encoder that doesn't
// know what it holds. Publish the entity's public keys as its JWKS
// instead.
var ErrIssueDependenciesSerialization = errors.New("federation: issuer dependencies cannot be marshaled, since their Signer may be the private key")

// issueDependenciesShadow is what ResolveIssueDependencies,
// SubordinateIssueDependencies and TrustMarkIssueDependencies print.
type issueDependenciesShadow struct {
	Signer    redact.Hidden
	Algorithm fapi.SignatureAlgorithm
	KeyID     string
	Clock     Clock
}

// jwksIssueDependenciesShadow is what HistoricalKeysIssueDependencies
// and SelfIssueDependencies print.
type jwksIssueDependenciesShadow struct {
	Signer    redact.Hidden
	Algorithm fapi.SignatureAlgorithm
	KeyID     string
	JWKS      json.RawMessage
	Clock     Clock
}

func signerMask(signer crypto.Signer) redact.Hidden {
	if signer == nil {
		return ""
	}
	return redact.Redacted
}

func formatDependencies(f fmt.State, verb rune, signer crypto.Signer, alg fapi.SignatureAlgorithm, kid string, clock Clock, typeName string) {
	sh := issueDependenciesShadow{Signer: signerMask(signer), Algorithm: alg, KeyID: kid, Clock: clock}
	redact.Format(f, verb, sh, "federation.issueDependenciesShadow", typeName)
}

func formatJWKSDependencies(f fmt.State, verb rune, signer crypto.Signer, alg fapi.SignatureAlgorithm, kid string, jwks json.RawMessage, clock Clock, typeName string) {
	sh := jwksIssueDependenciesShadow{Signer: signerMask(signer), Algorithm: alg, KeyID: kid, JWKS: jwks, Clock: clock}
	redact.Format(f, verb, sh, "federation.jwksIssueDependenciesShadow", typeName)
}

func dependenciesLogValue(signer crypto.Signer, alg fapi.SignatureAlgorithm, kid string, clock Clock, extra ...slog.Attr) slog.Value {
	attrs := []slog.Attr{
		slog.String("Signer", string(signerMask(signer))), slog.String("Algorithm", alg.String()),
		slog.String("KeyID", kid),
	}
	attrs = append(attrs, extra...)
	return slog.GroupValue(append(attrs, slog.Any("Clock", clock))...)
}

// Format implements fmt.Formatter: d prints its fields, with only
// [REDACTED] for Signer, under every verb and flag.
func (d HistoricalKeysIssueDependencies) Format(f fmt.State, verb rune) {
	formatJWKSDependencies(f, verb, d.Signer, d.Algorithm, d.KeyID, d.JWKS, d.Clock, "federation.HistoricalKeysIssueDependencies")
}

// LogValue implements slog.LogValuer: d's fields, with only
// [REDACTED] for Signer.
func (d HistoricalKeysIssueDependencies) LogValue() slog.Value {
	return dependenciesLogValue(d.Signer, d.Algorithm, d.KeyID, d.Clock, slog.Any("JWKS", d.JWKS))
}

// MarshalText implements encoding.TextMarshaler by refusing: see
// ErrIssueDependenciesSerialization.
func (HistoricalKeysIssueDependencies) MarshalText() ([]byte, error) {
	return nil, ErrIssueDependenciesSerialization
}

// MarshalJSON implements json.Marshaler by refusing: see
// ErrIssueDependenciesSerialization.
func (HistoricalKeysIssueDependencies) MarshalJSON() ([]byte, error) {
	return nil, ErrIssueDependenciesSerialization
}

// Format implements fmt.Formatter: d prints its fields, with only
// [REDACTED] for Signer, under every verb and flag.
func (d ResolveIssueDependencies) Format(f fmt.State, verb rune) {
	formatDependencies(f, verb, d.Signer, d.Algorithm, d.KeyID, d.Clock, "federation.ResolveIssueDependencies")
}

// LogValue implements slog.LogValuer: d's fields, with only
// [REDACTED] for Signer.
func (d ResolveIssueDependencies) LogValue() slog.Value {
	return dependenciesLogValue(d.Signer, d.Algorithm, d.KeyID, d.Clock)
}

// MarshalText implements encoding.TextMarshaler by refusing: see
// ErrIssueDependenciesSerialization.
func (ResolveIssueDependencies) MarshalText() ([]byte, error) {
	return nil, ErrIssueDependenciesSerialization
}

// MarshalJSON implements json.Marshaler by refusing: see
// ErrIssueDependenciesSerialization.
func (ResolveIssueDependencies) MarshalJSON() ([]byte, error) {
	return nil, ErrIssueDependenciesSerialization
}

// Format implements fmt.Formatter: d prints its fields, with only
// [REDACTED] for Signer, under every verb and flag.
func (d SelfIssueDependencies) Format(f fmt.State, verb rune) {
	formatJWKSDependencies(f, verb, d.Signer, d.Algorithm, d.KeyID, d.JWKS, d.Clock, "federation.SelfIssueDependencies")
}

// LogValue implements slog.LogValuer: d's fields, with only
// [REDACTED] for Signer.
func (d SelfIssueDependencies) LogValue() slog.Value {
	return dependenciesLogValue(d.Signer, d.Algorithm, d.KeyID, d.Clock, slog.Any("JWKS", d.JWKS))
}

// MarshalText implements encoding.TextMarshaler by refusing: see
// ErrIssueDependenciesSerialization.
func (SelfIssueDependencies) MarshalText() ([]byte, error) {
	return nil, ErrIssueDependenciesSerialization
}

// MarshalJSON implements json.Marshaler by refusing: see
// ErrIssueDependenciesSerialization.
func (SelfIssueDependencies) MarshalJSON() ([]byte, error) {
	return nil, ErrIssueDependenciesSerialization
}

// Format implements fmt.Formatter: d prints its fields, with only
// [REDACTED] for Signer, under every verb and flag.
func (d SubordinateIssueDependencies) Format(f fmt.State, verb rune) {
	formatDependencies(f, verb, d.Signer, d.Algorithm, d.KeyID, d.Clock, "federation.SubordinateIssueDependencies")
}

// LogValue implements slog.LogValuer: d's fields, with only
// [REDACTED] for Signer.
func (d SubordinateIssueDependencies) LogValue() slog.Value {
	return dependenciesLogValue(d.Signer, d.Algorithm, d.KeyID, d.Clock)
}

// MarshalText implements encoding.TextMarshaler by refusing: see
// ErrIssueDependenciesSerialization.
func (SubordinateIssueDependencies) MarshalText() ([]byte, error) {
	return nil, ErrIssueDependenciesSerialization
}

// MarshalJSON implements json.Marshaler by refusing: see
// ErrIssueDependenciesSerialization.
func (SubordinateIssueDependencies) MarshalJSON() ([]byte, error) {
	return nil, ErrIssueDependenciesSerialization
}

// Format implements fmt.Formatter: d prints its fields, with only
// [REDACTED] for Signer, under every verb and flag.
func (d TrustMarkIssueDependencies) Format(f fmt.State, verb rune) {
	formatDependencies(f, verb, d.Signer, d.Algorithm, d.KeyID, d.Clock, "federation.TrustMarkIssueDependencies")
}

// LogValue implements slog.LogValuer: d's fields, with only
// [REDACTED] for Signer.
func (d TrustMarkIssueDependencies) LogValue() slog.Value {
	return dependenciesLogValue(d.Signer, d.Algorithm, d.KeyID, d.Clock)
}

// MarshalText implements encoding.TextMarshaler by refusing: see
// ErrIssueDependenciesSerialization.
func (TrustMarkIssueDependencies) MarshalText() ([]byte, error) {
	return nil, ErrIssueDependenciesSerialization
}

// MarshalJSON implements json.Marshaler by refusing: see
// ErrIssueDependenciesSerialization.
func (TrustMarkIssueDependencies) MarshalJSON() ([]byte, error) {
	return nil, ErrIssueDependenciesSerialization
}
