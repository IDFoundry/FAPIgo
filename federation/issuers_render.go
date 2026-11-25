package federation

import (
	"fmt"
	"log/slog"

	"github.com/idfoundry/fapigo/internal/jose"
	"github.com/idfoundry/fapigo/internal/redact"
)

// Each issuer holds its dependencies, Signer included, so it prints a
// shadow of itself in which they print as their own Format does, with
// [REDACTED] for Signer (see dependencies_render.go), under every verb
// and flag and in log/slog. The dependencies are held behind a pointer,
// so fmt's reflection fallback, which calls no Format method (%w outside
// Errorf, say), prints only an address where Signer is: an
// ed25519.PrivateKey is a byte slice it would print whole.

type historicalKeysIssuerShadow struct {
	Config       HistoricalKeysIssueConfig
	Dependencies HistoricalKeysIssueDependencies
	Active       []jose.ParsedJWK
}

type resolveIssuerShadow struct {
	Config       ResolveIssueConfig
	Dependencies ResolveIssueDependencies
}

type selfIssuerShadow struct {
	Config       SelfIssueConfig
	Dependencies SelfIssueDependencies
}

type subordinateIssuerShadow struct {
	Config       SubordinateIssueConfig
	Dependencies SubordinateIssueDependencies
}

type trustMarkIssuerShadow struct {
	Config       TrustMarkIssueConfig
	Dependencies TrustMarkIssueDependencies
}

// deref is *p, or the zero value for a nil p.
func deref[T any](p *T) T {
	if p == nil {
		var zero T
		return zero
	}
	return *p
}

// Format implements fmt.Formatter: i prints its config and
// dependencies, with [REDACTED] for Signer, under every verb and flag.
func (i HistoricalKeysIssuer) Format(f fmt.State, verb rune) {
	redact.Format(f, verb, historicalKeysIssuerShadow{Config: i.cfg, Dependencies: deref(i.deps), Active: i.active},
		"federation.historicalKeysIssuerShadow", "federation.HistoricalKeysIssuer")
}

// LogValue implements slog.LogValuer: i's config and dependencies, with
// [REDACTED] for Signer.
func (i HistoricalKeysIssuer) LogValue() slog.Value {
	return slog.GroupValue(slog.Any("Config", i.cfg), slog.Any("Dependencies", deref(i.deps).LogValue()), slog.Any("Active", i.active))
}

// Format implements fmt.Formatter: i prints its config and
// dependencies, with [REDACTED] for Signer, under every verb and flag.
func (i ResolveIssuer) Format(f fmt.State, verb rune) {
	redact.Format(f, verb, resolveIssuerShadow{Config: i.cfg, Dependencies: deref(i.deps)}, "federation.resolveIssuerShadow", "federation.ResolveIssuer")
}

// LogValue implements slog.LogValuer: i's config and dependencies, with
// [REDACTED] for Signer.
func (i ResolveIssuer) LogValue() slog.Value {
	return slog.GroupValue(slog.Any("Config", i.cfg), slog.Any("Dependencies", deref(i.deps).LogValue()))
}

// Format implements fmt.Formatter: i prints its config and
// dependencies, with [REDACTED] for Signer, under every verb and flag.
func (s SelfIssuer) Format(f fmt.State, verb rune) {
	redact.Format(f, verb, selfIssuerShadow{Config: s.cfg, Dependencies: deref(s.deps)}, "federation.selfIssuerShadow", "federation.SelfIssuer")
}

// LogValue implements slog.LogValuer: i's config and dependencies, with
// [REDACTED] for Signer.
func (s SelfIssuer) LogValue() slog.Value {
	return slog.GroupValue(slog.Any("Config", s.cfg), slog.Any("Dependencies", deref(s.deps).LogValue()))
}

// Format implements fmt.Formatter: i prints its config and
// dependencies, with [REDACTED] for Signer, under every verb and flag.
func (s SubordinateIssuer) Format(f fmt.State, verb rune) {
	redact.Format(f, verb, subordinateIssuerShadow{Config: s.cfg, Dependencies: deref(s.deps)}, "federation.subordinateIssuerShadow", "federation.SubordinateIssuer")
}

// LogValue implements slog.LogValuer: i's config and dependencies, with
// [REDACTED] for Signer.
func (s SubordinateIssuer) LogValue() slog.Value {
	return slog.GroupValue(slog.Any("Config", s.cfg), slog.Any("Dependencies", deref(s.deps).LogValue()))
}

// Format implements fmt.Formatter: i prints its config and
// dependencies, with [REDACTED] for Signer, under every verb and flag.
func (i TrustMarkIssuer) Format(f fmt.State, verb rune) {
	redact.Format(f, verb, trustMarkIssuerShadow{Config: i.cfg, Dependencies: deref(i.deps)}, "federation.trustMarkIssuerShadow", "federation.TrustMarkIssuer")
}

// LogValue implements slog.LogValuer: i's config and dependencies, with
// [REDACTED] for Signer.
func (i TrustMarkIssuer) LogValue() slog.Value {
	return slog.GroupValue(slog.Any("Config", i.cfg), slog.Any("Dependencies", deref(i.deps).LogValue()))
}
