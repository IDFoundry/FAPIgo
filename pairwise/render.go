package pairwise

import (
	"fmt"
	"log/slog"

	"github.com/idfoundry/fapigo/internal/redact"
	"github.com/idfoundry/fapigo/keys"
)

// A Deriver built on a key held in memory keeps that key in its ops, so
// HMACDeriver and ReversibleDeriver print a shadow of themselves in
// which ops is only redact.Redacted, under every verb and in log/slog
// (see package redact). The in-memory ops hold their keys where fmt's
// reflection fallback prints only an address (see memoryHMACOps).

type hmacDeriverShadow struct {
	ops     redact.Hidden
	custody keys.KeyCustody
}

type reversibleDeriverShadow struct {
	ops     redact.Hidden
	custody keys.KeyCustody
}

func opsMask(ops any) redact.Hidden {
	if ops == nil {
		return ""
	}
	return redact.Redacted
}

// Format implements fmt.Formatter: d prints its key custody, and
// [REDACTED] for the key operations, under every verb and flag.
func (d HMACDeriver) Format(f fmt.State, verb rune) {
	redact.Format(f, verb, hmacDeriverShadow{ops: opsMask(d.ops), custody: d.custody}, "pairwise.hmacDeriverShadow", "pairwise.HMACDeriver")
}

// LogValue implements slog.LogValuer: d's key operations as
// [REDACTED], and its key custody.
func (d HMACDeriver) LogValue() slog.Value {
	return derivedLogValue(d.ops, d.custody)
}

// Format implements fmt.Formatter: d prints its key custody, and
// [REDACTED] for the key operations, under every verb and flag.
func (d ReversibleDeriver) Format(f fmt.State, verb rune) {
	redact.Format(f, verb, reversibleDeriverShadow{ops: opsMask(d.ops), custody: d.custody}, "pairwise.reversibleDeriverShadow", "pairwise.ReversibleDeriver")
}

// LogValue implements slog.LogValuer: d's key operations as
// [REDACTED], and its key custody.
func (d ReversibleDeriver) LogValue() slog.Value {
	return derivedLogValue(d.ops, d.custody)
}

func derivedLogValue(ops any, custody keys.KeyCustody) slog.Value {
	return slog.GroupValue(
		slog.String("ops", string(opsMask(ops))),
		slog.Any("custody", custody),
	)
}
