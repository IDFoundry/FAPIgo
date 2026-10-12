// Package pairwise derives pairwise subject identifiers (PPIDs, OpenID
// Connect Core 1.0 §8.1): the "sub" an end user has at one sector of
// clients, unlinkable to the sub the same user has at another sector.
//
// A Deriver turns an Input (issuer, sector, internal subject) into the
// opaque body of a PPID; the server prepends the deployment's Prefix,
// stores the result with the grant, and issues it wherever the client
// sees the user's sub. A Deriver that can also map a body back to the
// internal subject implements Lookup.
//
// NewHMAC is the built-in one-way Deriver. NewMapping is a reversible
// one that keeps a random body per user and sector in a
// storage.PairwiseSubjectStore, so no key exists whose loss would let
// anyone compute or reverse identifiers. The package imports neither
// server nor resource, so both can use the same deriver without one
// importing the other.
package pairwise

import (
	"context"
	"fmt"
	"unicode/utf8"
)

// Derivation is whether a deployment's pairwise subjects can be mapped
// back to the internal subject by the OP. Its zero value is no
// derivation at all, which a configuration that can issue pairwise
// subjects refuses: the choice is stated, never defaulted.
type Derivation uint8

const (
	_ Derivation = iota

	// OneWay derivation can't be reversed, even by the OP: a leaked key
	// only lets an attacker test guesses at internal subjects. NewHMAC
	// is OneWay.
	OneWay

	// Reversible derivation can be mapped back to the internal subject by
	// the OP, through Lookup. NewMapping is Reversible.
	Reversible
)

// String returns "one-way" or "reversible", or "" if d is not a
// recognized Derivation.
func (d Derivation) String() string {
	switch d {
	case OneWay:
		return "one-way"
	case Reversible:
		return "reversible"
	default:
		return ""
	}
}

// IsValid reports whether d is OneWay or Reversible.
func (d Derivation) IsValid() bool { return d == OneWay || d == Reversible }

// MaxPrefixLength is the longest Prefix NewPrefix accepts, in bytes.
const MaxPrefixLength = 16

// MaxBodyLength is the longest body a Deriver may return: OpenID
// Connect Core §2 limits sub to 255 ASCII characters, and the server
// prepends a Prefix of up to MaxPrefixLength.
const MaxBodyLength = 255 - MaxPrefixLength

// Prefix is the text a deployment puts in front of every pairwise
// subject's body, such as "ppid:". It may be empty, but it is always
// set explicitly: the zero Prefix is unset, and a configuration that can
// issue pairwise subjects refuses it. Changing a deployment's Prefix
// changes every pairwise sub it issues afterwards.
type Prefix struct {
	value string
	set   bool
}

// NewPrefix returns s as a Prefix: at most MaxPrefixLength printable
// ASCII characters (0x21 to 0x7E), or empty.
func NewPrefix(s string) (Prefix, error) {
	if len(s) > MaxPrefixLength {
		return Prefix{}, fmt.Errorf("pairwise: prefix is %d bytes, more than %d", len(s), MaxPrefixLength)
	}
	if i := firstNonGraphic(s); i >= 0 {
		return Prefix{}, fmt.Errorf("pairwise: prefix has a byte (0x%02x at %d) that isn't printable ASCII", s[i], i)
	}
	return Prefix{value: s, set: true}, nil
}

// String returns the prefix text ("" for an empty or unset Prefix).
func (p Prefix) String() string { return p.value }

// IsSet reports whether p was made by NewPrefix, empty or not.
func (p Prefix) IsSet() bool { return p.set }

// Input is what a Deriver derives a body from: the issuer, the client's
// sector, and the end user's internal subject. Build one with NewInput.
type Input struct {
	issuer, sector, subject string
}

// MaxInputLength is the longest issuer, sector or internal subject
// NewInput accepts, in bytes.
const MaxInputLength = 2048

// NewInput validates and returns an Input. The issuer and sector must be
// non-empty, valid UTF-8 without control characters, and at most
// MaxInputLength bytes; the internal subject must be 1 to 255 printable
// ASCII characters (0x20 to 0x7E), as a server.SubjectID is.
func NewInput(issuer, sector, subject string) (Input, error) {
	if err := checkText("issuer", issuer); err != nil {
		return Input{}, err
	}
	if err := checkText("sector", sector); err != nil {
		return Input{}, err
	}
	if subject == "" || len(subject) > 255 {
		return Input{}, fmt.Errorf("pairwise: subject must be 1 to 255 bytes, not %d", len(subject))
	}
	for i := range len(subject) {
		if c := subject[i]; c < 0x20 || c > 0x7e {
			return Input{}, fmt.Errorf("pairwise: subject has a byte (0x%02x at %d) that isn't printable ASCII", c, i)
		}
	}
	return Input{issuer: issuer, sector: sector, subject: subject}, nil
}

// Issuer returns the issuer in.
func (in Input) Issuer() string { return in.issuer }

// Sector returns the sector in.
func (in Input) Sector() string { return in.sector }

// Subject returns the internal subject in.
func (in Input) Subject() string { return in.subject }

// IsZero reports whether in is the zero Input, which no Deriver accepts.
func (in Input) IsZero() bool { return in.subject == "" }

// Deriver derives the body of a pairwise subject. Implementations must
// be deterministic (the same Input always gives the same body, on every
// instance and after every restart), must give different Inputs
// different bodies, and must not let anyone without their secret link a
// body to its Input. The body must pass CheckBody. NewHMAC is the
// built-in implementation; TestDeriverContract checks the observable
// parts of this contract.
type Deriver interface {
	DerivePairwiseSubject(ctx context.Context, in Input) (string, error)
}

// Lookup is the optional interface of a Deriver that can map a body back
// to the internal subject it was derived from: LookupInternalSubject
// returns the internal subject whose body under issuer and sector is
// body, or an error wrapping ErrSubjectNotFound if there is none (any
// other error means the lookup itself failed). A Reversible
// deployment's Deriver must implement it.
type Lookup interface {
	LookupInternalSubject(ctx context.Context, issuer, sector, body string) (string, error)
}

// SubjectResolver maps a pairwise sub a OneWay deployment issued back to
// the internal subject, from a mapping the embedder keeps itself (a table
// of the subs it issued, say), since a OneWay Deriver can't.
// ResolveSubject returns the internal subject whose sub, under issuer and
// sector, is sub (the whole sub, prefix included), or an error wrapping
// ErrSubjectNotFound if there is none; any other error means the mapping
// couldn't be read, and is never read as "no such subject".
//
// It's what lets a OneWay deployment issue self-contained (JWT) access
// tokens: every resource server verifying them needs it
// (resource.Dependencies.SubjectResolver), and the authorization server
// is told one is in use (server.Dependencies.PairwiseSubjectResolver),
// though the server itself never calls it. Under production assurance it
// must implement keys.KeyCustodyAssurance, declaring Durable (and
// CrossInstanceConsistent for a fleet).
type SubjectResolver interface {
	ResolveSubject(ctx context.Context, issuer, sector, sub string) (string, error)
}

// CheckBody refuses a body a Deriver must never return: empty, longer
// than MaxBodyLength, or with a byte outside printable ASCII without the
// space (0x21 to 0x7E).
func CheckBody(body string) error {
	if body == "" || len(body) > MaxBodyLength {
		return fmt.Errorf("pairwise: body must be 1 to %d bytes, not %d", MaxBodyLength, len(body))
	}
	if i := firstNonGraphic(body); i >= 0 {
		return fmt.Errorf("pairwise: body has a byte (0x%02x at %d) that isn't printable ASCII", body[i], i)
	}
	return nil
}

// firstNonGraphic returns the index of s's first byte outside 0x21 to
// 0x7E, or -1 if there is none.
func firstNonGraphic(s string) int {
	for i := range len(s) {
		if c := s[i]; c < 0x21 || c > 0x7e {
			return i
		}
	}
	return -1
}

// checkText refuses an issuer or sector that is empty, too long, not
// valid UTF-8, or holds a control character.
func checkText(name, s string) error {
	if s == "" || len(s) > MaxInputLength {
		return fmt.Errorf("pairwise: %s must be 1 to %d bytes, not %d", name, MaxInputLength, len(s))
	}
	if !utf8.ValidString(s) {
		return fmt.Errorf("pairwise: %s is not valid UTF-8", name)
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) {
			return fmt.Errorf("pairwise: %s has a control character (%U)", name, r)
		}
	}
	return nil
}
