package resource

import "time"

// Clock supplies the current time. There is no implicit default —
// Dependencies.Clock must always be set explicitly, even to SystemClock.
type Clock interface {
	Now() time.Time
}

// ClockAssurance is implemented by a Clock to declare, under
// AssuranceProduction, that Now reads the system's current time: every
// expiry this verifier enforces (an access token's, a DPoP proof's, a
// nonce's) is only as sound as that reading, and a fixed or offset clock
// meant for tests would accept what has long expired. NewVerifier
// refuses any other Clock under AssuranceProduction. SystemClock
// declares it, as do server.SystemClock and client.SystemClock — the
// same method, so one clock type declaring it serves all three
// packages, and serverresource.NewVerifier can pass the server's Clock
// on; a clock of the application's own declares it only if Now does
// return the current time.
//
// A declaration is the operator's promise, not something this library
// verifies, beyond NewVerifier's one sanity check under
// AssuranceProduction: Now must be within Limits.MaxClockSkew of
// time.Now when NewVerifier runs.
type ClockAssurance interface {
	ReadsSystemTime() bool
}

// SystemClock is a Clock backed by time.Now. It is a plain, ready-made
// implementation a caller can wire in explicitly — supplying it is still
// a deliberate choice, not an implicit fallback NewVerifier applies on
// its own.
type SystemClock struct{}

// Now returns time.Now().
func (SystemClock) Now() time.Time { return time.Now() }

// ReadsSystemTime implements ClockAssurance: Now is time.Now.
func (SystemClock) ReadsSystemTime() bool { return true }
