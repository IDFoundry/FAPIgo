package server

import "time"

// Clock supplies the current time. There is no implicit default —
// Dependencies.Clock must always be set explicitly, even to SystemClock.
type Clock interface {
	Now() time.Time
}

// ClockAssurance is implemented by a Clock to declare, under
// AssuranceProduction, that Now reads the system's current time:
// every expiry this server enforces is only as sound as that reading,
// and a fixed or offset clock meant for tests would silently stop
// every code, token and request from expiring. New refuses any other
// Clock under AssuranceProduction. SystemClock declares it; a clock of
// the application's own (one adding tracing, say) declares it only if
// Now does return the current time. client.ClockAssurance and
// resource.ClockAssurance are the same method, so one clock type
// declaring it serves all three.
//
// A declaration is the operator's promise, not something this library
// verifies, beyond New's one sanity check under AssuranceProduction:
// Now must be within Limits.MaxClockSkew of time.Now when New runs.
type ClockAssurance interface {
	ReadsSystemTime() bool
}

// SystemClock is a Clock backed by time.Now. It is a plain, ready-made
// implementation a caller can wire in explicitly — supplying it is still
// a deliberate choice, not an implicit fallback New applies on its own.
type SystemClock struct{}

// Now returns time.Now().
func (SystemClock) Now() time.Time { return time.Now() }

// ReadsSystemTime implements ClockAssurance: Now is time.Now.
func (SystemClock) ReadsSystemTime() bool { return true }
