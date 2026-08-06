package client

import "time"

// Clock supplies the current time. There is no implicit default —
// Dependencies.Clock must always be set explicitly, even to SystemClock.
type Clock interface {
	Now() time.Time
}

// SystemClock is a Clock backed by time.Now. It is a plain, ready-made
// implementation a caller can wire in explicitly — supplying it is still
// a deliberate choice, not an implicit fallback New applies on its own.
type SystemClock struct{}

// Now returns time.Now().
func (SystemClock) Now() time.Time { return time.Now() }
