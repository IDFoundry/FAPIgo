package federation

import "time"

// Clock supplies the current time. There is no implicit default —
// Dependencies.Clock must always be set explicitly, even to SystemClock.
type Clock interface {
	Now() time.Time
}

// SystemClock is a Clock backed by time.Now.
type SystemClock struct{}

// Now returns time.Now().
func (SystemClock) Now() time.Time { return time.Now() }
