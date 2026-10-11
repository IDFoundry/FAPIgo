// Package timeutil holds the duration arithmetic the packages that size
// replay and revocation records share.
package timeutil

import (
	"math"
	"time"
)

// SaturatingAdd returns the sum of durations, capped at the largest
// Duration instead of wrapping round to a negative one. A record sized
// from configured lifetimes and skews, however absurdly long, then
// outlasts them rather than having already expired.
func SaturatingAdd(durations ...time.Duration) time.Duration {
	var sum time.Duration
	for _, d := range durations {
		if d > 0 && sum > math.MaxInt64-d {
			return math.MaxInt64
		}
		sum += d
	}
	return sum
}
