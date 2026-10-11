package timeutil

import (
	"math"
	"testing"
	"time"
)

func TestSaturatingAdd(t *testing.T) {
	const largest = time.Duration(math.MaxInt64)
	for _, tc := range []struct {
		name string
		in   []time.Duration
		want time.Duration
	}{
		{"none", nil, 0},
		{"ordinary", []time.Duration{time.Minute, 10 * time.Second, 10 * time.Second}, time.Minute + 20*time.Second},
		{"exactly the largest", []time.Duration{largest - time.Second, time.Second}, largest},
		{"one past the largest", []time.Duration{largest - time.Second, time.Second, 1}, largest},
		{"two huge skews", []time.Duration{time.Minute, largest / 2, largest / 2}, largest},
		{"largest then more", []time.Duration{largest, largest}, largest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := SaturatingAdd(tc.in...); got != tc.want {
				t.Fatalf("SaturatingAdd(%v) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}
