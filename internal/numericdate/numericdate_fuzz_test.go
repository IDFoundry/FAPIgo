package numericdate

import (
	"bytes"
	"encoding/json"
	"math"
	"testing"
	"time"
)

// FuzzNumericDateParse checks Parse against encoding/json: an integer
// up to Max it decodes exactly as json.Unmarshal into an int64 does, so
// integer NumericDates keep their old meaning, and one after Max it
// refuses; anything else it accepts is a JSON number (or null), floored
// to within a second of its float64 value; and it never accepts a JSON
// string.
func FuzzNumericDateParse(f *testing.F) {
	for _, seed := range []string{
		"1700000000", "1700000000.75", "1.7e9", "-1.5", "null", `"1700000000"`,
		"9223372036854775807", "9223372036854775808", "1e400", "0.0", "-0", "{}",
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		got, err := Parse(raw)
		var asInt int64
		if json.Unmarshal(raw, &asInt) == nil && !bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			if asInt > Max {
				if err == nil {
					t.Fatalf("Parse(%q) = %d, after Max", raw, got)
				}
				return
			}
			if err != nil || got != asInt {
				t.Fatalf("Parse(%q) = %d, %v; json.Unmarshal into int64 gives %d", raw, got, err, asInt)
			}
			return
		}
		if err == nil {
			checkAccepted(t, raw, got)
		}
	})
}

// checkAccepted checks a value Parse accepted that isn't an int64: it's
// null, as 0, or a JSON number, floored to within a second of its
// float64 value. JSON has no NaN, so the comparison with 1<<53 is
// always defined.
func checkAccepted(t *testing.T, raw []byte, got int64) {
	t.Helper()
	var v any
	if json.Unmarshal(raw, &v) != nil {
		t.Fatalf("Parse accepted %q, which isn't JSON", raw)
	}
	switch n := v.(type) {
	case nil:
		if got != 0 {
			t.Fatalf("Parse(null) = %d, want 0", got)
		}
	case float64:
		if d := n - float64(got); d < 0 || d >= 1 && math.Abs(n) < 1<<53 {
			t.Fatalf("Parse(%q) = %d, not the floor of %v", raw, got, n)
		}
	default:
		t.Fatalf("Parse accepted %q, a JSON %T", raw, v)
	}
}

// FuzzNumericDateOrderPreserving: any value Parse accepts must, as a
// time.Time, compare with a fixed instant the same way the number
// compares with that instant's Unix seconds. Otherwise a far-future
// exp, nbf or iat would read as the past, or the reverse, in every
// caller.
func FuzzNumericDateOrderPreserving(f *testing.F) {
	for _, s := range []string{"0", "1800000000", "-1", "253402300799", "253402300800", "4611686018427387904", "9223372036854775807", "9.2e18", "-9223372036854775808"} {
		f.Add(s)
	}
	ref := time.Unix(1_800_000_000, 0)
	f.Fuzz(func(t *testing.T, raw string) {
		v, err := Parse([]byte(raw))
		if err != nil {
			return
		}
		ts := Value(v).Time()
		if (v > ref.Unix()) != ts.After(ref) || (v < ref.Unix()) != ts.Before(ref) || ts.Unix() != v {
			t.Fatalf("Parse(%s) = %d: as a time.Time %v, After(ref) = %v, but the number after ref is %v", raw, v, ts.UTC(), ts.After(ref), v > ref.Unix())
		}
	})
}
