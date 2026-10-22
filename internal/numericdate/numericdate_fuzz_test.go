package numericdate

import (
	"bytes"
	"encoding/json"
	"math"
	"testing"
)

// FuzzNumericDateParse checks Parse against encoding/json: an integer it decodes
// exactly as json.Unmarshal into an int64 does, so integer NumericDates
// keep their old meaning; anything else it accepts is a JSON number (or
// null), floored to within a second of its float64 value; and it never
// accepts a JSON string.
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
