// Package numericdate decodes RFC 7519 §2 NumericDate claim values (exp,
// iat, nbf, auth_time) to whole seconds since the epoch.
//
// A NumericDate is "a JSON numeric value representing the number of
// seconds from 1970-01-01T00:00:00Z UTC until the specified UTC
// date/time", and RFC 7519 §2 notes it "can represent ... non-integer
// values". Every JWT this module verifies keeps decoding an integer as
// before; a non-integer one is floored to the second before it, rather
// than refused, so a sender that writes fractional seconds interoperates.
package numericdate

import (
	"bytes"
	"encoding/json"
	"errors"
	"math"
	"strconv"
	"time"
)

// ErrInvalid reports a value that isn't a JSON number, or one outside
// the range of whole seconds an int64 holds.
var ErrInvalid = errors.New("numericdate: not a JSON number within range")

// jsonSpace is the whitespace RFC 8259 §2 allows around a JSON value:
// narrower than bytes.TrimSpace's, which would let a form feed through.
const jsonSpace = " \t\n\r"

// twoTo63 is 2^63 exactly: a float64 at or above it, or below its
// negation, doesn't fit an int64.
const twoTo63 = 9223372036854775808.0

// Parse decodes raw, one JSON value, as a NumericDate in whole seconds.
// null decodes as present and zero, as json.Unmarshal into an int64
// does, so the callers' own zero-value handling stays as it was.
// A JSON string is refused even when it holds a number.
func Parse(raw []byte) (int64, error) {
	b := bytes.Trim(raw, jsonSpace)
	if bytes.Equal(b, []byte("null")) {
		return 0, nil
	}
	if len(b) == 0 || (b[0] != '-' && (b[0] < '0' || b[0] > '9')) {
		return 0, ErrInvalid
	}
	var n int64
	if json.Unmarshal(b, &n) == nil {
		return n, nil
	}
	var num json.Number
	if err := json.Unmarshal(b, &num); err != nil {
		return 0, ErrInvalid
	}
	f, err := strconv.ParseFloat(num.String(), 64)
	if err != nil || math.IsNaN(f) || f >= twoTo63 || f < -twoTo63 {
		return 0, ErrInvalid
	}
	return int64(math.Floor(f)), nil
}

// Value is a NumericDate claim field in whole seconds. It encodes as the
// integer it holds and decodes through Parse.
type Value int64

// Time is v as a time.Time.
func (v Value) Time() time.Time { return time.Unix(int64(v), 0) }

// UnmarshalJSON decodes data through Parse.
func (v *Value) UnmarshalJSON(data []byte) error {
	n, err := Parse(data)
	if err != nil {
		return err
	}
	*v = Value(n)
	return nil
}
