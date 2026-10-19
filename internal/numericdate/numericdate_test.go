package numericdate

import (
	"encoding/json"
	"errors"
	"math"
	"testing"
)

func TestParse(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want int64
	}{
		{"1700000000", 1700000000},
		{" 1700000000 ", 1700000000},
		{"0", 0},
		{"-5", -5},
		{"null", 0},
		{"1700000000.75", 1700000000},
		{"1700000000.0", 1700000000},
		{"1.7e9", 1700000000},
		{"1.7E+9", 1700000000},
		{"-1.5", -2},
		{"9223372036854775807", math.MaxInt64},
		{"-9223372036854775808", math.MinInt64},
		{"-9223372036854775808.0", math.MinInt64},
	} {
		got, err := Parse([]byte(tc.raw))
		if err != nil || got != tc.want {
			t.Errorf("Parse(%s) = %d, %v; want %d", tc.raw, got, err, tc.want)
		}
	}
}

func TestParseRefuses(t *testing.T) {
	for _, raw := range []string{
		``, ` `, "0\f", "\v1", `"1700000000"`, `"1.5"`, `true`, `{}`, `[1]`, `01`, `1.`, `.5`, `-`, `+1`,
		`NaN`, `Infinity`, `9223372036854775808`, `1e19`, `-1e19`, `1e400`, `1700000000x`,
	} {
		if got, err := Parse([]byte(raw)); !errors.Is(err, ErrInvalid) {
			t.Errorf("Parse(%q) = %d, %v; want ErrInvalid", raw, got, err)
		}
	}
}

func TestValue(t *testing.T) {
	var c struct {
		Exp Value `json:"exp"`
		Iat Value `json:"iat,omitempty"`
	}
	if err := json.Unmarshal([]byte(`{"exp":1700000000.5,"iat":null}`), &c); err != nil {
		t.Fatal(err)
	}
	if c.Exp != 1700000000 || c.Iat != 0 {
		t.Errorf("decoded %+v", c)
	}
	if err := json.Unmarshal([]byte(`{"exp":"1700000000"}`), &c); err == nil {
		t.Error("a string exp decoded")
	}
	out, err := json.Marshal(struct {
		Exp Value `json:"exp"`
	}{1700000000})
	if err != nil || string(out) != `{"exp":1700000000}` {
		t.Errorf("Marshal = %s, %v", out, err)
	}
}
