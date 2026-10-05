package strictb64

import (
	"bytes"
	"testing"
)

func TestURL(t *testing.T) {
	for name, tc := range map[string]struct {
		in   string
		want []byte
		ok   bool
	}{
		"canonical":               {"_-8", []byte{0xff, 0xef}, true},
		"empty":                   {"", []byte{}, true},
		"non-zero trailing bits":  {"_-9", nil, false},
		"padding":                 {"_-8=", nil, false},
		"standard alphabet":       {"/+8", nil, false},
		"line feed":               {"_-\n8", nil, false},
		"carriage return":         {"_\r-8", nil, false},
		"impossible length":       {"_", nil, false},
		"three canonical bytes":   {"AQID", []byte{1, 2, 3}, true},
		"trailing bits, one byte": {"AR", nil, false},
		"canonical, one byte":     {"AQ", []byte{1}, true},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := URL(tc.in)
			if (err == nil) != tc.ok {
				t.Fatalf("URL(%q) error = %v, want ok = %v", tc.in, err, tc.ok)
			}
			if tc.ok && !bytes.Equal(got, tc.want) {
				t.Fatalf("URL(%q) = %x, want %x", tc.in, got, tc.want)
			}
		})
	}
}

func TestStd(t *testing.T) {
	for name, tc := range map[string]struct {
		in   string
		want []byte
		ok   bool
	}{
		"canonical":              {"/+8=", []byte{0xff, 0xef}, true},
		"non-zero trailing bits": {"/+9=", nil, false},
		"missing padding":        {"/+8", nil, false},
		"URL alphabet":           {"_-8=", nil, false},
		"line feed":              {"/+\n8=", nil, false},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := Std(tc.in)
			if (err == nil) != tc.ok {
				t.Fatalf("Std(%q) error = %v, want ok = %v", tc.in, err, tc.ok)
			}
			if tc.ok && !bytes.Equal(got, tc.want) {
				t.Fatalf("Std(%q) = %x, want %x", tc.in, got, tc.want)
			}
		})
	}
}
