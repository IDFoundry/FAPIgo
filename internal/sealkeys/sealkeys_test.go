package sealkeys

import (
	"bytes"
	"strings"
	"testing"
)

func key(seed byte) []byte {
	k := make([]byte, Size)
	for i := range k {
		k[i] = seed + byte(i)
	}
	return k
}

func TestCheck(t *testing.T) {
	almost := bytes.Repeat([]byte{7}, Size)
	almost[Size-1] = 8
	for name, tc := range map[string]struct {
		keys    [][]byte
		wantErr string
	}{
		"one key":             {[][]byte{key(1)}, ""},
		"two keys":            {[][]byte{key(1), key(2)}, ""},
		"one byte differs":    {[][]byte{almost}, ""},
		"none":                {nil, "at least one key"},
		"short":               {[][]byte{key(1)[:31]}, "key 0 is 31 bytes"},
		"long":                {[][]byte{append(key(1), 0)}, "key 0 is 33 bytes"},
		"all zero":            {[][]byte{make([]byte, Size)}, "key 0 is one byte repeated"},
		"repeated byte later": {[][]byte{key(1), bytes.Repeat([]byte{0xab}, Size)}, "key 1 is one byte repeated"},
		"duplicate":           {[][]byte{key(1), key(2), key(1)}, "key 2 repeats key 0"},
	} {
		t.Run(name, func(t *testing.T) {
			err := Check("test", tc.keys)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("Check: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) || !strings.HasPrefix(err.Error(), "test: ") {
				t.Fatalf("Check error = %v, want one containing %q", err, tc.wantErr)
			}
		})
	}
}
