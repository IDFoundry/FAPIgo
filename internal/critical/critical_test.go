package critical

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCheck(t *testing.T) {
	understood := map[string]bool{"ext": true, "ext2": true}
	for name, tc := range map[string]struct {
		raw     string
		wantErr string
	}{
		"absent":                      {"", ""},
		"understood extension":        {`["ext"]`, ""},
		"two understood":              {`["ext","ext2"]`, ""},
		"not understood":              {`["other"]`, "not understood"},
		"null":                        {`null`, "not null"},
		"empty":                       {`[]`, "must not be empty"},
		"not an array":                {`"ext"`, "array of names"},
		"array of non-strings":        {`[1]`, "array of names"},
		"duplicate":                   {`["ext","ext"]`, "listed twice"},
		"registered alg":              {`["alg"]`, "defined by the JOSE specifications"},
		"registered crit":             {`["crit"]`, "defined by the JOSE specifications"},
		"registered x5t#S256":         {`["x5t#S256"]`, "defined by the JOSE specifications"},
		"registered JWE enc":          {`["enc"]`, "defined by the JOSE specifications"},
		"registered after understood": {`["ext","kid"]`, "defined by the JOSE specifications"},
	} {
		t.Run(name, func(t *testing.T) {
			err := Check(json.RawMessage(tc.raw), understood)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("Check(%s) = %v, want nil", tc.raw, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("Check(%s) = %v, want error containing %q", tc.raw, err, tc.wantErr)
			}
		})
	}
}

// TestCheckRefusesEveryNameWithoutExtensions pins what both header
// parsers rely on: with no understood extensions, any "crit" at all is
// refused.
func TestCheckRefusesEveryNameWithoutExtensions(t *testing.T) {
	for _, raw := range []string{`["alg"]`, `["b64"]`, `["anything"]`} {
		if err := Check(json.RawMessage(raw), nil); err == nil {
			t.Fatalf("Check(%s, nil) = nil, want error", raw)
		}
	}
}
