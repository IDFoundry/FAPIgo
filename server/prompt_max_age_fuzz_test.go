package server

import (
	"encoding/json"
	"testing"
)

// FuzzRequestedPromptAndMaxAge: the prompt and max_age readers never
// panic, a prompt with none never carries another value, and an
// accepted max_age is never negative.
func FuzzRequestedPromptAndMaxAge(f *testing.F) {
	for _, s := range []string{`"login"`, `"none login"`, `"none"`, `"consent select_account"`, `5`, `"5"`, `-1`, `1e9`, `9223372036854775807`, `1.5`, `"  "`} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		if !json.Valid([]byte(raw)) {
			return
		}
		params := map[string]json.RawMessage{"prompt": json.RawMessage(raw), "max_age": json.RawMessage(raw)}
		if p, err := requestedPrompt(params); err == nil && p.Has(PromptNone) && len(p) > 1 {
			t.Fatalf("prompt %q accepted with none and another value: %v", raw, p)
		}
		if d, ok, err := requestedMaxAge(params); err == nil && ok && d < 0 {
			t.Fatalf("max_age %q accepted as negative duration %v", raw, d)
		}
	})
}
