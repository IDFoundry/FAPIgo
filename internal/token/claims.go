package token

import (
	"encoding/json"
	"fmt"
)

// popString extracts and deletes key from m, decoding it as a JSON
// string. If required and the key is absent, it returns
// ErrMalformedClaims.
func popString(m map[string]json.RawMessage, key string, required bool) (value string, present bool, err error) {
	raw, ok := m[key]
	if !ok {
		if required {
			return "", false, fmt.Errorf("%w: missing %q", ErrMalformedClaims, key)
		}
		return "", false, nil
	}
	delete(m, key)
	var s string
	if err := json.Unmarshal(raw, &s); err != nil || s == "" {
		return "", false, fmt.Errorf("%w: %q must be a non-empty string", ErrMalformedClaims, key)
	}
	return s, true, nil
}

// popInt64 extracts and deletes key from m, decoding it as a JSON
// number. If required and the key is absent, it returns
// ErrMalformedClaims.
func popInt64(m map[string]json.RawMessage, key string, required bool) (value int64, present bool, err error) {
	raw, ok := m[key]
	if !ok {
		if required {
			return 0, false, fmt.Errorf("%w: missing %q", ErrMalformedClaims, key)
		}
		return 0, false, nil
	}
	delete(m, key)
	var n int64
	if err := json.Unmarshal(raw, &n); err != nil {
		return 0, false, fmt.Errorf("%w: %q must be an integer", ErrMalformedClaims, key)
	}
	return n, true, nil
}

// popStringSlice extracts and deletes key from m, decoding it as a JSON
// array of strings.
func popStringSlice(m map[string]json.RawMessage, key string) (value []string, present bool, err error) {
	raw, ok := m[key]
	if !ok {
		return nil, false, nil
	}
	delete(m, key)
	var s []string
	if err := json.Unmarshal(raw, &s); err != nil || len(s) == 0 {
		return nil, false, fmt.Errorf("%w: %q must be a non-empty array of strings", ErrMalformedClaims, key)
	}
	return s, true, nil
}
