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

// popStringOrStringSlice extracts and deletes key from m, accepting
// either form RFC 7519 §4.1.3 permits for "aud": a single JSON string,
// or a JSON array of one or more non-empty strings. Both forms
// normalize to this slice. It is required — a token missing "aud"
// entirely is malformed either way.
func popStringOrStringSlice(m map[string]json.RawMessage, key string) ([]string, error) {
	raw, ok := m[key]
	if !ok {
		return nil, fmt.Errorf("%w: missing %q", ErrMalformedClaims, key)
	}
	delete(m, key)

	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		if s == "" {
			return nil, fmt.Errorf("%w: %q must be a non-empty string", ErrMalformedClaims, key)
		}
		return []string{s}, nil
	}

	var arr []string
	if err := json.Unmarshal(raw, &arr); err != nil || len(arr) == 0 {
		return nil, fmt.Errorf("%w: %q must be a non-empty string or a non-empty array of strings", ErrMalformedClaims, key)
	}
	for _, v := range arr {
		if v == "" {
			return nil, fmt.Errorf("%w: %q must not contain an empty string", ErrMalformedClaims, key)
		}
	}
	return arr, nil
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
