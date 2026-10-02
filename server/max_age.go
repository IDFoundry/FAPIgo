package server

import (
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"
)

// maxMaxAge bounds "max_age" at 100 years: far beyond any real policy,
// and small enough that the value as a time.Duration, less
// Limits.MaxClockSkew, never overflows.
const maxMaxAge = 100 * 366 * 24 * 60 * 60

// requestedMaxAge parses the authorization request's "max_age" (OIDC Core
// §3.1.2.1): a non-negative whole number of seconds. It arrives as a JSON
// number in a signed request object, and as a JSON string from plain form
// parameters (see plainParamsToJSON). ok is false when the request has
// none.
func requestedMaxAge(params map[string]json.RawMessage) (maxAge time.Duration, ok bool, err error) {
	raw, present := params["max_age"]
	if !present {
		return 0, false, nil
	}
	text := strings.TrimSpace(string(raw))
	if strings.HasPrefix(text, `"`) {
		if err := json.Unmarshal(raw, &text); err != nil {
			return 0, false, err
		}
	}
	seconds, err := strconv.ParseInt(text, 10, 64)
	if err != nil {
		return 0, false, errors.New("max_age must be a whole number of seconds")
	}
	if seconds < 0 || seconds > maxMaxAge {
		return 0, false, errors.New("max_age is out of range")
	}
	return time.Duration(seconds) * time.Second, true, nil
}

// requestedACRValues is the authorization request's "acr_values" (OIDC
// Core §3.1.2.1), most preferred first.
func requestedACRValues(params map[string]json.RawMessage) []string {
	v, err := jsonString(params, "acr_values")
	if err != nil {
		return nil
	}
	return strings.Fields(v)
}
