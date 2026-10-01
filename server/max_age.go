package server

import (
	"encoding/json"
	"errors"
	"math"
	"strconv"
	"strings"
	"time"
)

// maxMaxAge bounds "max_age" so a value converts to a time.Duration
// without overflowing.
const maxMaxAge = math.MaxInt64 / int64(time.Second)

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
