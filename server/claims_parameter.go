package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
)

// validateClaimsParameter checks the "claims" request parameter (OIDC
// Core §5.5), when present: it must be a JSON object (or, as a plain
// form parameter, a string holding one) whose "id_token" and "userinfo"
// members, if present, map claim names to null or an object.
// parseRequestedClaimNames reads a malformed value as no claims at all,
// so without this a client that sent one would believe it requested
// claims it never did.
func validateClaimsParameter(params map[string]json.RawMessage) error {
	raw, ok := params["claims"]
	if !ok {
		return nil
	}
	object := bytes.TrimSpace(raw)
	if len(object) > 0 && object[0] == '"' {
		var s string
		if err := json.Unmarshal(object, &s); err != nil {
			return errors.New("claims must be a JSON object")
		}
		object = bytes.TrimSpace([]byte(s))
	}
	var top map[string]json.RawMessage
	if len(object) == 0 || object[0] != '{' || json.Unmarshal(object, &top) != nil {
		return errors.New("claims must be a JSON object")
	}
	for _, member := range []string{"id_token", "userinfo"} {
		value, ok := top[member]
		if !ok || isJSONNull(value) {
			continue
		}
		var requests map[string]json.RawMessage
		if trimmed := bytes.TrimSpace(value); len(trimmed) == 0 || trimmed[0] != '{' || json.Unmarshal(trimmed, &requests) != nil {
			return fmt.Errorf("claims.%s must be a JSON object", member)
		}
		for name, request := range requests {
			if trimmed := bytes.TrimSpace(request); !isJSONNull(trimmed) && (len(trimmed) == 0 || trimmed[0] != '{') {
				return fmt.Errorf("claims.%s.%s must be null or a JSON object", member, name)
			}
		}
	}
	return nil
}

func isJSONNull(raw json.RawMessage) bool {
	return bytes.Equal(bytes.TrimSpace(raw), []byte("null"))
}
