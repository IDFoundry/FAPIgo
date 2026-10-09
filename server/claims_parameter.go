package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/idfoundry/fapigo/internal/strictjson"
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
	top, ok := claimsMembers(raw)
	if !ok {
		return errors.New("claims must be a JSON object")
	}
	if err := checkMemberCase(top, "claims", "id_token", "userinfo"); err != nil {
		return err
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

// claimsMembers decodes the "claims" parameter's raw value (a JSON
// object, or, as a plain form parameter, a string holding one) into its
// top-level members, keyed exactly as sent. ok is false when it isn't an
// object. Every reader of the parameter goes through this, so they all
// see the same members: decoding into a struct instead would match
// "ID_TOKEN" to "id_token" the way encoding/json folds case, while
// validation, reading exact keys, wouldn't.
func claimsMembers(raw json.RawMessage) (map[string]json.RawMessage, bool) {
	object := bytes.TrimSpace(raw)
	if len(object) > 0 && object[0] == '"' {
		var s string
		if err := json.Unmarshal(object, &s); err != nil {
			return nil, false
		}
		object = bytes.TrimSpace([]byte(s))
	}
	var top map[string]json.RawMessage
	if len(object) == 0 || object[0] != '{' || json.Unmarshal(object, &top) != nil {
		return nil, false
	}
	return top, true
}

// claimsLocation returns the claim requests under location ("id_token"
// or "userinfo") in top, keyed exactly as sent: nil when it's absent,
// null or not an object.
func claimsLocation(top map[string]json.RawMessage, location string) map[string]json.RawMessage {
	value, ok := top[location]
	if !ok || isJSONNull(value) {
		return nil
	}
	var requests map[string]json.RawMessage
	if json.Unmarshal(value, &requests) != nil {
		return nil
	}
	return requests
}

// checkMemberCase refuses a member of members that equals one of names
// under encoding/json's case folding but isn't spelled exactly, such as
// "ID_TOKEN" or "Essential": the parameter's members are case-sensitive,
// and such a member would otherwise be silently ignored.
func checkMemberCase(members map[string]json.RawMessage, where string, names ...string) error {
	for key := range members {
		for _, name := range names {
			if key != name && strictjson.FoldKey(key) == strictjson.FoldKey(name) {
				return fmt.Errorf("%s member %q must be spelled %q", where, key, name)
			}
		}
	}
	return nil
}
