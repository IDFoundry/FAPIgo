package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"unicode/utf8"

	"github.com/idfoundry/fapigo/internal/strictjson"
)

// validateClaimsParameter checks the "claims" request parameter (OIDC
// Core §5.5), when present: it must be a JSON object (or, as a plain
// form parameter, a string holding one) whose "id_token" and "userinfo"
// members, if present, map claim names to null or an object.
// parseRequestedClaimNames reads a malformed value as no claims at all,
// so without this a client that sent one would believe it requested
// claims it never did.
// Bounds on the "claims" parameter (OIDC Core §5.5), so parsing it stays
// cheap whatever a client sends. maxClaimsParameterBytes matches
// jose.DefaultMaxCompactBytes: a signed request object can't carry a
// larger claims parameter than that, so a plain-form one gets the same
// room. The counts are far above what any real request needs.
const (
	maxClaimsParameterBytes       = 16 << 10
	maxRequestedClaimsPerLocation = 256
	maxEssentialACRValues         = 32
)

func validateClaimsParameter(params map[string]json.RawMessage) error {
	raw, ok := params["claims"]
	if !ok {
		return nil
	}
	object, ok := claimsObject(raw)
	if !ok {
		return errors.New("claims must be a JSON object")
	}
	if len(object) > maxClaimsParameterBytes {
		return fmt.Errorf("claims must not exceed %d bytes", maxClaimsParameterBytes)
	}
	// encoding/json reads invalid UTF-8 and an unpaired surrogate escape
	// as U+FFFD, so a requested sub or acr would then match a value the
	// client never sent. Both raw and the object a string raw holds are
	// checked: an escape in the string ("\\ud800") only becomes one in
	// the object. Only the client's request is refused here, not a
	// stored request read again later.
	if !strictjson.DecodesLosslessly(raw) || !strictjson.DecodesLosslessly(object) {
		return errClaimsNotLossless
	}
	top, ok := claimsMembers(object)
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
		if err := validateClaimsLocationValue(member, value); err != nil {
			return err
		}
	}
	return nil
}

// errClaimsNotLossless refuses a "claims" parameter encoding/json
// wouldn't decode as written.
var errClaimsNotLossless = errors.New("claims must be valid UTF-8, without unpaired surrogate escapes")

// checkPlainClaimsParameter refuses a plain form "claims" value that
// isn't valid UTF-8. plainParamsToJSON's json.Marshal replaces invalid
// bytes with U+FFFD, so validateClaimsParameter, which sees only its
// result, can't tell; it checks escapes, which survive.
func checkPlainClaimsParameter(params map[string]string) error {
	if v, ok := params["claims"]; ok && !utf8.ValidString(v) {
		return errClaimsNotLossless
	}
	return nil
}

// validateClaimsLocationValue checks one present, non-null location
// member of the "claims" parameter ("id_token" or "userinfo"): it must
// be a JSON object mapping each claim name to null or an object.
func validateClaimsLocationValue(member string, value json.RawMessage) error {
	var requests map[string]json.RawMessage
	if trimmed := bytes.TrimSpace(value); len(trimmed) == 0 || trimmed[0] != '{' || json.Unmarshal(trimmed, &requests) != nil {
		return fmt.Errorf("claims.%s must be a JSON object", member)
	}
	if len(requests) > maxRequestedClaimsPerLocation {
		return fmt.Errorf("claims.%s must not request more than %d claims", member, maxRequestedClaimsPerLocation)
	}
	for name, request := range requests {
		if trimmed := bytes.TrimSpace(request); !isJSONNull(trimmed) && (len(trimmed) == 0 || trimmed[0] != '{') {
			return &detailedError{description: "claims." + member + " must map each claim name to null or a JSON object", detail: fmt.Sprintf("claim %q", name)}
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
	object, ok := claimsObject(raw)
	if !ok {
		return nil, false
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

// claimsObject returns the claims parameter's JSON text: raw itself, or
// the string it holds when it arrived as a form value.
func claimsObject(raw json.RawMessage) (json.RawMessage, bool) {
	object := bytes.TrimSpace(raw)
	if len(object) > 0 && object[0] == '"' {
		var s string
		if err := json.Unmarshal(object, &s); err != nil {
			return nil, false
		}
		object = bytes.TrimSpace([]byte(s))
	}
	return object, true
}

// checkMemberCase refuses a member of members that equals one of names
// under encoding/json's case folding but isn't spelled exactly, such as
// "ID_TOKEN" or "Essential": the parameter's members are case-sensitive,
// and such a member would otherwise be silently ignored.
func checkMemberCase(members map[string]json.RawMessage, where string, names ...string) error {
	for key := range members {
		for _, name := range names {
			if key != name && strictjson.FoldKey(key) == strictjson.FoldKey(name) {
				return &detailedError{description: where + " member " + name + " must be spelled in lowercase", detail: fmt.Sprintf("member %q", key)}
			}
		}
	}
	return nil
}
