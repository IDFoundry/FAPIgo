package server

import (
	"encoding/json"
	"errors"
	"slices"
)

// essentialACRValues reads an essential "acr" request for the ID token
// from the "claims" parameter (OIDC Core §5.5.1.1): the Authentication
// Context Class References the authentication must have used one of,
// in the order given. It returns nil when the request makes no such
// demand — no "claims", no id_token "acr" entry, or one that isn't
// essential or names no value — and an error for an "acr" entry that
// is malformed, so the request can be refused rather than silently
// treated as asking for nothing.
//
// A non-essential "acr" entry, like "acr_values", is the client's
// preference only (OIDC Core §5.5.1.1), surfaced through ACRValues and
// never enforced.
//
// raw arrives either as a nested JSON object (a request object) or as
// a JSON string containing one (plain parameters; see
// parseRequestedClaimNames). A "claims" value that is neither is left
// to the claims parameter's own handling.
func essentialACRValues(params map[string]json.RawMessage) ([]string, error) {
	entry, err := idTokenACREntry(params)
	if entry == nil || err != nil {
		return nil, err
	}
	essential, err := acrEntryEssential(entry)
	if err != nil {
		return nil, err
	}
	values, err := acrEntryValues(entry)
	if err != nil {
		return nil, err
	}
	if !essential || len(values) == 0 {
		return nil, nil
	}
	return dedupeStrings(values), nil
}

// idTokenACREntry returns the "claims" parameter's id_token "acr" entry
// with its member names checked: nil, with no error, when there is no
// such entry or it's null.
func idTokenACREntry(params map[string]json.RawMessage) (map[string]json.RawMessage, error) {
	idToken, ok := claimsIDTokenMembers(params["claims"])
	if !ok {
		return nil, nil
	}
	raw, present := idToken["acr"]
	if !present || string(raw) == "null" {
		return nil, nil
	}
	var entry map[string]json.RawMessage
	if err := json.Unmarshal(raw, &entry); err != nil || entry == nil {
		return nil, errors.New(`claims: the id_token "acr" entry must be a JSON object or null`)
	}
	if err := checkMemberCase(entry, `claims: the id_token "acr" entry's`, "essential", "value", "values"); err != nil {
		return nil, err
	}
	return entry, nil
}

// acrEntryEssential reads the "acr" entry's "essential" member, false
// when absent.
func acrEntryEssential(entry map[string]json.RawMessage) (bool, error) {
	essential := false
	if v, ok := entry["essential"]; ok {
		if err := json.Unmarshal(v, &essential); err != nil {
			return false, errors.New(`claims: the id_token "acr" entry's "essential" must be a boolean`)
		}
	}
	return essential, nil
}

// acrEntryValues reads the "acr" entry's "value" and then "values"
// members, in that order.
func acrEntryValues(entry map[string]json.RawMessage) ([]string, error) {
	var values []string
	if v, ok := entry["value"]; ok {
		var value string
		if err := json.Unmarshal(v, &value); err != nil || value == "" {
			return nil, errors.New(`claims: the id_token "acr" entry's "value" must be a non-empty string`)
		}
		values = append(values, value)
	}
	if v, ok := entry["values"]; ok {
		var list []string
		if err := json.Unmarshal(v, &list); err != nil || len(list) == 0 || slices.Contains(list, "") {
			return nil, errors.New(`claims: the id_token "acr" entry's "values" must be a non-empty array of non-empty strings`)
		}
		values = append(values, list...)
	}
	return values, nil
}

// dedupeStrings returns values without repeats, in first-seen order.
func dedupeStrings(values []string) []string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		if !slices.Contains(out, v) {
			out = append(out, v)
		}
	}
	return out
}

// claimsIDTokenMembers returns the "claims" parameter's id_token
// member entries, accepting the parameter as a JSON object or as a JSON
// string containing one. ok is false when there is no such object.
func claimsIDTokenMembers(raw json.RawMessage) (map[string]json.RawMessage, bool) {
	top, ok := claimsMembers(raw)
	if !ok {
		return nil, false
	}
	idToken := claimsLocation(top, "id_token")
	return idToken, idToken != nil
}

// meetsEssentialACR reports whether acr satisfies required, the
// essential "acr" values a request recorded (see essentialACRValues):
// always, when it recorded none.
func meetsEssentialACR(required []string, acr string) bool {
	return len(required) == 0 || slices.Contains(required, acr)
}
