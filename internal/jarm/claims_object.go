package jarm

import (
	"encoding/json"
	"fmt"

	"github.com/idfoundry/fapigo/internal/strictjson"
)

// decodeClaimsObject decodes payload, a JWT's claims set, as a JSON
// object, refusing one that repeats a member name, at any depth, with
// copies that differ, or holds two names that differ only in case
// (strictjson.CheckConflictingMembers): RFC 7519 §4 requires unique
// claim names, and encoding/json keeps the last copy of a repeated one,
// where another reader of the same JWT may keep the first. A repeat
// whose copies are identical is accepted, since every reader takes the
// same value from it.
func decodeClaimsObject(payload []byte) (map[string]json.RawMessage, error) {
	if err := strictjson.CheckConflictingMembers(payload); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformedClaims, err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(payload, &raw); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformedClaims, err)
	}
	return raw, nil
}
