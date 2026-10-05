// Package critical implements the "crit" (Critical) Header Parameter
// check RFC 7515 §4.1.11 (JWS) and RFC 7516 §4.1.13 (JWE, which
// inherits the JWS rule) both require: a header must be rejected if
// "crit" names a parameter the recipient doesn't actually understand
// and process — every other unrecognized member is ignored, never
// rejected (RFC 7515 §4.2/§4.3, RFC 7516 §4.2/§4.3). It also refuses a
// "crit" that breaks the rest of §4.1.11: one that isn't a non-empty
// array of strings (producers "MUST NOT use the empty list"), lists a
// name twice, or lists a parameter RFC 7515, RFC 7516 or RFC 7518
// defines (which recipients MAY treat as invalid; they are never
// extensions to be marked critical).
// Shared by internal/jose and internal/jwe rather than duplicated,
// since both header parsers apply the identical rule against their own
// set of understood extension parameter names.
package critical

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
)

// registered is every header parameter name RFC 7515 §4.1, RFC 7516
// §4.1 and RFC 7518 §4.6.1, §4.7.1 and §4.8.1 define for JWS or JWE.
var registered = map[string]bool{
	"alg": true, "jku": true, "jwk": true, "kid": true, "x5u": true,
	"x5c": true, "x5t": true, "x5t#S256": true, "typ": true, "cty": true,
	"crit": true, "enc": true, "zip": true, "epk": true, "apu": true,
	"apv": true, "iv": true, "tag": true, "p2s": true, "p2c": true,
}

// Check validates a header's raw "crit" member: nil when the member is
// absent (raw is empty), otherwise an error unless it is a non-empty
// array of distinct strings, none a registered parameter name, each in
// understood (the extension parameters the caller processes).
func Check(raw json.RawMessage, understood map[string]bool) error {
	if len(raw) == 0 {
		return nil
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return errors.New(`critical header parameter "crit" must be an array of names, not null`)
	}
	var names []string
	if err := json.Unmarshal(raw, &names); err != nil {
		return fmt.Errorf(`critical header parameter "crit" must be an array of names: %w`, err)
	}
	if len(names) == 0 {
		return errors.New(`critical header parameter "crit" must not be empty`)
	}
	seen := make(map[string]bool, len(names))
	for _, name := range names {
		if seen[name] {
			return fmt.Errorf("critical header parameter %q is listed twice", name)
		}
		seen[name] = true
		if registered[name] {
			return fmt.Errorf("critical header parameter %q is defined by the JOSE specifications, not an extension", name)
		}
		if !understood[name] {
			return fmt.Errorf("critical header parameter %q is not understood", name)
		}
	}
	return nil
}
