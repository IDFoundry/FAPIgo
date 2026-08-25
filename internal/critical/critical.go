// Package critical implements the "crit" (Critical) Header Parameter
// check RFC 7515 §4.1.11 (JWS) and RFC 7516 §4.1.13 (JWE, which
// inherits the JWS rule) both require: a header must be rejected only
// if "crit" names a parameter the recipient doesn't actually
// understand and process — every other unrecognized member is
// ignored, never rejected (RFC 7515 §4.2/§4.3, RFC 7516 §4.2/§4.3).
// Shared by internal/jose and internal/jwe rather than duplicated,
// since both header parsers apply the identical rule against their own
// (differently shaped) set of understood parameter names.
package critical

import "fmt"

// Check returns an error if crit names any parameter not in
// understood; nil otherwise, including when crit is empty.
func Check(crit []string, understood map[string]bool) error {
	for _, name := range crit {
		if !understood[name] {
			return fmt.Errorf("critical header parameter %q is not understood", name)
		}
	}
	return nil
}
