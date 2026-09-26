package server

import (
	"encoding/json"
	"fmt"
	"slices"
	"unicode/utf8"

	"github.com/idfoundry/fapigo/internal/token"
)

// reservedIDTokenClaims are claim names GrantedAuthorization.IDTokenClaims
// must not set beyond those token.IsIDTokenReservedClaim already covers:
// ones a relying party validates against its own expectations (azp,
// OIDC Core §3.1.3.7) or that describe the token itself (jti, nbf, cnf)
// rather than the authenticated subject.
var reservedIDTokenClaims = []string{"azp", "jti", "nbf", "cnf"}

// validateGrantedIDTokenClaims checks GrantedAuthorization.IDTokenClaims
// before anything is persisted, so a bad claim is reported to the
// application that supplied it rather than failing ID token issuance
// later at the token endpoint.
func validateGrantedIDTokenClaims(claims map[string]json.RawMessage) error {
	for name, value := range claims {
		if name == "" {
			return fmt.Errorf("ID token claim name must not be empty")
		}
		if !utf8.ValidString(name) {
			return fmt.Errorf("ID token claim name %q is not valid UTF-8", name)
		}
		if token.IsIDTokenReservedClaim(name) || slices.Contains(reservedIDTokenClaims, name) {
			return fmt.Errorf("ID token claim %q is managed by the server and must not be set", name)
		}
		if !json.Valid(value) {
			return fmt.Errorf("ID token claim %q is not valid JSON", name)
		}
	}
	return nil
}
