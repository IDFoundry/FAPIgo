package server

import (
	"encoding/json"
	"fmt"
	"unicode/utf8"

	"github.com/idfoundry/fapigo/internal/claimnames"
	"github.com/idfoundry/fapigo/internal/strictjson"
)

// isServerManagedIDTokenClaim reports whether name is a claim the server
// sets in an ID token itself or never lets an embedder-supplied value
// set there — GrantedAuthorization.IDTokenClaims or an
// IdentityClaimsSource's. The policy is internal/claimnames'
// (claimnames.Reserved for an ID token and claimnames.Embedder): the
// claims the server sets; the ones a relying party checks against its
// own expectations (azp, nonce, the hashes); the ones describing the
// token itself (jti, nbf, cnf); the ones that change how a relying
// party processes it (_claim_names, _claim_sources, sub_jwk, events);
// and the authorization response parameters code, state and error, by
// whose presence a relying party tells a JARM response from an ID
// token.
func isServerManagedIDTokenClaim(name string) bool {
	return claimnames.Reserved(claimnames.IDToken, claimnames.Embedder, name)
}

// validateGrantedIDTokenClaims checks GrantedAuthorization.IDTokenClaims
// before anything is persisted, so a bad claim is reported to the
// application that supplied it rather than failing ID token issuance
// later at the token endpoint. maxBytes is Limits.MaxIDTokenClaimsBytes:
// the application's own claims alone may not exceed the budget every
// non-standard ID token claim shares.
func validateGrantedIDTokenClaims(claims map[string]json.RawMessage, maxBytes int) error {
	if size := claimsSize(claims); size > maxBytes {
		return fmt.Errorf("ID token claims total %d bytes, over limits.max_id_token_claims_bytes (%d)", size, maxBytes)
	}
	for name, value := range claims {
		if name == "" {
			return fmt.Errorf("ID token claim name must not be empty")
		}
		if !utf8.ValidString(name) {
			return fmt.Errorf("ID token claim name %q is not valid UTF-8", name)
		}
		if isServerManagedIDTokenClaim(name) {
			return fmt.Errorf("ID token claim %q is managed by the server and must not be set", name)
		}
		if !json.Valid(value) {
			return fmt.Errorf("ID token claim %q is not valid JSON", name)
		}
		// Relying parties, this module's client included, refuse an ID
		// token whose claims aren't valid UTF-8 or carry a lone
		// surrogate escape (RFC 8725 §3.7), which json.Valid accepts.
		if !strictjson.DecodesLosslessly(value) {
			return fmt.Errorf("ID token claim %q is not valid UTF-8, or has an unpaired surrogate escape", name)
		}
	}
	return nil
}

// claimsSize is the size Limits.MaxIDTokenClaimsBytes measures: every
// claim name plus its encoded value.
func claimsSize(claims map[string]json.RawMessage) int {
	size := 0
	for name, value := range claims {
		size += len(name) + len(value)
	}
	return size
}
