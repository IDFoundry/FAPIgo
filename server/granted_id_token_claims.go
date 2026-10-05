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
//   - ones a relying party validates against its own expectations: azp
//     (OIDC Core §3.1.3.7), and c_hash/s_hash, the hybrid-flow hashes of
//     the code and state (§3.3.2.11, FAPI 1.0 Advanced §5.2.2.1), which
//     this server never issues but a relying party supporting that flow
//     would check;
//   - ones that describe the token itself (jti, nbf, cnf) rather than
//     the authenticated subject;
//   - ones that change how a relying party processes the token: the
//     aggregated and distributed claims references _claim_names and
//     _claim_sources (§5.6.2), which send a relying party to fetch or
//     trust claims from elsewhere, and sub_jwk, the key a self-issued ID
//     token is verified with (§7.4);
//   - events, the claim that marks a Security Event Token (RFC 8417),
//     such as a Back-Channel Logout token (OpenID Connect Back-Channel
//     Logout 1.0 §2.4): an ID token re-issued without a nonce that
//     carried it would look like a logout token to a relying party
//     that doesn't check the token type.
var reservedIDTokenClaims = []string{
	"azp", "c_hash", "s_hash", "jti", "nbf", "cnf",
	"_claim_names", "_claim_sources", "sub_jwk", "events",
}

// isServerManagedIDTokenClaim reports whether name is a claim the server
// sets in an ID token itself or never lets anything else set there.
func isServerManagedIDTokenClaim(name string) bool {
	return token.IsIDTokenReservedClaim(name) || slices.Contains(reservedIDTokenClaims, name)
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
