// Package claimnames is the one reserved-claim-name policy for every
// JWT this library issues whose claims a caller contributes to: ID
// tokens, JWT access tokens and signed UserInfo responses.
//
// Which names are reserved depends on two things: the kind of JWT, and
// who chose the value.
//
//   - The issuer: each issuing function sets some claims itself (iss,
//     aud and so on, see setByIssuer). Nobody else may set them.
//   - Embedder: values the application embedding the server supplies
//     itself — GrantedAuthorization.IDTokenClaims, an
//     IdentityClaimsSource's values, the claims passed to
//     SignUserInfoResponse, or the Claims a custom AccessTokenIssuer
//     adds before calling JWTAccessTokens. On top of the issuer's own
//     claims, these must not use a name that changes how a recipient
//     processes the JWT rather than describing its subject (see
//     processingClaims), nor, in an ID token or UserInfo response, a
//     name that makes it look like another kind of response (see
//     idTokenBindingClaims and authorizationResponseClaims).
//   - Client: values a client chose, which reach tokens through
//     extension parameters registered with ReturnInTokenClaims. These
//     additionally must not use a name whose meaning a recipient takes
//     from the authorization server or the resource owner: the
//     authorization attributes of RFC 9068 §2.2.3.1 (roles, groups,
//     entitlements), the delegation claims of RFC 8693 §4.1/§4.4 (act,
//     may_act), the OIDC Core §5.1 standard claims, and RFC 9396's
//     authorization_details. The embedder may set the authorization
//     attributes and delegation claims itself — they are its decision
//     to make — but a client never may.
package claimnames

import "slices"

// Kind is the kind of JWT a claim is destined for.
type Kind uint8

const (
	// IDToken is an OpenID Connect ID token.
	IDToken Kind = iota + 1
	// AccessToken is an RFC 9068 JWT access token.
	AccessToken
	// UserInfo is a signed UserInfo response (OIDC Core §5.3.2).
	UserInfo
)

// Source is who chose a claim's value.
type Source uint8

const (
	// Embedder is the application embedding the server.
	Embedder Source = iota + 1
	// Client is a client of the authorization server.
	Client
)

// setByIssuer are the claims each issuing function sets itself.
var setByIssuer = map[Kind][]string{
	IDToken:     {"iss", "sub", "aud", "exp", "iat", "nonce", "auth_time", "acr", "amr", "at_hash"},
	AccessToken: {"iss", "sub", "aud", "client_id", "scope", "exp", "iat", "jti", "cnf"},
	UserInfo:    {"iss", "aud"},
}

// processingClaims change how a recipient processes a JWT, whatever its
// kind: the aggregated and distributed claims references _claim_names
// and _claim_sources (OIDC Core §5.6.2), which send a recipient to
// fetch or trust claims from elsewhere; sub_jwk, the key a self-issued
// ID token is verified with (§7.4); and events, the claim that marks a
// Security Event Token (RFC 8417) such as a Back-Channel Logout token
// (OpenID Connect Back-Channel Logout 1.0 §2.4).
var processingClaims = []string{"_claim_names", "_claim_sources", "sub_jwk", "events"}

// idTokenBindingClaims are the ID token claims a relying party checks
// against its own expectations (OIDC Core §3.1.3.7, §3.3.2.11): azp,
// the nonce and the hybrid-flow hashes, which this server never issues
// but a relying party supporting that flow would check.
var idTokenBindingClaims = []string{"azp", "nonce", "at_hash", "c_hash", "s_hash"}

// tokenMetadataClaims describe the JWT itself rather than its subject.
var tokenMetadataClaims = []string{"jti", "nbf", "cnf"}

// authorizationResponseClaims are the authorization response parameters
// a JARM response carries as claims (JARM §2.1). A relying party tells
// a JARM response from another JWT of the same issuer and audience
// largely by which of these it carries, so an ID token or UserInfo
// response must never carry one.
var authorizationResponseClaims = []string{"code", "state", "error"}

// authorityClaims are claims whose meaning a recipient takes from the
// authorization server: RFC 9068 §2.2.3.1's authorization attributes,
// RFC 8693's delegation claims and RFC 9396's authorization_details.
var authorityClaims = []string{"roles", "groups", "entitlements", "act", "may_act", "authorization_details"}

// standardClaims are the OIDC Core §5.1 standard claims, which only the
// resource owner's identity source supplies.
var standardClaims = []string{
	"name", "given_name", "family_name", "middle_name", "nickname",
	"preferred_username", "profile", "picture", "website", "email",
	"email_verified", "gender", "birthdate", "zoneinfo", "locale",
	"phone_number", "phone_number_verified", "address", "updated_at",
}

// Reserved reports whether a value source chose must not appear in a
// JWT of kind under name.
func Reserved(kind Kind, source Source, name string) bool {
	if slices.Contains(setByIssuer[kind], name) || slices.Contains(processingClaims, name) {
		return true
	}
	switch kind {
	case IDToken:
		if slices.Contains(idTokenBindingClaims, name) || slices.Contains(tokenMetadataClaims, name) ||
			slices.Contains(authorizationResponseClaims, name) {
			return true
		}
	case UserInfo:
		if slices.Contains(idTokenBindingClaims, name) || slices.Contains(authorizationResponseClaims, name) {
			return true
		}
	}
	return source == Client && (slices.Contains(authorityClaims, name) || slices.Contains(standardClaims, name))
}

// ReservedInTokens reports whether name is Reserved, for source, in
// either an ID token or an access token — the check for a value copied
// into both, as an extension parameter's is.
func ReservedInTokens(source Source, name string) bool {
	return Reserved(IDToken, source, name) || Reserved(AccessToken, source, name)
}
