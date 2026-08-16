package server

import (
	"context"
	"encoding/json"
)

// IdentityClaimsSource resolves a subject's identity claim values (OIDC
// Core §5.1, e.g. "name", "email") for embedding in an ID token or
// returning from a UserInfo endpoint. It is optional — Dependencies.
// IdentityClaims may be left nil — because this package takes no
// position on where claim values come from, or whether a deployment
// supports them at all; a nil source simply means the "claims" request
// parameter (OIDC Core §5.5) is accepted but has no effect on what a
// token contains.
type IdentityClaimsSource interface {
	// ResolveIdentityClaims returns identity claim values for subject,
	// restricted to names — a claim not in names must not appear in the
	// result, even if this source has a value for it. names is never
	// empty when this method is called (callers skip the call entirely
	// when nothing was requested), so an empty result here means "no
	// value for any of these", not "return everything". Each value is
	// already JSON-encoded. A name this source has no value for is
	// simply absent from the result — that is not an error condition.
	ResolveIdentityClaims(ctx context.Context, subject string, names []string) (map[string]json.RawMessage, error)
}

// RequestedUserinfoClaimsKey is the access-token claim name this
// package embeds the OIDC Core §5.5 "claims" parameter's userinfo-scoped
// claim names under, when both IdentityClaims is configured and the
// authorization request asked for at least one userinfo claim. This
// package doesn't implement a UserInfo endpoint itself (see
// IdentityClaimsSource's doc comment — that's left to the embedder), so
// an embedder's own UserInfo handler needs this to know which claims
// were actually requested: unlike the ID token (issued once, at the
// same time the request is known), a UserInfo call is a wholly separate
// later request carrying only the access token, with no other link back
// to what was originally asked for.
const RequestedUserinfoClaimsKey = "requested_userinfo_claims"

// requestedClaimsParameter is the OIDC Core §5.5 "claims" request
// parameter's shape, trimmed to the one thing this package acts on:
// which claim names were asked for, per delivery location. Everything
// else about each entry (essential/value/values) is intentionally
// ignored — OIDC Core §5.5 permits a server to honor as much or as
// little of a claims request as it wants; this package's contract is
// simply "never return what wasn't asked for", not "honor every nuance
// of the request".
type requestedClaimsParameter struct {
	UserInfo map[string]json.RawMessage `json:"userinfo"`
	IDToken  map[string]json.RawMessage `json:"id_token"`
}

// parseRequestedClaimNames extracts the claim names requested for each
// delivery location from raw (the "claims" parameter's raw JSON value,
// or empty if absent). Malformed input yields no requested claims
// rather than an error — "claims" is optional convenience data (OIDC
// Core §5.5), never something that should block an otherwise-valid
// authorization.
//
// raw arrives in one of two shapes depending on how the authorization
// request was made: a signed request object carries "claims" as a
// genuine nested JSON object, but resolveAuthorizationParameters's
// plain-parameter path (par.go's plainParamsToJSON) JSON-encodes every
// form value as a string — form parameters are strings on the wire, and
// that function doesn't special-case this one — so a plain "claims"
// parameter arrives here as a JSON string *containing* the object, not
// the object itself. Both are handled.
func parseRequestedClaimNames(raw json.RawMessage) (idToken, userinfo []string) {
	if len(raw) == 0 {
		return nil, nil
	}
	var parsed requestedClaimsParameter
	if err := json.Unmarshal(raw, &parsed); err == nil {
		return claimNames(parsed.IDToken), claimNames(parsed.UserInfo)
	}
	var asString string
	if err := json.Unmarshal(raw, &asString); err != nil {
		return nil, nil
	}
	if err := json.Unmarshal([]byte(asString), &parsed); err != nil {
		return nil, nil
	}
	return claimNames(parsed.IDToken), claimNames(parsed.UserInfo)
}

func claimNames(m map[string]json.RawMessage) []string {
	if len(m) == 0 {
		return nil
	}
	names := make([]string, 0, len(m))
	for name := range m {
		names = append(names, name)
	}
	return names
}
