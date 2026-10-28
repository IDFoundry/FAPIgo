package server

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"

	"github.com/idfoundry/fapigo/extension"
	"github.com/idfoundry/fapigo/internal/claimnames"
	"github.com/idfoundry/fapigo/internal/claimvalues"
	"github.com/idfoundry/fapigo/internal/grantrevocation"
	"github.com/idfoundry/fapigo/internal/token"
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
	// result, even if this source has a value for it. names holds only
	// claims the client requested with the "claims" parameter (OIDC Core
	// §5.5) and the application then approved for release, through
	// GrantedAuthorization.ApprovedIdentityClaims. names is never
	// empty when this method is called (callers skip the call entirely
	// when nothing was requested), so an empty result here means "no
	// value for any of these", not "return everything". Each value is
	// already JSON-encoded. A name this source has no value for is
	// simply absent from the result — that is not an error condition.
	//
	// The server enforces the restriction too: it puts only names into
	// an ID token or UserInfo response, whatever this returns, and never
	// a value for a claim it sets itself — "sub", "acr", "auth_time" and
	// the like, which a client may request but the server answers. A
	// claim requested with "value" or "values" (OIDC Core §5.5.1) is
	// released only with one of those values, compared as JSON: the
	// server, and serverresource.UserInfoClaims, drop it otherwise, so a
	// source returns the claim's real value and needn't look at the
	// request.
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
// to what was originally asked for. serverresource.UserInfoClaims reads
// it and builds the response's claims from IdentityClaimsSource.
const RequestedUserinfoClaimsKey = "requested_userinfo_claims"

// RequestedUserinfoClaimValuesKey is the access-token claim name this
// package records, beside RequestedUserinfoClaimsKey, the values the
// "claims" parameter's userinfo-scoped requests asked each claim to have
// under: a JSON object mapping each claim requested with "value" or
// "values" (OIDC Core §5.5.1) to the array of values it may be released
// with. OIDC Core §5.5.1: "When the Claim value does not match the
// requested value, the Claim is not included in the response."
// serverresource.UserInfoClaims drops a claim whose resolved value isn't
// one of them; a claim absent from the object is unconstrained, and the
// claim is absent from the token when no request carried a value.
const RequestedUserinfoClaimValuesKey = "requested_userinfo_claim_values"

// parseRequestedClaimNames extracts the claim names requested for each
// delivery location from raw (the "claims" parameter's raw JSON value,
// or empty if absent), reading members by their exact names through
// claimsMembers. Only the names are kept here: "essential" is advisory
// (OIDC Core §5.5.1), "value" and "values" are kept apart by
// requestedClaimValues, and an essential "acr" request with values,
// which §5.5.1.1 makes a requirement, by essentialACRValues. Malformed
// input yields no requested claims rather than an error here; requests
// are refused earlier, by validateClaimsParameter.
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
	top, ok := claimsMembers(raw)
	if !ok {
		return nil, nil
	}
	return claimNames(claimsLocation(top, "id_token")), claimNames(claimsLocation(top, "userinfo"))
}

func claimNames(m map[string]json.RawMessage) []string {
	if len(m) == 0 {
		return nil
	}
	names := make([]string, 0, len(m))
	for name := range m {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

// RequestedClaims is the identity claims an authorization request asked
// for with the OIDC Core §5.5 "claims" parameter, by where each would be
// delivered. It is the client's request, not a decision: a client can
// name any claim it likes, so the server releases only those the
// application also approves in GrantedAuthorization.ApprovedIdentityClaims
// — show these to the user alongside the requested scope.
type RequestedClaims struct {
	IDToken  []string // requested for the ID token
	UserInfo []string // requested from the UserInfo endpoint
}

// Names returns every requested claim name, from either location, once
// each and sorted.
func (r RequestedClaims) Names() []string {
	names := append(append([]string{}, r.IDToken...), r.UserInfo...)
	slices.Sort(names)
	return slices.Compact(names)
}

// requestedClaimValues returns the values each of names, as requested
// under location ("id_token" or "userinfo") by params' "claims"
// parameter, may be released with (claimvalues.FromRequest): nil when
// none was requested with "value" or "values".
func requestedClaimValues(params map[string]json.RawMessage, location string, names []string) claimvalues.Acceptable {
	top, ok := claimsMembers(params["claims"])
	if !ok {
		return nil
	}
	requests := claimsLocation(top, location)
	var out claimvalues.Acceptable
	for _, name := range names {
		acceptable, constrained := claimvalues.FromRequest(requests[name])
		if !constrained {
			continue
		}
		if out == nil {
			out = claimvalues.Acceptable{}
		}
		out[name] = acceptable
	}
	return out
}

func requestedClaimsFrom(params map[string]json.RawMessage) RequestedClaims {
	idToken, userinfo := parseRequestedClaimNames(params["claims"])
	return RequestedClaims{IDToken: idToken, UserInfo: userinfo}
}

// approvedClaimNames returns, per delivery location, the requested
// claims the application approved, rejecting an approval for a claim
// that wasn't requested — the same rule a granted scope follows.
func approvedClaimNames(params map[string]json.RawMessage, approved []string) (idToken, userinfo []string, err error) {
	requested := requestedClaimsFrom(params)
	all := make(map[string]struct{}, len(requested.IDToken)+len(requested.UserInfo))
	for _, name := range requested.Names() {
		all[name] = struct{}{}
	}
	approvedSet := make(map[string]struct{}, len(approved))
	for _, name := range approved {
		if _, ok := all[name]; !ok {
			return nil, nil, fmt.Errorf("claim %q was not requested", name)
		}
		approvedSet[name] = struct{}{}
	}
	keep := func(names []string) []string {
		var out []string
		for _, n := range names {
			if _, ok := approvedSet[n]; ok {
				out = append(out, n)
			}
		}
		return out
	}
	return keep(requested.IDToken), keep(requested.UserInfo), nil
}

// serverTokenClaims are the claims this package adds to access tokens
// itself, beyond those internal/claimnames reserves for every
// authorization server: they record the grant behind a token, so only
// this server may set them.
var serverTokenClaims = []string{
	RequestedUserinfoClaimsKey, RequestedUserinfoClaimValuesKey, grantrevocation.Claim, grantrevocation.CodeClaim, token.GrantTypeClaim,
	token.PairwiseSectorClaim, token.ClientSubjectClaim,
}

// isManagedTokenClaim reports whether name is a claim whose meaning a
// token's recipient takes from this server, the resource owner or the
// token's own structure, never from a client: one internal/claimnames
// reserves against a client in an ID token or an access token (the
// claims set by the server itself, RFC 9068 roles/groups/entitlements,
// RFC 8693 act/may_act, authorization_details, the OIDC Core §5.1
// standard claims, events and the other claims that change how a
// recipient processes a token, and the JARM parameters code, state and
// error), or one in serverTokenClaims. A client-supplied extension
// value must not appear under one of them: a client-chosen
// roles:["admin"] would otherwise reach the access token, and an
// unapproved "email" an ID token, as the client's own value.
func isManagedTokenClaim(name string) bool {
	return claimnames.ReservedInTokens(claimnames.Client, name) || slices.Contains(serverTokenClaims, name)
}

// checkExtensionClaimNames rejects a registry that would copy a
// client-supplied value into a token under a managed claim name
// (isManagedTokenClaim). extension.NewRegistry already refuses every
// name but serverTokenClaims; this also covers those.
func checkExtensionClaimNames(registry *extension.Registry) error {
	for _, name := range registry.TokenClaimNames() {
		if isManagedTokenClaim(name) {
			return fmt.Errorf("server: config: extension %q has ReturnInTokenClaims set, but %q is a claim the server or the resource owner supplies, not the client", name, name)
		}
	}
	return nil
}
