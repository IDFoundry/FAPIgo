package server

import (
	"encoding/json"
	"fmt"
	"time"
	"unicode/utf8"
)

// SubjectID identifies a resource owner the server has authenticated. It
// has no public zero-value use — construct one with NewSubjectID — so a
// caller can't accidentally treat an empty string as a valid subject.
type SubjectID struct {
	value string
}

// maxSubjectIDLength is OIDC Core §2's limit on "sub": it "MUST NOT
// exceed 255 ASCII characters in length".
const maxSubjectIDLength = 255

// NewSubjectID validates and wraps value: 1 to 255 printable ASCII
// characters (0x20 to 0x7E). OIDC Core §2 limits an ID token's "sub" to
// 255 ASCII characters; control characters are refused too, since no
// identifier needs them and they can forge lines in logs. A user's
// display name or email address, which may be longer or non-ASCII, is
// a claim, not the subject: map it to a stable identifier of your own.
//
// Grants stored before this check was added keep the subject they were
// issued with: only new authentications are checked.
//
// A deployment whose pairwise subjects come from pairwise.NewReversible
// holds shorter internal subjects: at most
// pairwise.MaxReversibleSubjectLength (151) bytes. A longer one is
// accepted here, but completing an authorization for it at a pairwise
// client fails with server_error, since its sub can't be derived.
func NewSubjectID(value string) (SubjectID, error) {
	if value == "" {
		return SubjectID{}, fmt.Errorf("server: subject ID is empty")
	}
	if len(value) > maxSubjectIDLength {
		return SubjectID{}, fmt.Errorf("server: subject ID is %d bytes, more than OIDC Core's %d ASCII characters", len(value), maxSubjectIDLength)
	}
	for i := range len(value) {
		if c := value[i]; c < 0x20 || c > 0x7e {
			return SubjectID{}, fmt.Errorf("server: subject ID has a byte (0x%02x at %d) that isn't printable ASCII", c, i)
		}
	}
	return SubjectID{value: value}, nil
}

// String returns the subject's wire value.
func (s SubjectID) String() string { return s.value }

// AuthenticatedSubject is a resource owner the embedding application has
// verified. It can only be constructed via NewAuthenticatedSubject, so
// CompleteAuthorization never receives an authorization result asserting
// authentication happened without that assertion having gone through
// validation.
type AuthenticatedSubject struct {
	id SubjectID
}

// NewAuthenticatedSubject wraps id.
func NewAuthenticatedSubject(id SubjectID) (AuthenticatedSubject, error) {
	if id.value == "" {
		return AuthenticatedSubject{}, fmt.Errorf("server: authenticated subject requires a non-zero SubjectID")
	}
	return AuthenticatedSubject{id: id}, nil
}

// ID returns the authenticated subject's ID.
func (a AuthenticatedSubject) ID() SubjectID { return a.id }

// AuthenticationContext describes how and when the resource owner
// authenticated. Build it with NewAuthenticationContext: Authorize with
// a zero AuthenticationContext{} is refused by CompleteAuthorization and
// CompleteBackchannelAuthentication (server_error), since it says
// nothing about when the user authenticated, as is one whose
// authentication time is later than now (beyond Limits.MaxClockSkew).
type AuthenticationContext struct {
	authTime time.Time
	acr      string
	amr      []string
}

// NewAuthenticationContext validates and wraps its arguments. acr and
// amr are optional (pass "" / nil if the application doesn't track
// them); authTime is required: when the user authenticated, no earlier
// than the Unix epoch. CompleteAuthorization and
// CompleteBackchannelAuthentication also refuse an authTime later than
// now (allowing Limits.MaxClockSkew), so pass the time the user
// actually authenticated, never a session's expiry.
func NewAuthenticationContext(authTime time.Time, acr string, amr []string) (AuthenticationContext, error) {
	if authTime.IsZero() {
		return AuthenticationContext{}, fmt.Errorf("server: authentication context requires a non-zero authTime")
	}
	if authTime.Before(unixEpoch) {
		return AuthenticationContext{}, fmt.Errorf("server: authentication context authTime is before the Unix epoch")
	}
	// Same reason as NewSubjectID: acr and amr are JSON strings in the
	// issued ID token.
	if !utf8.ValidString(acr) {
		return AuthenticationContext{}, fmt.Errorf("server: authentication context acr is not valid UTF-8")
	}
	for _, method := range amr {
		if !utf8.ValidString(method) {
			return AuthenticationContext{}, fmt.Errorf("server: authentication context amr is not valid UTF-8")
		}
	}
	amrCopy := make([]string, len(amr))
	copy(amrCopy, amr)
	return AuthenticationContext{authTime: authTime, acr: acr, amr: amrCopy}, nil
}

// unixEpoch is the earliest authTime an AuthenticationContext takes: an
// ID token's auth_time is seconds since it (OIDC Core §2).
var unixEpoch = time.Unix(0, 0)

// authTimeProblem describes why a's authTime can't be the time the user
// authenticated, at now with skew allowed, or returns "" when it can.
// A zero AuthenticationContext{} (one that bypassed
// NewAuthenticationContext) has no authTime, and one later than now
// isn't an authentication that happened, but would pass max_age and
// prompt=login as the most recent possible. (NewAuthenticationContext
// refuses one before the Unix epoch, so only the zero value has one.)
func (a AuthenticationContext) authTimeProblem(now time.Time, skew time.Duration) string {
	switch {
	case a.authTime.IsZero():
		return "authorize result carries no authentication context (use NewAuthenticationContext)"
	case a.authTime.After(now.Add(skew)):
		return "authorize result's authentication time is in the future"
	}
	return ""
}

// GrantedAuthorization is what the embedding application decided to
// approve — which may be a subset of what was originally requested.
// CompleteAuthorization rejects a scope not present in the original
// request; it does not otherwise second-guess this decision.
type GrantedAuthorization struct {
	Scope []string

	// ApprovedIdentityClaims names the identity claims, from the
	// request's own RequestedClaims (InteractionRequest or
	// BackchannelInteractionRequest), that the resource owner agreed to
	// release — typically what the consent screen showed and the user
	// left selected. Only claims both requested and approved are
	// resolved through Dependencies.IdentityClaims, for the ID token or
	// UserInfo, wherever each was requested. Nil releases none.
	// CompleteAuthorization/CompleteBackchannelAuthentication reject a
	// name that wasn't requested, the same way they reject a scope that
	// wasn't.
	ApprovedIdentityClaims []string

	// AuthorizationDetails is the approved subset of the request's own
	// Rich Authorization Requests (RFC 9396) detail objects — one entry
	// per approved object, read out of InteractionRequest.AuthorizationDetails
	// (or BackchannelInteractionRequest's) via extension.RARGet and
	// re-encoded, or dropped/narrowed as the resource owner decided. Nil
	// or empty if the request carried no authorization_details, or none
	// of it was approved. CompleteAuthorization/
	// CompleteBackchannelAuthentication reject an entry that isn't an
	// acceptable narrowing (RARDefinition.ValidateGrant, or exact-match
	// if that hook is nil) of some object in the original request — the
	// same way a scope not present in the original request is rejected.
	AuthorizationDetails []json.RawMessage

	// Resources narrows the RFC 8707 resource indicators the grant's
	// access tokens are restricted to, to those the resource owner
	// approved, from the request's own (InteractionRequest.Resources,
	// or BackchannelInteractionRequest's). Nil or empty grants all of
	// them, so an application that doesn't show resources grants what
	// was requested. CompleteAuthorization/
	// CompleteBackchannelAuthentication reject one that wasn't
	// requested, the same way they reject a scope that wasn't — so a
	// request that named none can't be granted any.
	Resources []string

	// IDTokenClaims are additional claims the application wants in the
	// ID token issued for this authorization — e.g. provider-specific
	// claims describing the authenticated subject or who it is acting
	// for — keyed by claim name, each value already JSON-encoded. They go
	// into the ID token only, never the access token, and are carried
	// forward to every ID token re-issued from the same grant (a refresh,
	// or a CIBA poll). Nil if the application adds none.
	//
	// CompleteAuthorization/CompleteBackchannelAuthentication reject a
	// claim name the server manages itself — the claims it sets in an ID
	// token; azp, jti, nbf, cnf and the hashes; _claim_names,
	// _claim_sources, sub_jwk and events, which change how a relying
	// party processes the token; and code, state and error, which would
	// make it look like a JARM response — a name that isn't valid UTF-8,
	// a value that isn't valid JSON, and claims whose total size exceeds
	// Limits.MaxIDTokenClaimsBytes, a budget identity and extension
	// claims share at issuance. Authorization attributes (RFC 9068
	// roles, groups, entitlements) and delegation claims (RFC 8693 act,
	// may_act) are the application's to set here; a client can never
	// set them (see extension.Definition.ReturnInTokenClaims). A name that collides with an
	// IdentityClaimsSource or extension (ReturnInTokenClaims) claim
	// overrides it: this is the application's own decision at login,
	// the most specific source of the three. The claims are ignored if
	// no ID token is issued ("openid" not granted).
	//
	// For a client that gets pairwise subs, nothing here may identify the
	// user beyond the sub the server sets: an account number or the
	// user's internal subject in a claim would link them across relying
	// parties as surely as a public sub. ("sub" itself is managed, and
	// refused.)
	IDTokenClaims map[string]json.RawMessage

	// GrantID, if set, names this grant so the application can revoke it
	// later with Server.RevokeGrant — its authorization code, refresh
	// token and every access token issued from it — for a "connected
	// apps" page, for example. The application chooses it, typically a
	// random identifier keying its own record of what was approved. Give
	// each grant its own: RevokeGrant revokes every grant carrying the
	// ID, and the client a grant was issued to can trigger that through
	// RevokeToken, so an ID shared by several grants would let one
	// client end the others. To revoke everything for one user, keep
	// their grant IDs and call RevokeGrant for each. When a client ends
	// its grant through RevokeToken, the TokenRevocationResult names
	// this ID, so the application can delete what it kept for the grant
	// at once. The ID is
	// carried in every access token from the grant (as "grant_id"),
	// readable by the client in a self-contained one, so it mustn't be
	// personal data, or derived from the user's internal subject: for a
	// pairwise client that would undo its pairwise sub. Use a random
	// value. 1 to 128 characters from A-Z,
	// a-z, 0-9, '.', '_', '~' and '-'. Empty leaves the grant revocable
	// only token by token.
	//
	// CompleteAuthorization/CompleteBackchannelAuthentication reject a
	// grant ID that doesn't fit, or one set while Dependencies.Revocation
	// can't be checked (see RevokeGrant).
	GrantID string
}
