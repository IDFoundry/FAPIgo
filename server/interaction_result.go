package server

// InteractionResult is a closed sum type describing how an interaction
// concluded. It can only be constructed via Authorize, Deny or
// AuthenticationFailed — never assembled field-by-field — so an invalid
// combination (e.g. a granted authorization without an authenticated
// subject) cannot be represented at all.
type InteractionResult interface {
	interactionResult()
}

type authorizeResult struct {
	subject AuthenticatedSubject
	auth    AuthenticationContext
	grant   GrantedAuthorization
}

func (authorizeResult) interactionResult() { /* marker method — see InteractionResult's own doc comment. */
}

// Authorize records that subject authenticated (per auth) and the
// application approved grant.
func Authorize(subject AuthenticatedSubject, auth AuthenticationContext, grant GrantedAuthorization) InteractionResult {
	return authorizeResult{subject: subject, auth: auth, grant: grant}
}

type denyResult struct {
	reason string
}

func (denyResult) interactionResult() { /* marker method — see InteractionResult's own doc comment. */
}

// Deny records that the resource owner (or the application, on their
// behalf) declined to authorize the request. reason is an optional,
// human-readable explanation the caller controls — it is not internal
// diagnostic detail, and may be surfaced to the client.
func Deny(reason string) InteractionResult {
	return denyResult{reason: reason}
}

type authenticationFailedResult struct {
	reason string
}

func (authenticationFailedResult) interactionResult() { /* marker method — see InteractionResult's own doc comment. */
}

// AuthenticationFailed records that the resource owner could not be
// authenticated at all (as distinct from authenticating and then
// declining to authorize). reason is an optional, human-readable
// explanation the caller controls.
func AuthenticationFailed(reason string) InteractionResult {
	return authenticationFailedResult{reason: reason}
}
