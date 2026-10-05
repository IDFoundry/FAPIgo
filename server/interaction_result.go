package server

// InteractionResult is a closed sum type describing how an interaction
// concluded. It can only be constructed via Authorize, Deny,
// AuthenticationFailed or InteractionNeeded — never assembled
// field-by-field — so an invalid
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

// Discriminator for InteractionResult — deliberately empty.
func (authorizeResult) interactionResult() {}

// Authorize records that subject authenticated (per auth) and the
// application approved grant.
//
// auth's time must be when the user actually authenticated, never
// time.Now() for an existing session: CompleteAuthorization answers the
// client with login_required instead of a code when it's older than the
// request's max_age (InteractionRequest.MaxAge), or, when the request's
// prompt has PromptLogin, earlier than the request itself — both
// allowing Limits.MaxClockSkew.
func Authorize(subject AuthenticatedSubject, auth AuthenticationContext, grant GrantedAuthorization) InteractionResult {
	return authorizeResult{subject: subject, auth: auth, grant: grant}
}

type denyResult struct {
	reason string
}

// Discriminator for InteractionResult — deliberately empty.
func (denyResult) interactionResult() {}

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

// Discriminator for InteractionResult — deliberately empty.
func (authenticationFailedResult) interactionResult() {}

// AuthenticationFailed records that the resource owner could not be
// authenticated at all (as distinct from authenticating and then
// declining to authorize). reason is an optional, human-readable
// explanation the caller controls.
func AuthenticationFailed(reason string) InteractionResult {
	return authenticationFailedResult{reason: reason}
}

// InteractionNeed says what an interaction would have had to show the
// end user, for InteractionNeeded.
type InteractionNeed int

// The InteractionNeed values, each answered with the OIDC Core §3.1.2.6
// error of the same name.
const (
	_ InteractionNeed = iota
	// NeedLogin: the end user would have had to authenticate
	// (login_required).
	NeedLogin
	// NeedConsent: the end user would have had to consent
	// (consent_required).
	NeedConsent
	// NeedAccountSelection: the end user would have had to choose an
	// account (account_selection_required).
	NeedAccountSelection
	// NeedInteraction: the end user would have had to interact in some
	// other way (interaction_required).
	NeedInteraction
)

// errorCode is need's OIDC Core §3.1.2.6 error code, or "" for a value
// that isn't one of the InteractionNeed constants.
func (need InteractionNeed) errorCode() string {
	switch need {
	case NeedLogin:
		return "login_required"
	case NeedConsent:
		return "consent_required"
	case NeedAccountSelection:
		return "account_selection_required"
	case NeedInteraction:
		return "interaction_required"
	default:
		return ""
	}
}

type interactionNeededResult struct {
	need   InteractionNeed
	reason string
}

// Discriminator for InteractionResult — deliberately empty.
func (interactionNeededResult) interactionResult() {}

// InteractionNeeded records that the interaction couldn't be concluded
// without showing the end user something it wasn't allowed to show:
// the answer to a request whose InteractionRequest.Prompt has
// PromptNone, when the end user has no session or hasn't consented.
// CompleteAuthorization answers the client with need's error
// (login_required, consent_required, account_selection_required or
// interaction_required). reason is an optional, human-readable
// explanation the caller controls.
//
// It answers a redirect-based authorization only: a backchannel
// authentication request carries no prompt, and
// CompleteBackchannelAuthentication refuses it as an unrecognized
// result.
func InteractionNeeded(need InteractionNeed, reason string) InteractionResult {
	return interactionNeededResult{need: need, reason: reason}
}
