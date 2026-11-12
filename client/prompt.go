package client

import (
	"slices"
	"strings"
	"unicode"

	"github.com/idfoundry/fapigo/extension"
)

// promptParameter is the authorization request's "prompt" (OIDC Core
// §3.1.2.1).
const promptParameter = "prompt"

// The prompt values OIDC Core §3.1.2.1 defines, for
// BeginAuthorizationRequest.Prompt.
const (
	// PromptNone asks the server to show the user no authentication or
	// consent page: it fails the request (login_required,
	// consent_required, interaction_required…) if it can't proceed
	// without one.
	PromptNone = "none"
	// PromptLogin asks the server to authenticate the user again.
	PromptLogin = "login"
	// PromptConsent asks the server to ask the user for consent, even if
	// they gave it before.
	PromptConsent = "consent"
	// PromptSelectAccount asks the server to let the user choose which
	// of their accounts to use.
	PromptSelectAccount = "select_account"
)

// checkPrompt refuses a prompt OIDC Core §3.1.2.1 doesn't allow, or
// that the space-separated parameter can't carry as given: "none" with
// another value, and an empty or repeated value, or one containing
// whitespace or a control character. It also refuses an Extensions
// value named "prompt" beside it.
func checkPrompt(prompt []string, extensions extension.Values) *Error {
	if len(prompt) == 0 {
		return nil
	}
	if _, ok := extension.Snapshot(extensions)[promptParameter]; ok {
		return newError(ErrorInvalidRequest, `"prompt" is set both as Prompt and as an Extensions value: set it only as Prompt`, nil)
	}
	for i, v := range prompt {
		if v == "" || strings.ContainsFunc(v, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) {
			return newError(ErrorInvalidRequest, "a prompt value is empty or contains whitespace or control characters", nil)
		}
		if slices.Contains(prompt[:i], v) {
			return newError(ErrorInvalidRequest, "a prompt value is repeated", nil)
		}
	}
	if len(prompt) > 1 && slices.Contains(prompt, PromptNone) {
		return newError(ErrorInvalidRequest, `prompt "none" must not be combined with another value`, nil)
	}
	return nil
}
