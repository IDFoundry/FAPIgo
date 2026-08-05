package pkce

import "errors"

var (
	// ErrPlainMethodNotPermitted indicates a code_challenge_method of
	// "plain" — a syntactically valid PKCE method this package refuses
	// to support, since it provides no protection against interception
	// of the authorization code.
	ErrPlainMethodNotPermitted = errors.New("pkce: plain code_challenge_method is not permitted")

	// ErrUnsupportedMethod indicates a code_challenge_method other than
	// "S256" or "plain" — something outside RFC 7636 entirely.
	ErrUnsupportedMethod = errors.New("pkce: unsupported code_challenge_method")

	// ErrInvalidVerifierSyntax indicates a code_verifier that does not
	// meet RFC 7636's length and character-set requirements.
	ErrInvalidVerifierSyntax = errors.New("pkce: invalid code_verifier syntax")

	// ErrChallengeMismatch indicates a code_verifier whose derived
	// challenge does not match the code_challenge on record.
	ErrChallengeMismatch = errors.New("pkce: code_verifier does not match code_challenge")
)
