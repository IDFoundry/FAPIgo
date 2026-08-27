package resource

import "fmt"

// ErrorCode is a closed set of error codes Verify returns, matching the
// "error" values RFC 6750 §3.1 and RFC 9449 §7.1 define for a
// WWW-Authenticate challenge.
type ErrorCode string

const (
	ErrorInvalidRequest ErrorCode = "invalid_request"
	ErrorInvalidToken   ErrorCode = "invalid_token"
	ErrorServerError    ErrorCode = "server_error"

	// ErrorUseDPoPNonce indicates the presented DPoP proof was otherwise
	// valid but carried no nonce, or one this verifier didn't just issue
	// (unknown, already consumed, or expired) — RFC 9449 §8's own error
	// value, distinct from ErrorInvalidToken (the token itself is fine;
	// the caller just needs to retry with the nonce this error's own
	// Nonce method returns). Only ever returned when
	// Dependencies.Nonces is configured.
	ErrorUseDPoPNonce ErrorCode = "use_dpop_nonce"
)

// Error is the error type Verify returns. Code and PublicDescription
// are safe to put directly into a WWW-Authenticate challenge or an
// error response body; the underlying cause (available via Unwrap, and
// included in Error's own message) is for logs only and must never be
// copied into a public response.
type Error struct {
	code        ErrorCode
	httpStatus  int
	description string
	cause       error
	nonce       string
}

func newError(code ErrorCode, httpStatus int, description string, cause error) *Error {
	return &Error{code: code, httpStatus: httpStatus, description: description, cause: cause}
}

// Code returns the error code.
func (e *Error) Code() ErrorCode { return e.code }

// PublicDescription returns a short, safe-to-expose description.
func (e *Error) PublicDescription() string { return e.description }

// Nonce returns the nonce a caller should present on retry, alongside
// this error's own DPoP challenge — non-empty only when Code is
// ErrorUseDPoPNonce, in which case it belongs in the response's own
// DPoP-Nonce header (RFC 9449 §8).
func (e *Error) Nonce() string { return e.nonce }

// HTTPStatus returns the HTTP status code an adapter should respond
// with.
func (e *Error) HTTPStatus() int { return e.httpStatus }

// Error implements the error interface. Its output includes the
// internal cause and is meant for logs, not for a public response.
func (e *Error) Error() string {
	if e.cause != nil {
		return fmt.Sprintf("resource: %s: %s: %v", e.code, e.description, e.cause)
	}
	return fmt.Sprintf("resource: %s: %s", e.code, e.description)
}

// Unwrap returns the underlying cause, if any.
func (e *Error) Unwrap() error { return e.cause }
