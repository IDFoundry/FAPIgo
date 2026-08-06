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
}

func newError(code ErrorCode, httpStatus int, description string, cause error) *Error {
	return &Error{code: code, httpStatus: httpStatus, description: description, cause: cause}
}

// Code returns the error code.
func (e *Error) Code() ErrorCode { return e.code }

// PublicDescription returns a short, safe-to-expose description.
func (e *Error) PublicDescription() string { return e.description }

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
