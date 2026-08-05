package server

import "fmt"

// ErrorCode is a closed set of OAuth error codes (RFC 6749 §5.2, RFC
// 9126) this server's public methods return.
type ErrorCode string

const (
	ErrorInvalidRequest       ErrorCode = "invalid_request"
	ErrorInvalidClient        ErrorCode = "invalid_client"
	ErrorInvalidRequestObject ErrorCode = "invalid_request_object"
	ErrorInvalidGrant         ErrorCode = "invalid_grant"
	ErrorInvalidScope         ErrorCode = "invalid_scope"
	ErrorUnsupportedGrantType ErrorCode = "unsupported_grant_type"
	ErrorServerError          ErrorCode = "server_error"
)

// Error is the error type every public Server method returns. Code and
// PublicDescription are safe to put directly into an OAuth error
// response; the underlying cause (available via Unwrap, and included in
// Error's own message) is for logs only and must never be copied into a
// public response.
type Error struct {
	code        ErrorCode
	httpStatus  int
	description string
	cause       error
}

func newError(code ErrorCode, httpStatus int, description string, cause error) *Error {
	return &Error{code: code, httpStatus: httpStatus, description: description, cause: cause}
}

// Code returns the OAuth error code.
func (e *Error) Code() ErrorCode { return e.code }

// PublicDescription returns a short, safe-to-expose description.
func (e *Error) PublicDescription() string { return e.description }

// HTTPStatus returns the HTTP status code an adapter should respond
// with.
func (e *Error) HTTPStatus() int { return e.httpStatus }

// Error implements the error interface. Its output includes the
// internal cause and is meant for logs, not for an OAuth response body.
func (e *Error) Error() string {
	if e.cause != nil {
		return fmt.Sprintf("server: %s: %s: %v", e.code, e.description, e.cause)
	}
	return fmt.Sprintf("server: %s: %s", e.code, e.description)
}

// Unwrap returns the underlying cause, if any.
func (e *Error) Unwrap() error { return e.cause }
