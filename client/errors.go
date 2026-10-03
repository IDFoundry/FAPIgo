package client

import "fmt"

// ErrorCode is a closed set of error codes this client's public methods
// return.
type ErrorCode string

const (
	ErrorInvalidRequest      ErrorCode = "invalid_request"
	ErrorInvalidResponse     ErrorCode = "invalid_response"
	ErrorAuthorizationDenied ErrorCode = "authorization_denied"
	ErrorInternal            ErrorCode = "internal"

	// ErrorResponseTooLarge indicates an ID token or UserInfo response
	// exceeded Config.Limits.MaxJOSECompactBytes — distinct from
	// ErrorInvalidResponse because the artifact wasn't malformed, it was
	// simply larger than configured; PublicDescription names which
	// artifact, and the wrapped cause (Unwrap) carries the observed and
	// allowed byte counts for logs.
	ErrorResponseTooLarge ErrorCode = "response_too_large"
)

// Error is the error type every public Client method returns. Code and
// PublicDescription are safe to surface to the embedding application
// (e.g. in a UI message); the underlying cause (available via Unwrap,
// and included in Error's own message) is for logs only.
type Error struct {
	code        ErrorCode
	description string
	cause       error
	server      *ServerErrorResponse
}

func newError(code ErrorCode, description string, cause error) *Error {
	return &Error{code: code, description: description, cause: cause}
}

// Code returns the error code.
func (e *Error) Code() ErrorCode { return e.code }

// PublicDescription returns a short, safe-to-expose description. When
// the Error was caused by a server's error response, it is that
// response's error_description (see ServerResponse), which is the
// server's own text.
func (e *Error) PublicDescription() string { return e.description }

// Error implements the error interface. Its output includes the
// internal cause and is meant for logs, not for a user-facing message.
// It never includes a response body. It may include text the remote
// server wrote: an authorization server error response's
// error_description (PublicDescription), limited to RFC 6749's printable
// ASCII, and its error code — quoted, when it isn't RFC 6749 error text.
// Where only this client's own words may be logged, log Code() and
// ServerResponse()'s Code and HTTPStatus instead.
func (e *Error) Error() string {
	if e.cause != nil {
		return fmt.Sprintf("client: %s: %s: %v", e.code, e.description, e.cause)
	}
	return fmt.Sprintf("client: %s: %s", e.code, e.description)
}

// Unwrap returns the underlying cause, if any.
func (e *Error) Unwrap() error { return e.cause }
