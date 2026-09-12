package federation

import (
	"errors"
	"net/http"

	"github.com/idfoundry/fapigo/internal/httperror"
)

// ErrorCode is a closed set of OpenID Federation 1.0 §8.9 error codes
// this package's own methods (and NewError, for a caller reporting one
// it detected itself) return.
type ErrorCode string

const (
	// ErrorInvalidRequest is §8.9's own "the request is incomplete or
	// does not comply with current specifications" code — HTTP 400.
	// SubjectFromFetchRequest and SubordinateIssuer.SubordinateStatement
	// both use this for a missing/malformed "sub".
	ErrorInvalidRequest ErrorCode = "invalid_request"

	// ErrorNotFound is §8.9's "the endpoint cannot serve the requested
	// subject" code — HTTP 404. Only ever built with NewError: whether
	// a "sub" is actually a known subordinate is a lookup only the
	// caller's own subordinate storage can answer, so this package never
	// returns it itself.
	ErrorNotFound ErrorCode = "not_found"

	// ErrorUnsupportedParameter is §8.2's own code for a Subordinate
	// Listing filter parameter (entity_type, trust_marked,
	// trust_mark_type, intermediate) the responder doesn't support —
	// HTTP 400. RejectUnsupportedListingFilters returns this.
	ErrorUnsupportedParameter ErrorCode = "unsupported_parameter"
)

// Error is the error type this package's own HTTP-adjacent helpers
// (SubjectFromFetchRequest, RejectUnsupportedListingFilters,
// SubordinateIssuer.SubordinateStatement) return for a condition
// OpenID Federation 1.0 §8.9 itself defines a wire error for — safe to
// pass directly to WriteJSON.
type Error struct {
	code        ErrorCode
	httpStatus  int
	description string
	cause       error
}

func newError(code ErrorCode, httpStatus int, description string, cause error) *Error {
	return &Error{code: code, httpStatus: httpStatus, description: description, cause: cause}
}

// NewError builds an *Error for a caller reporting an OpenID Federation
// §8.9-shaped failure it detected itself — most notably ErrorNotFound,
// which only the caller's own subordinate lookup can determine (see
// ErrorNotFound's own doc comment). Mirrors server.NewError.
func NewError(code ErrorCode, httpStatus int, description string) *Error {
	return &Error{code: code, httpStatus: httpStatus, description: description}
}

// Code returns the OpenID Federation error code.
func (e *Error) Code() ErrorCode { return e.code }

// PublicDescription returns a short, safe-to-expose description.
func (e *Error) PublicDescription() string { return e.description }

// HTTPStatus returns the HTTP status code an adapter should respond
// with.
func (e *Error) HTTPStatus() int { return e.httpStatus }

// Error implements the error interface. Its output includes the
// underlying cause and is meant for logs, not for a federation error
// response body.
func (e *Error) Error() string {
	return httperror.Message("federation", string(e.code), e.description, e.cause)
}

// Unwrap returns the underlying cause, if any.
func (e *Error) Unwrap() error { return e.cause }

// WriteJSON writes e as a complete OpenID Federation 1.0 §8.9 JSON
// error response to w: the "application/json" Content-Type, e's own
// HTTPStatus, and a {"error": ..., "error_description": ...} body built
// from Code and PublicDescription — never Unwrap's cause. Every *Error
// this package's own methods return, and any built with NewError, is
// safe to pass here.
//
// Must be called before anything else writes to w — like every
// http.ResponseWriter header/status call, it has no effect once a
// prior write has already sent the response's status line.
func (e *Error) WriteJSON(w http.ResponseWriter) {
	httperror.WriteJSON(w, "", "", string(e.code), e.description, e.httpStatus)
}

// WriteError writes err to w: err's own WriteJSON if err is a *Error
// (as every error this package's own HTTP-adjacent helpers return is),
// or a generic 500 otherwise. Saves every HTTP adapter from
// reimplementing this same errors.As-or-fallback dance itself — see
// cmd/conformance-federation-trust-anchor's own history for exactly
// this boilerplate, repeated inline at every one of its endpoints
// before this existed.
func WriteError(w http.ResponseWriter, err error) {
	var fedErr *Error
	if errors.As(err, &fedErr) {
		fedErr.WriteJSON(w)
		return
	}
	http.Error(w, "server_error", http.StatusInternalServerError)
}
