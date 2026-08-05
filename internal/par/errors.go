package par

import "errors"

var (
	// ErrFormTooLarge indicates a form-encoded body larger than this
	// package is willing to parse.
	ErrFormTooLarge = errors.New("par: form body exceeds maximum size")

	// ErrResponseTooLarge indicates a JSON response body larger than
	// this package is willing to parse.
	ErrResponseTooLarge = errors.New("par: response body exceeds maximum size")

	// ErrMalformedForm indicates a form-encoded body that could not be
	// parsed as application/x-www-form-urlencoded.
	ErrMalformedForm = errors.New("par: malformed form body")

	// ErrDuplicateParameter indicates a form-encoded body containing the
	// same parameter name more than once. A PAR submission (or any
	// OAuth request body) with a duplicate parameter is rejected rather
	// than resolved by picking the first or last occurrence, since
	// either choice can be turned into a request-smuggling primitive.
	ErrDuplicateParameter = errors.New("par: duplicate parameter")

	// ErrMalformedResponse indicates a PAR response body that was not
	// valid JSON, or was missing a required field, or had a field of
	// the wrong shape.
	ErrMalformedResponse = errors.New("par: malformed response")

	// ErrMissingRequestURI indicates a PAR success response with an
	// empty or absent request_uri.
	ErrMissingRequestURI = errors.New("par: response is missing request_uri")

	// ErrInvalidExpiresIn indicates a PAR success response whose
	// expires_in is not a positive number of seconds.
	ErrInvalidExpiresIn = errors.New("par: expires_in must be positive")

	// ErrMissingErrorCode indicates an OAuth error response body with an
	// empty or absent error code.
	ErrMissingErrorCode = errors.New("par: error response is missing error code")
)
