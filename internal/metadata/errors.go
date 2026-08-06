package metadata

import "errors"

var (
	// ErrTooLarge indicates a metadata document exceeded the size this
	// package will attempt to parse.
	ErrTooLarge = errors.New("metadata: document too large")

	// ErrMalformed indicates a document was not valid JSON, or not a
	// JSON object.
	ErrMalformed = errors.New("metadata: malformed document")

	// ErrMissingField indicates a document was missing a field this
	// module requires.
	ErrMissingField = errors.New("metadata: missing required field")

	// ErrIssuerMismatch indicates a document's issuer claim did not
	// equal the issuer identifier the caller expected — see
	// ParseAndValidate.
	ErrIssuerMismatch = errors.New("metadata: issuer does not match expected issuer")
)
