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

	// ErrorInvalidRequestURI is RFC 9126 §2.3's dedicated error code for
	// a request_uri the authorization endpoint cannot use — unknown,
	// already consumed by a completed interaction, expired, or pushed
	// by a different client than the one now presenting it — as
	// distinct from ErrorInvalidRequest, which covers everything else
	// wrong with an authorization request (missing client_id, a
	// malformed request_uri reference that doesn't even parse, etc.).
	ErrorInvalidRequestURI ErrorCode = "invalid_request_uri"

	// ErrorUseDPoPNonce indicates a DPoP proof presented to the PAR or
	// token endpoint was otherwise valid but carried no nonce, or one
	// this server didn't just issue (unknown, already consumed, or
	// expired) — RFC 9449 §8's own error value, distinct from
	// ErrorInvalidGrant/ErrorInvalidRequest (the request itself is
	// fine; the caller just needs to retry with the nonce this error's
	// own Nonce method returns). Only ever returned when
	// Dependencies.Nonces is configured.
	ErrorUseDPoPNonce ErrorCode = "use_dpop_nonce"
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
	nonce       string
}

func newError(code ErrorCode, httpStatus int, description string, cause error) *Error {
	return &Error{code: code, httpStatus: httpStatus, description: description, cause: cause}
}

// Code returns the OAuth error code.
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
// internal cause and is meant for logs, not for an OAuth response body.
func (e *Error) Error() string {
	if e.cause != nil {
		return fmt.Sprintf("server: %s: %s: %v", e.code, e.description, e.cause)
	}
	return fmt.Sprintf("server: %s: %s", e.code, e.description)
}

// Unwrap returns the underlying cause, if any.
func (e *Error) Unwrap() error { return e.cause }
