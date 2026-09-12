package resource

import (
	"errors"
	"net/http"

	"github.com/idfoundry/fapigo/internal/httperror"
)

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

// NewError builds an *Error for a caller reporting an RFC 6750/RFC 9449
// -shaped failure it detected itself — an HTTP adapter's own request
// routing rejecting something before it ever calls Verify (a malformed
// Authorization header, more than one DPoP header — see
// dpop.ResolveHeaderValues). Mirrors server.NewError.
func NewError(code ErrorCode, httpStatus int, description string) *Error {
	return &Error{code: code, httpStatus: httpStatus, description: description}
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
	return httperror.Message("resource", string(e.code), e.description, e.cause)
}

// Unwrap returns the underlying cause, if any.
func (e *Error) Unwrap() error { return e.cause }

// WriteJSON writes e as a complete RFC 6750 §3.1 challenge response to
// w: a WWW-Authenticate header, the DPoP-Nonce header when Nonce is
// non-empty (RFC 9449 §8 — see Nonce's own doc comment for when that
// is), the "application/json" Content-Type, e's own HTTPStatus, and a
// {"error": ..., "error_description": ...} body built from Code and
// PublicDescription — never Unwrap's cause. Every *Error this
// package's own methods return, and any built with NewError, is safe
// to pass here.
//
// The WWW-Authenticate scheme is "DPoP" when Code is ErrorUseDPoPNonce
// (the only sensible scheme there — that error is impossible for a
// request that didn't present a DPoP proof in the first place) and
// "Bearer" otherwise: this package accepts both DPoP-bound and
// mTLS-bound access tokens on the same Verifier (SenderConstrain is
// resolved per token/request, not fixed per deployment — see
// VerifyRequest.PeerCertificate's own doc comment), and RFC 8705 §3.4
// presents an mTLS-bound token as an ordinary Bearer credential with no
// scheme of its own. "Bearer" is the universally correct RFC 6750
// challenge regardless of which binding a given rejected request
// actually used.
//
// Must be called before anything else writes to w — like every
// http.ResponseWriter header/status call, it has no effect once a
// prior write has already sent the response's status line.
func (e *Error) WriteJSON(w http.ResponseWriter) {
	scheme := "Bearer"
	if e.code == ErrorUseDPoPNonce {
		scheme = "DPoP"
	}
	httperror.WriteJSON(w, e.nonce, scheme, string(e.code), e.description, e.httpStatus)
}

// WriteError writes err to w: err's own WriteJSON if err is a *Error
// (as every error Verify returns is), or a generic 500 otherwise —
// the one case this package can't itself produce a *Error for, e.g. a
// context cancellation surfacing from a dependency. Saves every HTTP
// adapter from reimplementing this same errors.As-or-fallback dance
// itself.
func WriteError(w http.ResponseWriter, err error) {
	var resErr *Error
	if errors.As(err, &resErr) {
		resErr.WriteJSON(w)
		return
	}
	http.Error(w, "server_error", http.StatusInternalServerError)
}
