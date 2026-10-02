package resource

import (
	"errors"
	"net/http"

	"github.com/idfoundry/fapigo/internal/httperror"
)

// ErrorCode is a closed set of error codes, matching the "error" values
// RFC 6750 §3.1 and RFC 9449 §7.1 define for a WWW-Authenticate
// challenge. Verify returns every one except ErrorInsufficientScope,
// which only the protected resource itself can decide.
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

	// ErrorInvalidDPoPProof is RFC 9449 §7.1's error for a DPoP proof
	// "deemed invalid based on the criteria of Section 4.3" — one that
	// fails verification, is replayed, or isn't the only DPoP header —
	// distinct from ErrorInvalidToken, which is about the access token.
	// Always sent in a DPoP challenge.
	ErrorInvalidDPoPProof ErrorCode = "invalid_dpop_proof"

	// ErrorInsufficientScope is RFC 6750 §3.1's "The request requires
	// higher privileges than provided by the access token", sent with
	// HTTP 403 Forbidden. Verify never returns it: a token that verifies
	// is valid, and only the protected resource knows whether it covers
	// the request — its scope, or its granted authorization_details
	// (RFC 9396). An adapter reports that with
	// NewError(ErrorInsufficientScope, http.StatusForbidden, ...).
	ErrorInsufficientScope ErrorCode = "insufficient_scope"
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
	// dpopChallenge sends the error in a DPoP challenge: set by Verify
	// for a request that used the DPoP scheme (RFC 9449 §7.2).
	dpopChallenge bool
}

// wwwAuthenticate is the challenge header (RFC 6750 §3, RFC 9449 §7.1).
const wwwAuthenticate = "WWW-Authenticate"

// noCredentials is the error for a request presenting no credentials
// this verifier accepts: 401 with an empty Code, so WriteJSON sends a
// challenge without error information (RFC 6750 §3.1). reason is for
// logs only.
func noCredentials(reason string) *Error {
	return &Error{httpStatus: 401, cause: errors.New(reason)}
}

// dpopAlgorithms is the algs parameter of a DPoP challenge (RFC 9449
// §7.1): every algorithm the verifier accepts a DPoP proof signed with.
const dpopAlgorithms = "ES256 PS256 EdDSA"

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

// Code returns the error code — empty for a request that presented no
// credentials at all, which RFC 6750 §3.1 answers without one (see
// Verify).
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
// The challenge follows RFC 9449 §7.2, for a verifier accepting both
// DPoP-bound and mTLS-bound tokens (the latter presented with the Bearer
// scheme, RFC 8705 §3.4):
//
//   - An Error with an empty Code — the request presented no credentials
//     this verifier accepts — gets "Bearer, DPoP algs=..." with no error
//     information and no body, as RFC 6750 §3.1 asks.
//   - An error for a request that used the DPoP scheme, and
//     ErrorUseDPoPNonce and ErrorInvalidDPoPProof, gets a DPoP challenge
//     with the error and algs.
//   - Anything else, including every error built with NewError, gets a
//     Bearer challenge with the error.
//
// Must be called before anything else writes to w — like every
// http.ResponseWriter header/status call, it has no effect once a
// prior write has already sent the response's status line.
func (e *Error) WriteJSON(w http.ResponseWriter) {
	switch {
	case e.code == "":
		w.Header().Set(wwwAuthenticate, `Bearer, DPoP algs="`+dpopAlgorithms+`"`)
		w.WriteHeader(e.httpStatus)
		return
	case e.dpopChallenge || e.code == ErrorUseDPoPNonce || e.code == ErrorInvalidDPoPProof:
		w.Header().Set(wwwAuthenticate, `DPoP error="`+string(e.code)+`", algs="`+dpopAlgorithms+`"`)
	default:
		w.Header().Set(wwwAuthenticate, `Bearer error="`+string(e.code)+`"`)
	}
	httperror.WriteJSON(w, e.nonce, "", string(e.code), e.description, e.httpStatus)
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
