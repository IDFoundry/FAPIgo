package server

import "github.com/idfoundry/fapigo/internal/redact"

// RequestURI is an opaque request_uri value returned by
// PushAuthorizationRequest. It has no public constructor — only this
// package can produce one — so a caller can pass it around without being
// able to forge one.
//
// A live request_uri is a bearer value in the front channel until its
// interaction completes (see BeginAuthorization). String is its wire
// value, for the pushed authorization response, so fmt.Sprint, %s and
// %v print it: never log a RequestURI on its own with fmt. log/slog logs
// one given as an attribute as [REDACTED] (LogValue), and every
// rendering of PushAuthorizationResult shows [REDACTED]; but log/slog's
// text handler prints a struct with %+v, so a RequestURI in an exported
// field of a struct of yours logs its wire value. fmt's reflection
// fallback (a RequestURI in an unexported field, or under a verb other
// than v, s, q, x and X) prints an address.
type RequestURI struct {
	value redact.Handle
}

// String returns the request_uri's wire value.
func (r RequestURI) String() string { return r.value.Reveal() }
