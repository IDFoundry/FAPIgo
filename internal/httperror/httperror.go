// Package httperror is the shared mechanical bookkeeping every
// role-specific error type (server.Error, resource.Error,
// federation.Error) delegates its method bodies to. Deliberately NOT a
// shared struct or generic type each role aliases/embeds: an earlier
// version of this package tried that, but `go doc` (and, by extension,
// pkg.go.dev) never resolves methods through a type alias — or an
// embedded field — to a type in another package once that type is
// generic, so every method's own doc comment became invisible to an
// integrator running `go doc github.com/idfoundry/fapigo/server Error`.
// Each role keeps its own concrete Error struct, its own fields, and
// its own fully-documented methods; only the multi-line logic inside a
// method body (JSON encoding, header-writing, message formatting) is
// shared here, which is genuinely all that was identical — the
// documented, discoverable API surface never was.
package httperror

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// Message formats the log-facing message every role's own Error()
// method returns: pkg is the short name (e.g. "server") to prefix it
// with, and cause (if any) is appended — never included in a public
// response, only in this message.
func Message(pkg, code, description string, cause error) string {
	if cause != nil {
		return fmt.Sprintf("%s: %s: %s: %v", pkg, code, description, cause)
	}
	return fmt.Sprintf("%s: %s: %s", pkg, code, description)
}

// WriteJSON writes a role's own error as a complete JSON error response
// to w: the DPoP-Nonce header when nonce is non-empty (RFC 9449 §8),
// the WWW-Authenticate header when challengeScheme is non-empty (RFC
// 6750 §3.1 — resource's own errors are the only ones that set this),
// the "application/json" Content-Type, httpStatus, and a
// {"error": ..., "error_description": ...} body built from code and
// description.
//
// Must be called before anything else writes to w — like every
// http.ResponseWriter header/status call, it has no effect once a
// prior write has already sent the response's status line.
func WriteJSON(w http.ResponseWriter, nonce, challengeScheme, code, description string, httpStatus int) {
	if nonce != "" {
		w.Header().Set("DPoP-Nonce", nonce)
	}
	if challengeScheme != "" {
		w.Header().Set("WWW-Authenticate", challengeScheme+` error="`+code+`"`)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(httpStatus)
	// Encoding two plain strings cannot fail.
	_ = json.NewEncoder(w).Encode(struct {
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description,omitempty"`
	}{Error: code, ErrorDescription: description})
}
