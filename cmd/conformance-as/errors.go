package main

import (
	"net/http"

	"github.com/idfoundry/fapigo/internal/par"
	"github.com/idfoundry/fapigo/server"
)

// writeOAuthJSONError translates err into an OAuth JSON error response
// (RFC 6749 §5.2). Every server package method's error return is a
// *server.Error; the fallback below only triggers for something outside
// the request itself (e.g. context cancellation propagating from a
// dependency).
func writeOAuthJSONError(w http.ResponseWriter, err error) {
	srvErr, ok := err.(*server.Error)
	if !ok {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeRawOAuthError(w, srvErr.HTTPStatus(), string(srvErr.Code()), srvErr.PublicDescription())
}

// writeRawOAuthError writes an OAuth JSON error response directly, for
// failures detected before a *server.Error exists at all (e.g. a
// malformed form body, or an unsupported grant_type).
func writeRawOAuthError(w http.ResponseWriter, status int, code, description string) {
	body, err := par.EncodeErrorResponse(par.ErrorResponse{Code: code, Description: description})
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write(body)
}

// writeLocalHTMLError renders err as a browser-facing HTML page, never a
// JSON body and never a redirect — the contract server/authorization.go
// and server/complete_authorization.go's closed sum types establish for
// LocalErrorResponse/AuthorizationLocalError: the interaction could not
// be validated well enough to trust any redirect destination.
func writeLocalHTMLError(w http.ResponseWriter, err *server.Error) {
	writeLocalHTMLErrorRaw(w, err.HTTPStatus(), string(err.Code()), err.PublicDescription())
}

// writeLocalHTMLErrorRaw renders a browser-facing HTML error page
// directly, for failures the consent handler detects itself (an unknown
// interaction handle, a missing decision) before any *server.Error
// exists.
func writeLocalHTMLErrorRaw(w http.ResponseWriter, status int, code, description string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_ = localErrorTemplate.Execute(w, localErrorPage{Code: code, Description: description})
}
