package server_test

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/idfoundry/fapigo/server"
)

// WriteError writes any error a Server method returns as the OAuth
// error response (RFC 6749 §5.2) its *Error describes. An HTTP adapter
// uses NewError for a failure it detects itself, such as a grant_type
// it doesn't route; anything else becomes a generic 500.
func ExampleWriteError() {
	rec := httptest.NewRecorder()
	server.WriteError(rec, server.NewError(server.ErrorUnsupportedGrantType, http.StatusBadRequest, "grant_type must be authorization_code"))
	fmt.Println(rec.Code, rec.Header().Get("Content-Type"))
	fmt.Println(strings.TrimSpace(rec.Body.String()))

	rec = httptest.NewRecorder()
	server.WriteError(rec, errors.New("database unreachable"))
	fmt.Println(rec.Code)
	// Output:
	// 400 application/json
	// {"error":"unsupported_grant_type","error_description":"grant_type must be authorization_code"}
	// 500
}

// Metadata.WriteJSON serves the discovery document. Serve it at the
// issuer plus "/.well-known/openid-configuration", where client.Discover
// looks for it.
func ExampleMetadata_WriteJSON() {
	// In a handler: srv.Metadata(r.Context()).WriteJSON(w).
	var md server.Metadata
	md.ResponseTypesSupported = []string{"code"}

	rec := httptest.NewRecorder()
	md.WriteJSON(rec)
	fmt.Println(rec.Code, rec.Header().Get("Content-Type"))
	// Output:
	// 200 application/json
}
