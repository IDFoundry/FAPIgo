package resource_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/idfoundry/fapigo/resource"
)

// A resource server answers a request it refuses with the error's
// WriteJSON: the status, an RFC 6750 WWW-Authenticate challenge and the
// JSON body. Verify's own errors are already *Error values; NewError is
// for a refusal the resource server decides itself.
func ExampleNewError() {
	rec := httptest.NewRecorder()
	resource.NewError(resource.ErrorInvalidToken, http.StatusUnauthorized, "the access token has expired").WriteJSON(rec)
	fmt.Println(rec.Code)
	fmt.Println(rec.Header().Get("WWW-Authenticate"))
	fmt.Println(strings.TrimSpace(rec.Body.String()))
	// Output:
	// 401
	// Bearer error="invalid_token"
	// {"error":"invalid_token","error_description":"the access token has expired"}
}
