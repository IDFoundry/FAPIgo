package server_test

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/idfoundry/fapigo/server"
)

type failingBody struct{}

func (failingBody) Read([]byte) (int, error) { return 0, errors.New("connection reset") }

// formConstructors is every constructor built on FormRequestFromHTTP,
// BeginAuthorizationRequestFromHTTP given a POST.
func formConstructors() map[string]func(*http.Request) error {
	return map[string]func(*http.Request) error{
		"FormRequestFromHTTP": func(r *http.Request) error { _, err := server.FormRequestFromHTTP(r); return err },
		"PushAuthorizationRequestFromHTTP": func(r *http.Request) error {
			_, err := server.PushAuthorizationRequestFromHTTP(r)
			return err
		},
		"TokenEndpointRequestFromHTTP": func(r *http.Request) error { _, err := server.TokenEndpointRequestFromHTTP(r); return err },
		"BeginBackchannelAuthenticationRequestFromHTTP": func(r *http.Request) error {
			_, err := server.BeginBackchannelAuthenticationRequestFromHTTP(r)
			return err
		},
		"TokenRevocationRequestFromHTTP": func(r *http.Request) error {
			_, err := server.TokenRevocationRequestFromHTTP(r)
			return err
		},
		"BeginAuthorizationRequestFromHTTP": func(r *http.Request) error {
			_, err := server.BeginAuthorizationRequestFromHTTP(r)
			return err
		},
	}
}

// TestFromHTTPBodyFailuresAreInvalidRequest covers every way a request
// body can't be taken, through each constructor built on
// FormRequestFromHTTP: each is a 400 invalid_request *Error, so
// WriteError answers the client's mistake as one, not as a 500.
func TestFromHTTPBodyFailuresAreInvalidRequest(t *testing.T) {
	const form = "application/x-www-form-urlencoded"
	bodies := map[string]func() *http.Request{
		"wrong content type": func() *http.Request { return newFormPOST(t, "application/json", `{}`) },
		"malformed name":     func() *http.Request { return newFormPOST(t, form, "%zz=value") },
		"malformed value":    func() *http.Request { return newFormPOST(t, form, "grant_type=%zz") },
		"oversized":          func() *http.Request { return newFormPOST(t, form, "a="+strings.Repeat("a", 1<<20+1)) },
		"too many parameters": func() *http.Request {
			return newFormPOST(t, form, "&"+numberedForm(101, "&&"))
		},
		"unreadable": func() *http.Request {
			r := newFormPOST(t, form, "")
			r.Body = io.NopCloser(failingBody{})
			return r
		},
	}
	constructors := formConstructors()
	for body, request := range bodies {
		for name, construct := range constructors {
			err := construct(request())
			var serr *server.Error
			if !errors.As(err, &serr) || serr.Code() != server.ErrorInvalidRequest || serr.HTTPStatus() != http.StatusBadRequest {
				t.Errorf("%s(%s) = %v, want a 400 invalid_request *server.Error", name, body, err)
				continue
			}
			w := httptest.NewRecorder()
			server.WriteError(w, err)
			if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), `"invalid_request"`) {
				t.Errorf("WriteError(%s(%s)) = %d %s, want 400 invalid_request", name, body, w.Code, w.Body)
			}
		}
	}
}

// TestFromHTTPConstructorsTakeTheParameterBound: each constructor built
// on FormRequestFromHTTP takes a body of exactly 100 parameters, empty
// pairs around and between them, so what it refuses is never stricter
// than the bound the server's methods hold a FormRequest to.
func TestFromHTTPConstructorsTakeTheParameterBound(t *testing.T) {
	for name, construct := range formConstructors() {
		if err := construct(newFormPOST(t, "application/x-www-form-urlencoded", "&&"+numberedForm(100, "&&&")+"&")); err != nil {
			t.Errorf("%s(100 parameters) = %v, want no error", name, err)
		}
	}
}
