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
		"unreadable": func() *http.Request {
			r := newFormPOST(t, form, "")
			r.Body = io.NopCloser(failingBody{})
			return r
		},
	}
	constructors := map[string]func(*http.Request) error{
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
	}
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
