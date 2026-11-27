package resource

import (
	"context"
	"net/http"
	"net/url"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/canonical"
)

// resourceOriginKey is the context key WithResourceOrigin marks a
// request's origin under.
type resourceOriginKey struct{}

// WithResourceOrigin returns a handler that serves each request with
// next, marked as received at origin's scheme and host (its path, if
// any, is ignored). VerifyRequestFromHTTP takes the mark, and Verify
// then places the request's escaped path only under the
// Config.ResourceURLs at that origin. A resource server reachable under
// more than one origin, such as an mTLS alias host, whose ResourceURLs
// cover one path at several of them, needs the mark (or
// VerifyRequest.URL) for each DPoP request: a proof names one URL (RFC
// 9449 §4.3), and the Host header the client sends can't say which, or
// a proof captured at one origin could be spent again at another. Wrap
// each listener's handler with its own origin:
//
//	primary := &http.Server{Handler: resource.WithResourceOrigin(apiURL, mux)}
//	alias := &http.Server{Handler: resource.WithResourceOrigin(mtlsAPIURL, mux)}
//
// origin must be the origin of one of Config.ResourceURLs, or Verify
// refuses every request marked with it as a 500. An explicit
// VerifyRequest.URL takes precedence over the mark, and the innermost
// WithResourceOrigin wins.
func WithResourceOrigin(origin fapi.URL, next http.Handler) http.Handler {
	u := origin.URL()
	key := canonical.URI(&url.URL{Scheme: u.Scheme, Host: u.Host})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), resourceOriginKey{}, key)))
	})
}

// resourceOriginOf is the canonical origin WithResourceOrigin marked r
// with, or "".
func resourceOriginOf(r *http.Request) string {
	origin, _ := r.Context().Value(resourceOriginKey{}).(string)
	return origin
}
