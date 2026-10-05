// Package nofollow keeps an outbound HTTP client from following
// redirects on its own, for every caller in this module that sends
// credentials or validates a target before sending: a redirect followed
// inside the client would resend a request (with its client assertion,
// access token or DPoP proof) to a target the caller never checked.
package nofollow

import (
	"errors"
	"io"
	"net/http"
)

// Doer is the Do method of *http.Client — the shape of
// fapihttp.HTTPClient and client.Dependencies.HTTP.
type Doer interface {
	Do(*http.Request) (*http.Response, error)
}

// Client returns d made to never follow a redirect itself. An
// *http.Client is copied with its CheckRedirect set to return
// http.ErrUseLastResponse, so a 3xx comes back to the caller as the
// response; the caller's own value is left untouched, and later changes
// to it aren't seen by the copy. Any other Doer is returned as is —
// Followed then detects, after the fact, one that followed a redirect.
func Client(d Doer) Doer {
	c, ok := d.(*http.Client)
	if !ok || c == nil {
		return d
	}
	copied := *c
	copied.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &copied
}

// Followed reports whether res answers a request other than req: a
// Doer that followed a redirect itself returns the last hop's response,
// whose Request carries that hop's URL.
func Followed(req *http.Request, res *http.Response) bool {
	if res == nil || res.Request == nil || res.Request.URL == nil || req.URL == nil {
		return false
	}
	return res.Request.URL.String() != req.URL.String()
}

// ErrBodyNotResent is what a request's GetBody answers once SendOnce
// has made its body single-use: net/http asks GetBody for a fresh body
// only to resend the request — to the target of a 307 or 308 redirect,
// or after a connection failed once the body was read — and this module
// sends a body carrying credentials exactly once, to the target it
// checked.
var ErrBodyNotResent = errors.New("the request body is sent once and never resent (a 307/308 redirect or a retry asked for it again)")

// SendOnce makes req's body single-use when d isn't an *http.Client —
// a metrics or tracing wrapper, say, which Client can't stop following
// redirects — so an *http.Client inside it never resends the body
// across a 307 or 308: its redirect handling calls GetBody before
// building the redirected request, and GetBody now refuses with
// ErrBodyNotResent, which d returns as its error. GetBody is left
// non-nil rather than nil so net/http still retries a request on a
// reused keep-alive connection that failed before any of it was
// written, which never needs a fresh body.
//
// An *http.Client is left alone: every one this module sends with is
// Client's copy, which never follows, and keeping its GetBody lets it
// return a 307 or 308 to the caller as the response — net/http calls
// GetBody before CheckRedirect, so a refusing GetBody would turn that
// response into an error. A body-less request is left as is too: a GET
// carries no body to resend, and a redirect of it can only be detected
// afterwards, by Followed.
func SendOnce(d Doer, req *http.Request) {
	if _, ok := d.(*http.Client); ok {
		return
	}
	if req.Body == nil || req.Body == http.NoBody {
		return
	}
	req.GetBody = func() (io.ReadCloser, error) { return nil, ErrBodyNotResent }
}
