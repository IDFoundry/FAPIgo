// Package nofollow keeps an outbound HTTP client from following
// redirects on its own, for every caller in this module that sends
// credentials or validates a target before sending: a redirect followed
// inside the client would resend a request (with its client assertion,
// access token or DPoP proof) to a target the caller never checked.
package nofollow

import "net/http"

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
