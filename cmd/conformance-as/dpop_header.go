package main

import "net/http"

// singleDPoPHeader returns the request's DPoP header value, and false if
// more than one was presented. RFC 9449 §7.1 requires a request carry at
// most one DPoP header; collapsing several into "the first one" (what
// http.Header.Get does) would silently accept something the spec
// requires rejecting outright, so callers must check ok before treating
// an empty proof as "none supplied".
func singleDPoPHeader(r *http.Request) (proof string, ok bool) {
	values := r.Header.Values("DPoP")
	if len(values) > 1 {
		return "", false
	}
	if len(values) == 0 {
		return "", true
	}
	return values[0], true
}
