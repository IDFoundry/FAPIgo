package server

import "net/http"

// AuthorizationPageHeaders wraps next — the handler for the
// authorization endpoint, or for a login, consent or error page of the
// interaction BeginAuthorization starts, the form submissions included
// — so that every response it writes carries the headers such a page
// needs:
//
//   - "Content-Security-Policy: frame-ancestors 'none'" and
//     "X-Frame-Options: DENY", so no other page can frame it. RFC 9700
//     §4.16: "Authorization servers MUST prevent clickjacking attacks":
//     a consent page framed invisibly over a page of the attacker's
//     has the user approve what they can't see. X-Frame-Options covers
//     browsers without CSP level 2, as §4.16 asks.
//   - "Referrer-Policy: no-referrer", so the request_uri in the
//     authorization URL, a bearer value until the interaction
//     completes (see BeginAuthorization), doesn't leave in a Referer
//     header: not to anything the page loads, nor to the client's
//     redirect URI.
//   - "Cache-Control: no-store", so neither the browser nor a shared
//     cache keeps a page carrying the user's details or the
//     interaction's form.
//
// The headers are set before next runs, so a handler that sets one of
// them itself replaces it: one that must be framed by a particular
// origin (RFC 9700 §4.16 lets a server allow that for a client) sets
// its own Content-Security-Policy frame-ancestors and drops
// X-Frame-Options. Wrap only these pages: an endpoint a client calls
// directly, such as the token endpoint, sets what it needs itself.
func AuthorizationPageHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "frame-ancestors 'none'")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}
