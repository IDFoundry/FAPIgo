// Package fapihttp provides the hardened HTTP transport used internally
// by client, server and resource: strict TLS verification, response-size
// limits, bounded (or disabled) redirects, endpoint origin validation,
// connection and body-read deadlines, SSRF restrictions for discovery and
// JWKS fetches, and content-type checks.
//
// Callers configure a role via a narrow HTTPClient interface (a Do method,
// matching *http.Client); fapihttp wraps whatever is supplied with these
// protections rather than trusting the caller to have applied them. It has
// no role-specific behaviour of its own — client.go, server.go and
// resource.go only differ in which protections are relevant to fetches
// that role performs (e.g. the server does not fetch client JWKS the way
// the client fetches AS discovery documents).
package fapihttp
