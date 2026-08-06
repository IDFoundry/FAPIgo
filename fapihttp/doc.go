// Package fapihttp provides the hardened HTTP transport used internally
// by client, server and resource: strict TLS verification, response-size
// limits, bounded (or disabled) redirects, endpoint origin validation,
// connection and body-read deadlines, SSRF restrictions for discovery and
// JWKS fetches, and content-type checks.
//
// Callers configure a role via a narrow HTTPClient interface (a Do method,
// matching *http.Client); fapihttp wraps whatever is supplied with these
// protections rather than trusting the caller to have applied them. It has
// no role-specific behaviour of its own — every role differentiates its
// fetches (e.g. the server does not fetch client JWKS the way the client
// fetches AS discovery documents) through Client.Fetch's FetchRequest
// fields, such as ExpectedContentType, rather than through separate
// per-role types.
//
// NewClient additionally builds an *http.Client with a hardened
// *http.Transport (SSRF-resistant dialing that validates a resolved
// address before connecting to it, TLS 1.2 minimum, no automatic
// redirect following) for callers who don't need to supply their own — see
// Client.Fetch for why a Fetch-level URL/origin check on its own cannot
// substitute for that, and why fapihttp owns bounded redirect handling
// itself instead of delegating it to the underlying HTTP client.
package fapihttp
