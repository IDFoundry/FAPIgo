package fapihttp

import "errors"

var (
	// ErrInsecureURL indicates a fetch target (the original URL or a
	// redirect destination) did not use https, and AllowLoopbackHTTP did
	// not except its host.
	ErrInsecureURL = errors.New("fapihttp: url must use https")

	// ErrSSRFBlocked indicates a fetch target's host resolved to an
	// address that isn't allowed — loopback, private, link-local,
	// unspecified, multicast, another reserved range (carrier-grade NAT,
	// documentation and benchmarking space, local-use NAT64), or an IPv6
	// transition address carrying one of those — and neither the loopback
	// fields
	// (AllowLoopbackHosts, AllowLoopbackHTTP, AllowedLoopbackHosts) nor
	// AllowedPrivateHosts excepted it. Fetch and Post refuse a host with
	// any such address before connecting; NewClient's transport skips
	// such addresses when dialing, and fails only when none is left.
	ErrSSRFBlocked = errors.New("fapihttp: target address is not allowed")

	// ErrTooManyRedirects indicates a fetch followed Config.MaxRedirects
	// redirect hops and the response was still a redirect.
	ErrTooManyRedirects = errors.New("fapihttp: too many redirects")

	// ErrRedirectOriginMismatch indicates a redirect's Location pointed
	// somewhere other than the original request's scheme and host.
	ErrRedirectOriginMismatch = errors.New("fapihttp: redirect target has a different origin than the request")

	// ErrResponseTooLarge indicates a response body exceeded
	// Config.MaxResponseBytes.
	ErrResponseTooLarge = errors.New("fapihttp: response body exceeds the configured size limit")

	// ErrUnexpectedContentType indicates a response's Content-Type header
	// did not match FetchRequest.ExpectedContentType.
	ErrUnexpectedContentType = errors.New("fapihttp: response has an unexpected content type")

	// ErrUnexpectedStatus indicates a non-redirect response's status code
	// was not 200.
	ErrUnexpectedStatus = errors.New("fapihttp: response has an unexpected status code")

	// ErrMissingTLS indicates an https request's response carried no TLS
	// connection state — a defense-in-depth check against a supplied
	// HTTPClient that silently downgraded or proxied the connection.
	ErrMissingTLS = errors.New("fapihttp: https response was not delivered over a verified TLS connection")

	// ErrRedirectFollowed indicates the supplied HTTPClient followed a
	// redirect itself, so the response answers a request to a target
	// this package never validated. New stops an *http.Client from doing
	// so; this catches any other HTTPClient that does.
	ErrRedirectFollowed = errors.New("fapihttp: the http client followed a redirect itself")
)
