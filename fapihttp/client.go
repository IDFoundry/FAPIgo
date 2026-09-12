package fapihttp

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// contentTypeHeader is the one HTTP header name this package ever sets
// or reads itself (a request's own outbound Content-Type for Post, and
// a response's inbound Content-Type for both Fetch and Post's own
// checkContentType call).
const contentTypeHeader = "Content-Type"

// HTTPClient is the narrow interface Client wraps — it matches
// *http.Client's Do method, so a caller can supply either an
// *http.Client (ideally one built by NewClient) or a purpose-built
// implementation, e.g. one that adds mTLS client certificates or routes
// through a corporate proxy.
//
// Strongly prefer an *http.Client built by NewClient. Its transport
// resolves each host itself, validates every candidate address before
// dialing, and pins the dial to an address it already validated — the
// only defense here that holds under DNS rebinding (see NewClient's doc
// comment). Fetch's own IP check (see FetchRequest.URL) is best-effort
// pre-dial validation, not a substitute: passing any other HTTPClient,
// including http.DefaultClient, means an actual round trip is made with
// whatever address that client's own transport resolves at connect
// time, which Fetch cannot see or control.
type HTTPClient interface {
	Do(*http.Request) (*http.Response, error)
}

// Config bounds every fetch a Client performs. None of these have an
// implicit default — New rejects a zero (or, for MaxRedirects, negative)
// value.
type Config struct {
	// MaxResponseBytes bounds how much of a response body Fetch reads
	// before failing — applied regardless of any Content-Length header,
	// which is untrusted until the body has actually been read.
	MaxResponseBytes int64

	// RequestTimeout bounds the total time a single Fetch call may take,
	// including every redirect hop it follows.
	RequestTimeout time.Duration

	// MaxRedirects bounds how many redirect hops Fetch will follow. Zero
	// means a redirect response is never followed — Fetch returns
	// ErrTooManyRedirects instead of the redirect body.
	MaxRedirects int

	// AllowLoopbackHTTP permits an http:// scheme when the host is a
	// loopback address, matching fapi.AllowLoopbackHTTP. It exists for
	// local development only.
	AllowLoopbackHTTP bool
}

// Client performs hardened GET fetches for discovery documents, JWKS
// documents, and similar security-sensitive resources — the recommended
// building block for an embedder's own ClientKeySource or
// IssuerKeySource implementation that fetches JWKS live, and for
// client's own AS-discovery path. See ARCHITECTURE.md design rule 6. It
// is entirely unexported — construct one with New.
type Client struct {
	http       HTTPClient
	cfg        Config
	resolveIPs func(ctx context.Context, host string) ([]net.IP, error)
}

// New validates cfg and returns a Client wrapping http.
func New(http HTTPClient, cfg Config) (*Client, error) {
	if http == nil {
		return nil, fmt.Errorf("fapihttp: http client is required")
	}
	if cfg.MaxResponseBytes <= 0 {
		return nil, fmt.Errorf("fapihttp: config: max response bytes must be positive")
	}
	if cfg.RequestTimeout <= 0 {
		return nil, fmt.Errorf("fapihttp: config: request timeout must be positive")
	}
	if cfg.MaxRedirects < 0 {
		return nil, fmt.Errorf("fapihttp: config: max redirects must not be negative")
	}
	return &Client{http: http, cfg: cfg, resolveIPs: defaultResolveIPs}, nil
}

// defaultResolveIPs resolves host via the system resolver.
func defaultResolveIPs(ctx context.Context, host string) ([]net.IP, error) {
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	ips := make([]net.IP, len(addrs))
	for i, a := range addrs {
		ips[i] = a.IP
	}
	return ips, nil
}

// FetchRequest describes one outbound GET fetch. Fetch exists for
// discovery-document and JWKS retrieval, both GET-only per the specs
// that define them — it is not a general-purpose HTTP client, and never
// hands a caller a way to build an arbitrary request.
type FetchRequest struct {
	// URL is the endpoint to fetch. The caller is responsible for having
	// already chosen it validly (e.g. a fapi.URL, or a JWKS URI resolved
	// from a discovery document under the same rules) — Fetch re-checks
	// scheme and host shape itself, on the initial request and on every
	// redirect hop, and additionally makes a best-effort check that the
	// host's resolved addresses aren't loopback/private/link-local/etc.
	// That best-effort check is pre-dial validation only: it does not by
	// itself defeat DNS rebinding, and it is not authoritative — full
	// IP-level SSRF protection, including under DNS rebinding, is
	// provided only by the transport NewClient builds (see HTTPClient
	// and NewClient's doc comments). Passing any other HTTPClient —
	// including http.DefaultClient — disables that protection and, if it
	// follows redirects itself, also bypasses Fetch's bounded
	// same-origin redirect handling.
	URL *url.URL

	// ExpectedContentType is the media type (ignoring parameters such as
	// charset, compared case-insensitively per RFC 7231 §3.1.1.1) the
	// response's Content-Type header must declare. Required, so a
	// caller can never accidentally accept an arbitrary content type
	// for a security-sensitive fetch.
	ExpectedContentType string

	// AlternateContentTypes are additional media types accepted the
	// same way as ExpectedContentType — for a resource whose own
	// registered media type (e.g. RFC 7517 §8.5.1's
	// "application/jwk-set+json" for a JWKS document) differs from
	// what most real deployments actually serve. Optional; most callers
	// leave this empty and rely on ExpectedContentType alone.
	AlternateContentTypes []string
}

// FetchResponse is a successfully fetched, size- and content-type-
// checked response body.
type FetchResponse struct {
	Body       []byte
	StatusCode int
}

// Fetch performs req, following at most c.cfg.MaxRedirects same-origin
// redirects, and enforces every protection described in Config and
// FetchRequest along the way.
func (c *Client) Fetch(ctx context.Context, req FetchRequest) (FetchResponse, error) {
	if req.URL == nil {
		return FetchResponse{}, fmt.Errorf("fapihttp: url is required")
	}
	if req.ExpectedContentType == "" {
		return FetchResponse{}, fmt.Errorf("fapihttp: expected content type is required")
	}

	ctx, cancel := context.WithTimeout(ctx, c.cfg.RequestTimeout)
	defer cancel()

	if err := c.validateFetchURL(ctx, req.URL); err != nil {
		return FetchResponse{}, err
	}

	origin := requestOrigin(req.URL)
	target := req.URL

	for hop := 0; ; hop++ {
		res, err := c.roundTrip(ctx, target)
		if err != nil {
			return FetchResponse{}, err
		}

		if isRedirect(res.StatusCode) {
			location := res.Header.Get("Location")
			_ = res.Body.Close()
			if hop >= c.cfg.MaxRedirects {
				return FetchResponse{}, ErrTooManyRedirects
			}
			next, err := c.resolveRedirect(ctx, target, location, origin)
			if err != nil {
				return FetchResponse{}, err
			}
			target = next
			continue
		}

		return c.readResponse(res, c.cfg.MaxResponseBytes, req.ExpectedContentType, req.AlternateContentTypes)
	}
}

// readResponse reads and validates res the same way for both Fetch's
// final (non-redirect) response and every Post response: bounded read,
// non-200 rejected, Content-Type checked. Always closes res.Body.
func (c *Client) readResponse(res *http.Response, maxBytes int64, expectedContentType string, alternateContentTypes []string) (FetchResponse, error) {
	body, readErr := readBounded(res.Body, maxBytes)
	_ = res.Body.Close()
	if readErr != nil {
		return FetchResponse{}, readErr
	}
	if res.StatusCode != http.StatusOK {
		return FetchResponse{}, fmt.Errorf("%w: %d", ErrUnexpectedStatus, res.StatusCode)
	}
	if err := checkContentType(res.Header.Get(contentTypeHeader), expectedContentType, alternateContentTypes); err != nil {
		return FetchResponse{}, err
	}
	return FetchResponse{Body: body, StatusCode: res.StatusCode}, nil
}

// PostRequest describes one outbound POST — the counterpart to
// FetchRequest for a caller that needs to submit a body rather than
// merely retrieve a resource (e.g. OpenID Federation 1.0 §8's Trust
// Mark Status endpoint, POST-only per spec). Like FetchRequest, it is
// narrow and single-purpose: there is no way to add arbitrary headers
// or otherwise build an unconstrained request.
type PostRequest struct {
	// URL is the endpoint to POST to. Validated exactly like
	// FetchRequest.URL — see its own doc comment for what that does and
	// does not guarantee.
	URL *url.URL

	// Body is the request body, sent as-is.
	Body []byte

	// ContentType is the request's own Content-Type header. Required.
	ContentType string

	// ExpectedContentType is the response's required Content-Type, and
	// AlternateContentTypes any additional accepted values — both work
	// exactly like their FetchRequest counterparts.
	ExpectedContentType   string
	AlternateContentTypes []string
}

// Post performs req and returns the response, enforcing every
// protection Fetch does (URL/SSRF validation, response size limit,
// content-type check, TLS verification) — with one deliberate
// difference: Post never follows a redirect. Resending a POST body
// across a 3xx has ambiguous semantics that differ by status code
// (307/308 preserve method and body; 301/302/303 don't, and most
// clients silently downgrade to GET), and nothing in the specs this
// method exists for requires a POST-only endpoint to redirect at all.
// A 3xx response is therefore treated as ErrUnexpectedStatus, the same
// as any other non-200 — not specially followed the way Fetch's own
// bounded, origin-checked redirect handling does for GET.
func (c *Client) Post(ctx context.Context, req PostRequest) (FetchResponse, error) {
	if req.URL == nil {
		return FetchResponse{}, fmt.Errorf("fapihttp: url is required")
	}
	if req.ContentType == "" {
		return FetchResponse{}, fmt.Errorf("fapihttp: content type is required")
	}
	if req.ExpectedContentType == "" {
		return FetchResponse{}, fmt.Errorf("fapihttp: expected content type is required")
	}

	ctx, cancel := context.WithTimeout(ctx, c.cfg.RequestTimeout)
	defer cancel()

	if err := c.validateFetchURL(ctx, req.URL); err != nil {
		return FetchResponse{}, err
	}

	res, err := c.doRoundTrip(ctx, http.MethodPost, req.URL, req.Body, req.ContentType)
	if err != nil {
		return FetchResponse{}, err
	}
	return c.readResponse(res, c.cfg.MaxResponseBytes, req.ExpectedContentType, req.AlternateContentTypes)
}

func (c *Client) roundTrip(ctx context.Context, target *url.URL) (*http.Response, error) {
	return c.doRoundTrip(ctx, http.MethodGet, target, nil, "")
}

// doRoundTrip is roundTrip generalized over method/body/contentType —
// Fetch's own behavior (GET, no body) is unchanged; Post is the only
// other caller.
func (c *Client) doRoundTrip(ctx context.Context, method string, target *url.URL, body []byte, contentType string) (*http.Response, error) {
	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}
	httpReq, err := http.NewRequestWithContext(ctx, method, target.String(), bodyReader)
	if err != nil {
		return nil, fmt.Errorf("fapihttp: build request: %w", err)
	}
	if contentType != "" {
		httpReq.Header.Set(contentTypeHeader, contentType)
	}
	res, err := c.http.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("fapihttp: %w", err)
	}
	if target.Scheme == "https" && res.TLS == nil {
		_ = res.Body.Close()
		return nil, ErrMissingTLS
	}
	return res, nil
}

func isRedirect(status int) bool {
	switch status {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther,
		http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		return true
	default:
		return false
	}
}

func requestOrigin(u *url.URL) string {
	return strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host)
}

func (c *Client) resolveRedirect(ctx context.Context, current *url.URL, location, origin string) (*url.URL, error) {
	if location == "" {
		return nil, fmt.Errorf("fapihttp: redirect response has no Location header")
	}
	parsed, err := url.Parse(location)
	if err != nil {
		return nil, fmt.Errorf("fapihttp: parse redirect location: %w", err)
	}
	next := current.ResolveReference(parsed)
	if requestOrigin(next) != origin {
		return nil, ErrRedirectOriginMismatch
	}
	if err := c.validateFetchURL(ctx, next); err != nil {
		return nil, err
	}
	return next, nil
}

// validateFetchURL checks u's scheme/host shape and, for an https URL
// not exempted by AllowLoopbackHTTP, makes a best-effort check that
// every address the host resolves to is allowed — see FetchRequest.URL
// and HTTPClient's doc comments for what this does and does not
// guarantee.
func (c *Client) validateFetchURL(ctx context.Context, u *url.URL) error {
	if !u.IsAbs() || u.Host == "" {
		return fmt.Errorf("fapihttp: url must be absolute")
	}
	if u.User != nil {
		return fmt.Errorf("fapihttp: url must not contain embedded credentials")
	}
	loopbackExempt := c.cfg.AllowLoopbackHTTP && isLoopbackHost(u.Host)
	switch strings.ToLower(u.Scheme) {
	case "https":
		if loopbackExempt {
			return nil
		}
		return c.checkHostIPs(ctx, u.Hostname())
	case "http":
		if loopbackExempt {
			return nil
		}
		return ErrInsecureURL
	default:
		return ErrInsecureURL
	}
}

// checkHostIPs resolves host (via c.resolveIPs, or directly if host is
// already an IP literal) and returns ErrSSRFBlocked if any resulting
// address is disallowed per disallowedIP. This is pre-dial validation
// only: it does not defeat DNS rebinding, since the caller's own
// HTTPClient may re-resolve the host at connect time — see
// FetchRequest.URL's doc comment.
func (c *Client) checkHostIPs(ctx context.Context, host string) error {
	if ip := net.ParseIP(host); ip != nil {
		if disallowedIP(ip, c.cfg.AllowLoopbackHTTP) {
			return ErrSSRFBlocked
		}
		return nil
	}
	ips, err := c.resolveIPs(ctx, host)
	if err != nil {
		return fmt.Errorf("fapihttp: resolve host: %w", err)
	}
	if len(ips) == 0 {
		return ErrSSRFBlocked
	}
	for _, ip := range ips {
		if disallowedIP(ip, c.cfg.AllowLoopbackHTTP) {
			return ErrSSRFBlocked
		}
	}
	return nil
}

func isLoopbackHost(host string) bool {
	h := host
	if hostOnly, _, err := net.SplitHostPort(host); err == nil {
		h = hostOnly
	}
	if strings.EqualFold(h, "localhost") {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

func readBounded(r io.Reader, max int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, max+1))
	if err != nil {
		return nil, fmt.Errorf("fapihttp: read response body: %w", err)
	}
	if int64(len(data)) > max {
		return nil, ErrResponseTooLarge
	}
	return data, nil
}

func checkContentType(got, want string, alternates []string) error {
	if got == "" {
		return fmt.Errorf("%w: response has no Content-Type", ErrUnexpectedContentType)
	}
	mediaType, _, err := mime.ParseMediaType(got)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnexpectedContentType, err)
	}
	if strings.EqualFold(mediaType, want) {
		return nil
	}
	for _, alt := range alternates {
		if strings.EqualFold(mediaType, alt) {
			return nil
		}
	}
	return fmt.Errorf("%w: got %q, want %q", ErrUnexpectedContentType, mediaType, want)
}
