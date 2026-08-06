package fapihttp

import (
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

// HTTPClient is the narrow interface Client wraps — it matches
// *http.Client's Do method, so a caller can supply either an
// *http.Client (ideally one built by NewClient) or a purpose-built
// implementation, e.g. one that adds mTLS client certificates or routes
// through a corporate proxy.
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
	http HTTPClient
	cfg  Config
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
	return &Client{http: http, cfg: cfg}, nil
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
	// redirect hop, as the authoritative check, not merely as a
	// defense-in-depth backstop.
	URL *url.URL

	// ExpectedContentType is the exact media type (ignoring parameters
	// such as charset) the response's Content-Type header must declare.
	// Required, so a caller can never accidentally accept an arbitrary
	// content type for a security-sensitive fetch.
	ExpectedContentType string
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
	if err := validateFetchURL(req.URL, c.cfg.AllowLoopbackHTTP); err != nil {
		return FetchResponse{}, err
	}

	ctx, cancel := context.WithTimeout(ctx, c.cfg.RequestTimeout)
	defer cancel()

	origin := requestOrigin(req.URL)
	target := req.URL

	for hop := 0; ; hop++ {
		res, err := c.roundTrip(ctx, target)
		if err != nil {
			return FetchResponse{}, err
		}

		if isRedirect(res.StatusCode) {
			location := res.Header.Get("Location")
			res.Body.Close()
			if hop >= c.cfg.MaxRedirects {
				return FetchResponse{}, ErrTooManyRedirects
			}
			next, err := resolveRedirect(target, location, origin, c.cfg.AllowLoopbackHTTP)
			if err != nil {
				return FetchResponse{}, err
			}
			target = next
			continue
		}

		body, readErr := readBounded(res.Body, c.cfg.MaxResponseBytes)
		res.Body.Close()
		if readErr != nil {
			return FetchResponse{}, readErr
		}
		if res.StatusCode != http.StatusOK {
			return FetchResponse{}, fmt.Errorf("%w: %d", ErrUnexpectedStatus, res.StatusCode)
		}
		if err := checkContentType(res.Header.Get("Content-Type"), req.ExpectedContentType); err != nil {
			return FetchResponse{}, err
		}
		return FetchResponse{Body: body, StatusCode: res.StatusCode}, nil
	}
}

func (c *Client) roundTrip(ctx context.Context, target *url.URL) (*http.Response, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("fapihttp: build request: %w", err)
	}
	res, err := c.http.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("fapihttp: %w", err)
	}
	if target.Scheme == "https" && res.TLS == nil {
		res.Body.Close()
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

func resolveRedirect(current *url.URL, location, origin string, allowLoopbackHTTP bool) (*url.URL, error) {
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
	if err := validateFetchURL(next, allowLoopbackHTTP); err != nil {
		return nil, err
	}
	return next, nil
}

func validateFetchURL(u *url.URL, allowLoopbackHTTP bool) error {
	if !u.IsAbs() || u.Host == "" {
		return fmt.Errorf("fapihttp: url must be absolute")
	}
	if u.User != nil {
		return fmt.Errorf("fapihttp: url must not contain embedded credentials")
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		return nil
	case "http":
		if allowLoopbackHTTP && isLoopbackHost(u.Host) {
			return nil
		}
		return ErrInsecureURL
	default:
		return ErrInsecureURL
	}
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

func checkContentType(got, want string) error {
	if got == "" {
		return fmt.Errorf("%w: response has no Content-Type", ErrUnexpectedContentType)
	}
	mediaType, _, err := mime.ParseMediaType(got)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnexpectedContentType, err)
	}
	if !strings.EqualFold(mediaType, want) {
		return fmt.Errorf("%w: got %q, want %q", ErrUnexpectedContentType, mediaType, want)
	}
	return nil
}
