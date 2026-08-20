package client

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// postFormResponse is a hardened application/x-www-form-urlencoded POST:
// bounded by c.cfg.Limits.HTTPTimeout and c.cfg.Limits.MaxHTTPResponseBytes,
// with every extra header added by extraHeaders. fapihttp.Client.Fetch
// does not fit this call shape — it is a GET-only fetch for discovery
// and JWKS documents (see its own doc comment) — so this package applies
// the same class of protections directly for the POST calls PAR and
// token-endpoint submission require. Response headers are returned
// alongside the body so a caller can read a DPoP-Nonce challenge
// (RFC 9449 §8) without a second round trip.
func (c *Client) postForm(ctx context.Context, url string, body []byte, extraHeaders map[string]string) ([]byte, int, http.Header, error) {
	ctx, cancel := context.WithTimeout(ctx, c.cfg.Limits.HTTPTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(string(body)))
	if err != nil {
		return nil, 0, nil, fmt.Errorf("client: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	for k, v := range extraHeaders {
		req.Header.Set(k, v)
	}

	res, err := c.deps.HTTP.Do(req)
	if err != nil {
		return nil, 0, nil, fmt.Errorf("client: %w", err)
	}
	defer func() { _ = res.Body.Close() }()

	data, err := io.ReadAll(io.LimitReader(res.Body, c.cfg.Limits.MaxHTTPResponseBytes+1))
	if err != nil {
		return nil, 0, nil, fmt.Errorf("client: read response body: %w", err)
	}
	if int64(len(data)) > c.cfg.Limits.MaxHTTPResponseBytes {
		return nil, 0, nil, fmt.Errorf("client: response body exceeds the configured size limit")
	}
	return data, res.StatusCode, res.Header, nil
}
