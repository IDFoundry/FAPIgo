package backchannelhttp

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/idfoundry/fapigo/fapihttp"
	"github.com/idfoundry/fapigo/server"
)

// maxDrainBytes bounds how much of a notification endpoint's response
// body Notify reads before discarding it. The body's content is never
// used for anything — only the status code is — so this exists purely
// to let the connection be reused without risking an unbounded read
// against a hostile or misbehaving endpoint.
const maxDrainBytes = 64 << 10

// Config bounds the Notifier New builds. Timeout has no implicit
// default — New rejects a non-positive value.
type Config struct {
	// Timeout bounds how long a single Notify call may take, in addition
	// to whatever deadline ctx itself already carries — whichever is
	// shorter wins. server.BackchannelNotifier.Notify is called
	// synchronously from the request path that decided a CIBA
	// backchannel authentication request, and its own doc comment
	// requires the caller to treat every error as best-effort
	// informational only — but a hung client notification endpoint
	// should still never be able to stall that caller indefinitely.
	Timeout time.Duration
}

// Notifier is a server.BackchannelNotifier that sends every notification
// through an http-supplied transport. Construct one with New.
type Notifier struct {
	http    fapihttp.HTTPClient
	timeout time.Duration
}

// New returns a Notifier that sends every notification through http,
// bounded by cfg. Strongly prefer an *http.Client built by
// fapihttp.NewClient — see its own doc comment for the SSRF/DNS-rebinding
// protection a plain http.DefaultClient doesn't provide.
func New(http fapihttp.HTTPClient, cfg Config) (*Notifier, error) {
	if http == nil {
		return nil, fmt.Errorf("backchannelhttp: http client is required")
	}
	if cfg.Timeout <= 0 {
		return nil, fmt.Errorf("backchannelhttp: config: timeout must be positive")
	}
	return &Notifier{http: http, timeout: cfg.Timeout}, nil
}

// Notify implements server.BackchannelNotifier: it builds the request via
// server.NewBackchannelNotificationRequest and sends it through n's own
// HTTPClient, treating any 2xx response as success and anything else —
// including a transport-level error — as a plain error.
func (n *Notifier) Notify(ctx context.Context, notification server.BackchannelNotification) error {
	ctx, cancel := context.WithTimeout(ctx, n.timeout)
	defer cancel()

	// NewBackchannelNotificationRequest's only failure mode is a nil
	// context (net/http's own rejection) — ctx here is always the
	// non-nil child context.WithTimeout above just returned (it panics
	// rather than returning one for a nil parent), so this can never
	// actually fail.
	req, _ := server.NewBackchannelNotificationRequest(ctx, notification)
	res, err := n.http.Do(req)
	if err != nil {
		return fmt.Errorf("backchannelhttp: %w", err)
	}
	defer res.Body.Close()
	if _, err := io.Copy(io.Discard, io.LimitReader(res.Body, maxDrainBytes)); err != nil {
		return fmt.Errorf("backchannelhttp: read response: %w", err)
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return fmt.Errorf("backchannelhttp: notification endpoint returned status %d", res.StatusCode)
	}
	return nil
}
