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

// Config bounds the Notifier New builds. Neither field has an implicit
// default — New rejects a non-positive Timeout, and fapihttp.NewClient
// rejects a zero Transport.
type Config struct {
	// Transport configures the fapihttp client New builds to send every
	// notification: dial and TLS handshake timeouts, and the loopback
	// and private-address exceptions its SSRF guard allows. A client's
	// notification endpoint can come from outside this deployment — an
	// OpenID Federation relying party's own metadata, under automatic
	// registration — so New always sends through that guarded client,
	// which never follows a redirect, rather than accepting one from
	// the caller.
	Transport fapihttp.TransportConfig

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
	http     fapihttp.HTTPClient
	timeout  time.Duration
	hardened bool
}

// New returns a Notifier that sends every notification through an
// SSRF-guarded client built from cfg.Transport by fapihttp.NewClient,
// bounded by cfg.Timeout.
func New(cfg Config) (*Notifier, error) {
	if cfg.Timeout <= 0 {
		return nil, fmt.Errorf("backchannelhttp: config: timeout must be positive")
	}
	client, err := fapihttp.NewClient(cfg.Transport)
	if err != nil {
		return nil, fmt.Errorf("backchannelhttp: config: %w", err)
	}
	n := newWithClient(client, cfg.Timeout)
	n.hardened = !cfg.Transport.AllowsLoopback()
	return n, nil
}

// newWithClient returns a Notifier over an arbitrary client, which it
// can't vouch for: it doesn't declare OutboundHardened.
func newWithClient(client fapihttp.HTTPClient, timeout time.Duration) *Notifier {
	return &Notifier{http: client, timeout: timeout}
}

// BackchannelNotifierCapabilities implements
// server.BackchannelNotifierAssurance: a Notifier sends through the
// fapihttp client New builds from Config.Transport (SSRF-guarded
// dialing, no redirects, https, dial and handshake timeouts), bounded
// by Config.Timeout, and drains at most a bounded amount of the
// response body. It declares OutboundHardened unless Config.Transport
// grants a loopback exception (fapihttp.TransportConfig's
// AllowsLoopback), which is for local development only: a client
// registers its own notification endpoint. AllowedPrivateHosts doesn't
// count — it names the operator's own fixed hosts.
func (n *Notifier) BackchannelNotifierCapabilities() server.BackchannelNotifierCapabilities {
	return server.BackchannelNotifierCapabilities{OutboundHardened: n.hardened}
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
	defer func() { _ = res.Body.Close() }()
	if _, err := io.Copy(io.Discard, io.LimitReader(res.Body, maxDrainBytes)); err != nil {
		return fmt.Errorf("backchannelhttp: read response: %w", err)
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return fmt.Errorf("backchannelhttp: notification endpoint returned status %d", res.StatusCode)
	}
	return nil
}
