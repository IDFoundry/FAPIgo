package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/idfoundry/fapigo/server"
)

// backchannelNotificationTimeout bounds a single outbound CIBA §10.2
// ping notification POST.
const backchannelNotificationTimeout = 10 * time.Second

// httpBackchannelNotifier is the real, HTTP-POSTing server.BackchannelNotifier
// this binary uses whenever -ciba is passed — CIBA ping delivery is
// meaningless without one actually making the call, unlike the library
// itself, which never terminates or originates a TLS connection anywhere
// (see ARCHITECTURE.md design rule 6) and so only ever ships the no-op
// server.NoBackchannelNotifications{}.
//
// Trusts any TLS certificate presented by the notification endpoint —
// this binary only ever talks to a locally running OIDF conformance
// suite (see package doc comment), whose own dev-mode instance presents
// a self-signed certificate; never appropriate outside a local
// conformance run. Mirrors every other suite-facing HTTP client in this
// repo's own conformance tooling (e.g.
// cmd/conformance-client's insecureSuiteHTTPClient).
type httpBackchannelNotifier struct {
	client *http.Client
}

func newHTTPBackchannelNotifier() *httpBackchannelNotifier {
	return &httpBackchannelNotifier{
		client: &http.Client{
			Timeout:   backchannelNotificationTimeout,
			Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, //nolint:gosec
			// Confirmed live against the OIDF suite's own
			// fapi-ciba-id1-ping-backchannel-notification-endpoint-return-redirect-request
			// module: a redirect response from the notification
			// endpoint must be treated as the final response, not
			// followed — the module's own registered
			// "invalid-ciba-notification-endpoint" callback fails the
			// test outright if this AS ever calls it.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
}

// Notify implements server.BackchannelNotifier — see that interface's
// own doc comment for the exact required request shape (CIBA §10.2,
// confirmed against the OIDF conformance suite's own verification
// logic: POST, Content-Type: application/json, Authorization: Bearer
// {token}, body {"auth_req_id": "..."}). Any non-2xx response, or a
// failure to even complete the request, is reported back as an error —
// the caller (server.CompleteBackchannelAuthentication) treats it as
// best-effort and never fails the decision over it.
func (n *httpBackchannelNotifier) Notify(ctx context.Context, notification server.BackchannelNotification) error {
	body, err := json.Marshal(map[string]string{"auth_req_id": notification.AuthReqID})
	if err != nil {
		return fmt.Errorf("marshal notification body: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, notification.Endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build notification request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+notification.ClientNotificationToken.Reveal())

	resp, err := n.client.Do(req)
	if err != nil {
		return fmt.Errorf("send notification request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("notification endpoint returned status %d", resp.StatusCode)
	}
	return nil
}
