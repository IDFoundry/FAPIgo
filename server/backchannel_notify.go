package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	fapi "github.com/idfoundry/fapigo"
)

// BackchannelNotification is the input to BackchannelNotifier.Notify —
// everything needed to POST a CIBA §10.2 ping notification to a
// client's own notification endpoint.
type BackchannelNotification struct {
	// Endpoint is the client's own registered
	// storage.RegisteredClient.BackchannelClientNotificationEndpoint().
	Endpoint fapi.URL

	// ClientNotificationToken is the bearer token to present in the
	// notification's own Authorization header — the client generated
	// this value itself and sent it in the original backchannel
	// authentication request; this server never invents one.
	ClientNotificationToken fapi.Secret

	// AuthReqID is the auth_req_id CIBA §10.2 requires the notification
	// body itself to carry — the suite's own conformance check
	// (CheckAuthReqIdInCallback/CheckNotificationCallbackOnlyAuthReqId)
	// confirms the body must be exactly {"auth_req_id": "..."}, nothing
	// more, with Content-Type: application/json.
	AuthReqID string
}

// BackchannelNotifier lets this server tell a CIBA client, out of band,
// that a decision was reached (CIBA §10.2's ping delivery mode) — this
// package builds the notification but never makes the HTTP call itself
// (it never terminates or originates a TLS connection anywhere in this
// codebase; see ARCHITECTURE.md design rule 6). Dependencies.BackchannelNotifier
// has no default: pass a real implementation, or NoBackchannelNotifications{}
// to explicitly decline (e.g. a poll-only deployment) — see that type's
// own doc comment for why declining must be a visible choice, not a
// silent one, mirroring RevocationSink/NoRevocation's identical
// precedent.
type BackchannelNotifier interface {
	// Notify POSTs to notification.Endpoint with
	// Authorization: Bearer {notification.ClientNotificationToken} and
	// Content-Type: application/json, a body of exactly
	// {"auth_req_id": "{notification.AuthReqID}"} — CIBA §10.2's own
	// required shape, confirmed against the OIDF conformance suite's own
	// verification (it rejects any other field being present) — see
	// NewBackchannelNotificationRequest, which builds exactly this
	// *http.Request. A CIBA client is required to keep polling
	// regardless of whether — or how — this call actually lands (CIBA
	// §10.3's backup-polling guarantee), so this server treats any error
	// Notify returns as best-effort informational only: it is never
	// allowed to fail the decision that triggered it.
	Notify(ctx context.Context, notification BackchannelNotification) error
}

// NewBackchannelNotificationRequest builds the *http.Request a
// BackchannelNotifier.Notify implementation should send for
// notification: POST to notification.Endpoint, Authorization: Bearer
// {ClientNotificationToken}, Content-Type: application/json, and a
// body of exactly {"auth_req_id": "..."} — CIBA §10.2's own required
// shape, the same one BackchannelNotifier.Notify's own doc comment
// specifies. This only builds the request; it never sends it (see
// BackchannelNotifier's own doc comment for why this package never
// originates the actual connection itself) — pass the result to a
// caller-supplied *http.Client.Do, after setting whatever transport
// policy (TLS trust, timeout, proxying) that deployment needs.
func NewBackchannelNotificationRequest(ctx context.Context, notification BackchannelNotification) (*http.Request, error) {
	// Encoding a single fixed string field cannot fail.
	body, _ := json.Marshal(struct {
		AuthReqID string `json:"auth_req_id"`
	}{AuthReqID: notification.AuthReqID})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, notification.Endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build notification request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+notification.ClientNotificationToken.Reveal())
	return req, nil
}

// NoBackchannelNotifications is an explicit no-op BackchannelNotifier
// for a deployment that has decided not to support CIBA ping delivery —
// every client it registers must stay BackchannelTokenDeliveryModePoll.
// There is no implicit default here (see server/dependencies.go and
// ARCHITECTURE.md: "no silently-installed in-memory store") — New
// rejects a nil Dependencies.BackchannelNotifier the same way it
// rejects a nil Backchannel once CIBA itself is configured.
// NoBackchannelNotifications exists so declining is a conscious,
// visible line of code (BackchannelNotifier: server.NoBackchannelNotifications{})
// instead of an easily-forgotten omission.
type NoBackchannelNotifications struct{}

// Notify implements BackchannelNotifier by doing nothing.
func (NoBackchannelNotifications) Notify(context.Context, BackchannelNotification) error {
	return nil
}
