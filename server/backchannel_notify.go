package server

import (
	"context"

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
	// verification (it rejects any other field being present). A CIBA
	// client is required to keep polling regardless of whether — or how
	// — this call actually lands (CIBA §10.3's backup-polling
	// guarantee), so this server treats any error Notify returns as
	// best-effort informational only: it is never allowed to fail the
	// decision that triggered it.
	Notify(ctx context.Context, notification BackchannelNotification) error
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
