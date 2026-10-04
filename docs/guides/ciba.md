# CIBA in Go

CIBA (OpenID Connect Client-Initiated Backchannel Authentication,
[CIBA]) lets a client start an authorization with no browser redirect at
all. A till, a call-centre agent or a budgeting app sends the
authorization server a
request naming the user. The server asks the user on a device of their
own, typically a banking app on their phone, and the client collects the
tokens once they decide. The user never types credentials into the
client's device.

FAPI-CIBA ([FAPI-CIBA]) profiles it for high-value APIs: the request is
always a signed request object, the client authenticates strongly, and
the tokens are sender-constrained. FAPIgo implements both decision
delivery modes the profile allows, poll and ping.

## Client: begin, then poll or wait for a ping

```go
session, err := c.BeginBackchannelAuthentication(ctx, client.BeginBackchannelAuthenticationRequest{
	Scope:          []string{"openid", "payments"},
	LoginHint:      "sam@example.com", // or LoginHintToken, or IDTokenHint: exactly one
	BindingMessage: "Order 1042",
})
// ... later, no sooner than session.Interval() apart:
result, err := c.PollBackchannelAuthentication(ctx, session)
switch r := result.(type) {
case client.BackchannelAuthenticationPending:
	retryLater(r.SlowDown) // SlowDown: the last poll came too soon, so back off
case client.BackchannelAuthenticationApproved:
	useTokens(r.Tokens)
case client.BackchannelAuthenticationDenied:
	reportDenied(r.Code, r.Description)
case client.BackchannelAuthenticationExpired:
	// the user didn't decide in time: start again
}
```

`BeginBackchannelAuthentication` signs the request, authenticates as
the client and sends it. `PollBackchannelAuthentication` makes exactly
one attempt, so you poll on your own schedule (a job queue, a ticker)
rather than blocking a goroutine while a person decides. The session
survives restarts: `MarshalText` and `UnmarshalText` store it.

For ping delivery, set `Config.BackchannelTokenDeliveryMode` to
`storage.BackchannelTokenDeliveryModePing`. The server then calls your
notification endpoint once the user decides:

```go
func notify(w http.ResponseWriter, r *http.Request) {
	n, err := client.ParseBackchannelNotification(r)
	if err != nil {
		http.Error(w, "malformed notification", http.StatusBadRequest)
		return
	}
	session, ok := sessionFor(n.AuthReqID()) // your own lookup
	if !ok || !n.Authenticates(session) {
		http.Error(w, "unknown request or wrong token", http.StatusUnauthorized)
		return
	}
	w.WriteHeader(http.StatusNoContent)
	go collect(session) // PollBackchannelAuthentication, after answering
}
```

`Authenticates` checks the notification's bearer token against the
`client_notification_token` the client sent, in constant time; CIBA
requires that before a ping is trusted.

## Authorization server: three calls around your user's decision

```go
func backchannelAuthentication(w http.ResponseWriter, r *http.Request) {
	req, err := server.BeginBackchannelAuthenticationRequestFromHTTP(r)
	if err != nil {
		server.WriteError(w, err)
		return
	}
	action, err := srv.BeginBackchannelAuthentication(r.Context(), req)
	if err != nil {
		server.WriteError(w, err)
		return
	}
	switch a := action.(type) {
	case server.BackchannelAuthenticationLocalError:
		a.Error.WriteJSON(w)
	case server.BackchannelInteractionRequired:
		askTheUser(a.Handle, a.Interaction) // your app: notify the user's device
		a.WriteJSON(w)                      // auth_req_id, expires_in, interval
	}
}
```

1. **`BeginBackchannelAuthentication`** authenticates the client, refuses
   one not registered for CIBA (`unauthorized_client`), verifies the
   signed request, requires exactly one of `login_hint`,
   `login_hint_token` and `id_token_hint`, and stores the request.
   `a.Interaction` has what to show the user: the scope, the hints, the
   binding message and any Rich Authorization Request details.
   `LookupBackchannelInteraction` reads it back by handle later.
2. **`CompleteBackchannelAuthentication`** records the user's decision
   (`server.Authorize(...)` or a denial) against the handle, once. For a
   ping client it then calls `Dependencies.BackchannelNotifier`.
3. **`ExchangeBackchannelAuthentication`** serves the token endpoint's
   CIBA grant (`TokenEndpointRequest.BackchannelTokenExchange()`):
   `authorization_pending` until a decision, `slow_down` for a poll
   sooner than `Limits.BackchannelAuthenticationPollInterval`,
   `access_denied`, `expired_token` after
   `Limits.BackchannelAuthenticationRequestLifetime`, and on approval
   sender-constrained tokens, issued exactly once.

Set `Dependencies.Backchannel` (`memstore.NewBackchannelAuthenticationStore()`
to start) and `Dependencies.BackchannelNotifier`: `backchannelhttp.New`
sends pings through a hardened HTTP client, and `NoBackchannelNotifications{}`
declines them for a poll-only deployment. `Dependencies.BackchannelHints`
can refuse a hint naming nobody (`unknown_user_id`) before the request is
stored. A hint only says whose device to ask: the user's approval there
is what authenticates them. The binding message is free text the client
wrote, so show it as such, beside what you describe from the request
itself.

## See it running

[decoupled-checkout](../../examples/decoupled-checkout/README.md): a till
that pays by polling, and a budgeting app linked by ping.

- The server's endpoints are in
  [`checkout/bank.go`](../../examples/decoupled-checkout/checkout/bank.go);
  the polling till is
  [`checkout/till.go`](../../examples/decoupled-checkout/checkout/till.go),
  and the ping client is
  [`checkout/pocketwise.go`](../../examples/decoupled-checkout/checkout/pocketwise.go).
- Its tour tries to charge more than was approved or charge twice, use
  the till's token from another device, and collect tokens a second time
  with the same `auth_req_id`; it also shows a misleading binding
  message, and a client asking for more than it's allowed, refused
  before the request reaches the phone.

[FAPI-CIBA]: https://openid.net/specs/openid-financial-api-ciba-ID1.html
[CIBA]: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html
