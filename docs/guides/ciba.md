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

Set `Config.Endpoints.BackchannelAuthentication` to the server's
backchannel authentication endpoint. `BeginBackchannelAuthentication`
signs the request, authenticates as the client and sends it, after
checking locally that exactly one hint is set. `PollBackchannelAuthentication`
makes exactly one attempt, so you poll on your own schedule (a job
queue, a ticker) rather than blocking a goroutine while a person
decides. The session survives restarts: seal it with a
`client.BackchannelSessionSealer` (`NewBackchannelSessionSealer(c, keys)`,
then `Seal(session, owner)`), store the result keyed by its `AuthReqID`,
and `Open(sealed, owner)` it on any instance. The sealing is AES-256-GCM,
bound to the client's issuer and client ID and to the owner you name
(the user, account or connection the request is for), so a stored
session can't be edited, and one leaked from another user doesn't open
under this one's: it records whether the request asked for `openid`,
which decides whether an approval without an ID token is refused.

For ping delivery, set `Config.BackchannelTokenDeliveryMode` to
`storage.BackchannelTokenDeliveryModePing`, and register your
notification endpoint with the server (below). The server then calls it
once the user decides:

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

Setting `Config.Endpoints.BackchannelAuthentication` turns CIBA on, and
`server.New` then requires `Dependencies.Backchannel` and
`Dependencies.BackchannelNotifier` (below). A client may use CIBA only
if its registration says so:

- `storage.RegisteredClientConfig.BackchannelAuthenticationRequestAlgorithm`,
  the algorithm its signed requests use, is the opt-in. Left zero, the
  client is refused with `unauthorized_client`.
- `BackchannelTokenDeliveryMode` is poll (the default) or ping; a ping
  client also needs `BackchannelClientNotificationEndpoint`, which a poll
  client must leave unset.
- An automatically registered OpenID Federation client may use CIBA only
  with `AutomaticRegistration.AllowsCIBA`.

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
   (`server.Authorize(...)`, `server.Deny(...)`, or
   `server.AuthenticationFailed(...)`, which the client sees as
   `access_denied`) against the handle, once, and refuses one made after
   the request expired (`expired_token`). `server.InteractionNeeded`
   answers a redirect's `prompt=none` only; CIBA refuses it. For a ping
   client it then calls `Dependencies.BackchannelNotifier`.
3. **`ExchangeBackchannelAuthentication`** serves the token endpoint's
   CIBA grant (`TokenEndpointRequest.BackchannelTokenExchange()`):
   `authorization_pending` until a decision, `slow_down` for a poll
   sooner than `Limits.BackchannelAuthenticationPollInterval`,
   `access_denied`, `expired_token` after
   `Limits.BackchannelAuthenticationRequestLifetime`, and on approval
   sender-constrained tokens, issued exactly once. Another client
   presenting the `auth_req_id` is refused without spending the
   approval, as long as the store honours the poll's `ClientID` (the
   bundled `memstore` does).

Set `Dependencies.Backchannel` (`memstore.NewBackchannelAuthenticationStore()`
to start) and `Dependencies.BackchannelNotifier`: `backchannelhttp.New`
sends pings through a hardened HTTP client, and `NoBackchannelNotifications{}`
declines them for a poll-only deployment. The notification endpoint is
whatever the client registered, so under `AssuranceProduction` a
notifier of your own must implement `server.BackchannelNotifierAssurance`
and declare `OutboundHardened` — a promise to send as `backchannelhttp`
does (refusing non-public addresses, following no redirects, with
timeouts and a bounded response read) — or `server.New` refuses it.
`backchannelhttp.New` declares it only when its `Config.Transport` grants
no loopback exception (`AllowsLoopback`). `Dependencies.BackchannelHints`
can refuse a hint naming nobody (`unknown_user_id`) before the request is
stored. A hint only says whose device to ask: the user's approval there
is what authenticates them. The binding message is free text the client
wrote, so show it as such, beside what you describe from the request
itself.

FAPI-CIBA §5.2.2 makes one more thing yours: the user must be able to
tell which request they're approving. Either each request carries a
unique authorization context you show them (a payment's amount and
payee in its authorization details, say), or you require a binding
message, which the consumption device shows too. This package can't
tell whether a request's details are unique to it, so it accepts a
request without `binding_message`. If yours can't be told apart
otherwise, complete one with an empty `a.Interaction.BindingMessage` as
`server.AuthenticationFailed(...)` before asking the user anything.

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
