# Pushed Authorization Requests (PAR) in Go

With PAR ([RFC 9126]), a client doesn't put its authorization request in
the browser's URL. It sends the request straight to the authorization
server, authenticated, and gets back a short-lived `request_uri`. The
browser then carries only that reference and the `client_id`. Nothing
in the request can be read or altered on the way through the user
agent, and the server checks it before the user sees anything.

FAPI 2.0 requires PAR for every authorization request. FAPIgo has no
other way to start one: the client always pushes, and the server only
accepts a `request_uri` it issued.

## Client: one call

```go
session, err := c.BeginAuthorization(ctx, client.BeginAuthorizationRequest{
	Scope: []string{"openid", "accounts"},
})
// ...
http.Redirect(w, r, session.URL().String(), http.StatusFound)
```

`BeginAuthorization` builds the request (PKCE, `state`, `nonce`, and a
DPoP key commitment when the client is DPoP-bound), authenticates as the
client, pushes it, and returns the authorization URL that carries only
the `request_uri`. Under the FAPI 2.0 Message Signing profile it pushes
a signed request object (JAR, [RFC 9101]) instead of plain parameters.
Keep the session's handle with the user agent (`client/sessioncookie`
does this for a browser), and pass the callback to
`CompleteAuthorization`.

## Authorization server: the endpoint and the authorization step

```go
func par(w http.ResponseWriter, r *http.Request) {
	req, err := server.PushAuthorizationRequestFromHTTP(r)
	if err != nil {
		server.WriteError(w, err)
		return
	}
	result, err := srv.PushAuthorizationRequest(r.Context(), req)
	if err != nil {
		server.WriteError(w, err)
		return
	}
	result.WriteJSON(w) // 201 with request_uri and expires_in
}
```

`PushAuthorizationRequest` authenticates the client, verifies the signed
request object or the plain parameters (per `Config.Profile`), checks
them against the client's registration (redirect URI, scopes, Rich
Authorization Request types, PKCE), and stores them for
`Limits.PushedRequestLifetime`. At the authorization endpoint,
`BeginAuthorizationRequestFromHTTP` and `BeginAuthorization` accept only
a `request_uri` this server issued, to the client it was issued to,
once, and before it expires. A plain authorization request without one
is refused.

Unregistered parameters are ignored rather than echoed into the grant,
and a PAR request that itself carries a `request_uri` is refused.

## See it running

- [payment-consent](../../examples/payment-consent/README.md): its attack
  lab skips PAR and tampers with the pushed request, and its protocol
  trace shows the push and the redirect. The endpoint above is from
  [`payment/bank.go`](../../examples/payment-consent/payment/bank.go).
- [GETTING_STARTED](../../GETTING_STARTED.md): the full authorization
  code flow.

[RFC 9126]: https://www.rfc-editor.org/rfc/rfc9126
[RFC 9101]: https://www.rfc-editor.org/rfc/rfc9101
