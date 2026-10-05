# FAPI 2.0 Message Signing in Go

The FAPI 2.0 Security Profile protects requests and responses in
transit. The Message Signing profile adds signatures, so each side can
prove later what the other one sent:

- the authorization request is a signed request object (JAR,
  [RFC 9101]), so the authorization server holds the client's own
  signature over exactly what was asked for;
- the authorization response is a signed JWT (JARM), so the client holds
  the authorization server's signature over the code and `state` it
  received.

This is what a payment needs when either party may later have to show
what was agreed. FAPIgo selects the profile with one setting on each
side.

## Selecting the profile

```go
// Authorization server.
cfg.Profile = server.ProfileFAPISecurityWithMessageSigning
cfg.Algorithms.RequestObject = server.AlgorithmSet{fapi.ES256} // accepted from clients
cfg.Algorithms.JARM = fapi.ES256                                // signs authorization responses
cfg.Limits.MaxRequestObjectLifetime = time.Minute
cfg.Limits.JARMResponseLifetime = 90 * time.Second

// Client.
clientCfg.Profile = client.ProfileFAPISecurityWithMessageSigning
clientCfg.Algorithms.RequestObject = fapi.ES256
clientCfg.Algorithms.JARM = fapi.ES256
clientCfg.Limits.RequestObjectLifetime = time.Minute
clientCfg.Limits.MaxJARMResponseLifetime = 90 * time.Second
```

Each client is registered with the algorithm it signs request objects
with (`storage.RegisteredClientConfig.RequestObjectAlgorithm`). The
server's key manager signs authorization responses under
`keys.JARMSigning`, and `PublicJWKS` publishes that key; the client signs
request objects under `keys.RequestObjectSigning`. Under this profile the
server's `New` refuses a configuration without `Algorithms.JARM` and
`Limits.JARMResponseLifetime`, and the client's without its request
object and JARM algorithms and lifetimes.

## Client: still one call each way

`BeginAuthorization` signs the request object and pushes it; there is
nothing else to call. `PushedRequestEncoding` follows the profile by
default, and `PushedRequestEncodingRequestObject` sends a signed request
object under the Security Profile too, without switching responses to
JARM.

`CompleteAuthorization` (or `HandleAuthorizationResponse`) then expects
the callback's `response` parameter, and verifies it before reading
anything inside: the signature with the authorization server's key
(`Dependencies.IssuerKeys`, purpose `keys.JARMVerification`), using
`Algorithms.JARM` rather than the JWT's own header, then `iss`, `aud`
and expiry. Which form to expect comes from the profile, never from the
callback, so a plain response can't stand in for a signed one.

## Authorization server: what changes

- **PAR** accepts only a signed request object; plain parameters are
  refused. The object must verify under the client's registered key and
  algorithm, name this server as its audience, carry `nbf` (Message
  Signing §5.3.1), be within `Limits.MaxRequestObjectLifetime`, be
  unused before, and not carry a `request_uri` of its own.
- **The authorization response**, success or error, is a JWT signed with
  `keys.JARMSigning`, addressed to the client and valid for
  `Limits.JARMResponseLifetime`.
- **Metadata** advertises `require_signed_request_object` and the `jwt`
  response mode.

## Signed UserInfo

Signed UserInfo responses are opt-in under either profile. On the
server, set `Algorithms.UserInfo` and `SignUserInfoResponse` signs the
claims your UserInfo handler serves, always adding `iss` and `aud`, and
encrypts them too for a client registered for encrypted UserInfo. In a
UserInfo handler, call `serverresource.SignUserInfoResponse` with the
verified access token's `resource.AuthorizationContext`: it resolves
the client the token was issued to, so the response can only be
addressed to that client, and refuses claims whose `sub` isn't the
token's subject.
On the client, setting `Algorithms.UserInfo` makes `FetchUserInfo`
verify the response; `VerifyIssuerJWS` verifies any other
issuer-signed artifact with the same keys.

## See it running

- [payment-consent](../../examples/payment-consent/README.md) runs the
  Message Signing profile end to end. Its protocol trace
  ([`payment/trace.go`](../../examples/payment-consent/payment/trace.go))
  shows each signed request object and authorization response decoded,
  and its attack lab tampers with the signed request and presents a
  forged authorization response, both refused. The server configuration
  is in [`payment/bank.go`](../../examples/payment-consent/payment/bank.go).
- [identity-check](../../examples/identity-check/README.md) serves signed
  and encrypted UserInfo responses.
- [PAR in Go](par.md), which every request object travels through.

[RFC 9101]: https://www.rfc-editor.org/rfc/rfc9101
