# DPoP in Go

DPoP (OAuth 2.0 Demonstrating Proof of Possession, [RFC 9449]) binds an
access token to a key the client holds. Every request that uses the
token carries a short-lived signed proof, made with that key, for that
exact method and URL. A stolen token is useless without the key.

FAPI 2.0 requires every access token to be sender-constrained, by DPoP
or by mutual TLS ([RFC 8705]). FAPIgo does DPoP by default, on all three
sides, without exposing a single proof to your code.

## Client: nothing to build

DPoP is the zero value of `client.Config.SenderConstrain`, so a client is
DPoP-bound unless you choose mTLS. Give `client.Dependencies.Keys` a key
for `keys.DPoPProofSigning` and the client:

- signs a proof for every pushed authorization request, token request and
  CIBA request, and retries once when the server answers `use_dpop_nonce`;
- commits to the key at PAR time, with a DPoP header (the default,
  `client.PARDPoPBindingProof`) or a `dpop_jkt` parameter
  (`client.PARDPoPBindingJKT`), so the authorization code can only be
  redeemed with it;
- calls protected resources with the same key, through `ProtectedResource`:

```go
tokens, err := c.RefreshTokens(ctx, client.RefreshTokenRequest{Tokens: saved})
// ...
req, err := http.NewRequestWithContext(ctx, http.MethodPost, paymentsURL, body)
// ...
res, err := c.ProtectedResource(tokens).Do(ctx, req)
```

`Do` sets `Authorization: DPoP <token>` and a fresh proof bound to the
token (its `ath` claim), and retries once if the resource server
challenges for a nonce. It requires an `https` URL (loopback `http`
only under `AssuranceDevelopment`) and never follows a redirect: a 3xx
comes back as the response, so the token and proof are only ever sent
to the URL you gave.

## Authorization server: verified for you

Register the client with `storage.SenderConstrainDPoP` (the default).
`server.Server` then verifies each DPoP proof at the PAR and token
endpoints, and binds the access token to the key (`cnf.jkt`). The checks
are the ones RFC 9449 §4.3 lists, plus the ones that are easy to miss:

- the proof's `htu` is checked against your configured endpoint URLs
  (`Config.Endpoints`, or their `MTLSEndpoints` aliases), never against
  the request's `Host` header;
- `iat` must fall within `Limits.MaxDPoPProofAge`, and a proof's `jti`
  can be used once (`Dependencies.Replay`);
- a key committed at PAR must match the key at the token endpoint.

DPoP nonces ([RFC 9449] §8) are optional: set `Dependencies.Nonces` and
`Limits.DPoPNonceLifetime`, and the server challenges a proof without a
current nonce and sends its current nonce with every response. A nonce
is valid until it expires, for any number of proofs, so concurrent
requests from one client all succeed (the `jti` check is what refuses a
replayed proof); the server switches to a new nonce once half the
lifetime has passed, and the previous one keeps working until it
expires.

## Resource server: one call

`resource.Verifier` checks the access token and its DPoP proof together:
the signature, `htm` against the method exactly, `htu` against the
request's escaped path at your API's own external URL (never a `Host`
the request describes), `ath` against the token, the key against
`cnf.jkt`, and replay. You give it that URL once, as
`resource.Config.ResourceURLs` (or `serverresource.Options.ResourceURLs`):
an origin, optionally with a path prefix. A request whose path no prefix
covers is refused, and so is a proof whose `htu` is relative or names
another scheme.

```go
// verifier's ResourceURLs: this API's own external URL, e.g. https://api.example.com.
func pay(w http.ResponseWriter, r *http.Request) {
	authz, err := verifier.Verify(r.Context(), resource.VerifyRequestFromHTTP(r))
	if err != nil {
		resource.WriteError(w, err) // 401 with the matching DPoP challenge
		return
	}
	authz.SetDPoPNonce(w.Header()) // when the verifier issues nonces
	// Whose payment: not InternalSubject alone, which for a client
	// credentials token is the client's own client_id.
	user, ok := authz.EndUser()
	if !ok {
		resource.NewInsufficientScopeError(authz, "the access token wasn't issued for a user").WriteJSON(w)
		return
	}
	// user, authz.Scopes, authz.Claims ...
}
```

## See it running

- [linked-accounts](../../examples/linked-accounts/README.md): an app
  syncing with a DPoP-bound refresh token, rotating its DPoP key midway,
  and an attack that presents its access token with another app's key.
- [payment-consent](../../examples/payment-consent/README.md): a
  DPoP-bound payment API; the handler above is from
  [`payment/api.go`](../../examples/payment-consent/payment/api.go).
- [payroll-run](../../examples/payroll-run/README.md): the mTLS
  alternative, with its own stolen-token attack.
- [GETTING_STARTED](../../GETTING_STARTED.md): wiring all three roles.

[RFC 9449]: https://www.rfc-editor.org/rfc/rfc9449
[RFC 8705]: https://www.rfc-editor.org/rfc/rfc8705
