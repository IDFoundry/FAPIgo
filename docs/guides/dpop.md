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
challenges for a nonce.

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
current nonce and issues a fresh one with every response.

## Resource server: one call

`resource.Verifier` checks the access token and its DPoP proof together:
the signature, `htm`/`htu` against the URL you pass (never one the
request describes), `ath` against the token, the key against `cnf.jkt`,
and replay.

```go
// paymentsEndpoint is this API's own external URL, a *url.URL.
func pay(w http.ResponseWriter, r *http.Request) {
	authz, err := verifier.Verify(r.Context(), resource.VerifyRequestFromHTTP(r, paymentsEndpoint))
	if err != nil {
		resource.WriteError(w, err) // 401 with the matching DPoP challenge
		return
	}
	authz.SetDPoPNonce(w.Header()) // when the verifier issues nonces
	// authz.Subject, authz.Scopes, authz.Claims ...
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
