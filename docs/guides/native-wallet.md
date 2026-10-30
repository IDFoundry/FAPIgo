# A FAPI 2.0 wallet in Go

A wallet, or any native app, is an OAuth client that runs on a phone or
desktop rather than on a server. That changes what the client has to get
right:

- the redirect comes back to the app, through a private-use URI scheme
  or a loopback listener ([RFC 8252]), not to a web page;
- each installation is a separate client instance, proving itself with a
  Client Attestation and a key of its own;
- its keys live in the platform's key store, not in a file;
- the operating system may stop the app while the user is at the
  authorization server, so the callback can arrive in a fresh process;
- its tokens and refresh grants outlive any one launch.

FAPIgo's `client` package handles each of these. Its package
documentation has a "Native apps" section with the full detail; this
page shows how the pieces fit.

## Authorization server: register the app as native

```go
wallet, err := storage.NewRegisteredClient(storage.RegisteredClientConfig{
	ID:              "wallet",
	ApplicationType: storage.ApplicationTypeNative,
	RedirectURIs:    []fapi.RegisteredRedirectURI{"com.example.wallet:/callback"},

	ClientAuthMethod:           storage.ClientAuthMethodAttestation,
	ExpectedAttesterIssuer:     "https://attester.example.com",
	ClientAttestationAlgorithm: fapi.ES256,
	AllowedScopes:              []string{"openid", "offline_access"},
})
```

A native client may use a private-use scheme in reverse-domain form,
written with a single slash (`com.example.wallet:/callback`), loopback
`http` to `127.0.0.1` or `[::1]` (never `localhost`, RFC 8252 §8.3),
matched on any port, or a claimed `https` URI, in production as well;
`NewRegisteredClient` refuses any other form. The server also
needs `Config.AttestationBasedClientAuthentication` and an
`AttesterTrust`: `server.RegisteredAttesterKeys` with the attesters'
own keys, by issuer (a `keys.AttesterKeySource` such as
`keys.StaticAttesterKeys` — never the clients' keys), or
`server.X5CAttesterChain` to verify the attestation's `x5c` chain. With
a trust list shared by several attesters, use its
`AttesterIssuerBoundToAnchor` binding, so each anchor vouches only for
the attesters it's bound to. Its `LeafPolicy`, by default
`server.DefaultAttesterLeafPolicy{}`, refuses a signing certificate
issued for another role (a TLS server or client, an OCSP responder, an
mdoc reader or document signer), or chaining only through a CA
restricted to such roles, so an anchor that also certifies those can't
turn their keys into attestation keys. Wrap it in a
`server.AttesterLeafPolicyFunc` to also require your ecosystem's own
Wallet Provider purpose; `server.AnyAttesterLeaf{}` declines the check.

### Checking Wallet Attestation status

`X5CAttesterChain` also needs a `Revocation` for the attesters'
signing certificates: `server.ClientCertificateCRLs{...}`, your own
`server.ClientCertificateRevocation`, or
`server.NoClientCertificateRevocationCheck{}` to decline. A revoked
certificate is `invalid_client` (your own checker wraps
`server.ErrCertificateRevoked` for it); a check that couldn't decide,
such as a stale CRL, is `server_error`. That covers a
Wallet Provider's key, not one wallet instance: every installation
shares the attestation's `sub`, so a Wallet Provider withdraws a single
compromised instance through the attestation's `status` claim (a Token
Status List). Pass a `server.ClientAttestationStatusChecker` as
`Dependencies.ClientAttestationStatus` to act on it: it's given every
claim of each verified attestation, along with the attester's key and
certificate chain to check a Status List Token's signer against, and
refuses a withdrawn attestation by returning an error wrapping
`server.ErrClientAttestationRevoked` (`invalid_client`). Fetch lists
through a `fapihttp.Client`, and cache them. Under
`AssuranceProduction` the dependency is required;
`server.NoClientAttestationStatusCheck{}` declines when your attesters
publish no status. [GETTING_STARTED.md](../../GETTING_STARTED.md#wallet-attestation-status)
sketches a checker.

## Client: keys from the platform, attestation, and the redirect

```go
// Signers backed by the Secure Enclave or Android Keystore.
km, err := keys.NewKeyManagerFromSigners(
	[]keys.SignerSpec{
		{Purpose: keys.DPoPProofSigning, Algorithm: fapi.ES256, Signer: dpopKey},
		{Purpose: keys.ClientAttestationPoPSigning, Algorithm: fapi.ES256, Signer: instanceKey},
	},
	keys.DeclareCustody(keys.KeyCustody{Durable: true}),
)

c, err := client.New(client.Config{
	// Issuer, ClientID, Endpoints, Profile, Algorithms, Limits ...
	RedirectURI:      "com.example.wallet:/callback",
	ClientAuthMethod: storage.ClientAuthMethodAttestation,
	CallbackBinding:  client.CallbackBindingDeviceLocalStore,
}, client.Dependencies{
	Keys:        km,
	Sessions:    onDeviceSessionStore, // durable, in the app's own container
	Attestation: attestations,         // a client.AttestationSource
	// IssuerKeys, HTTP, Clock, Random ...
})
```

- **Attestation.** Every request to the authorization server carries the
  Client Attestation from `Dependencies.Attestation` and a fresh PoP
  signed with the instance key. `client.StaticAttestation(jwt)` serves a
  fixed one; implement `AttestationSource` to renew it before it expires.
  An authorization server refusing an expired one answers
  `use_fresh_attestation` (in the error's `ServerResponse`): get a new
  attestation and retry. Challenges an authorization server sends in
  `OAuth-Client-Attestation-Challenge` are followed for you: the latest
  goes in every PoP, and a `use_attestation_challenge` error is retried
  once. For a request you send yourself with
  `ClientAttestationHeaders`, pass its response headers to
  `ObserveAttestationChallenge`.
- **Keys.** The Secure Enclave signs ES256 only. Keep each key until the
  tokens bound to it are discarded.
- **Loopback.** A desktop app on a port the OS picks per flow sets
  `RedirectURI` to the port-less `http://127.0.0.1/callback` and passes
  each flow's port as `BeginAuthorizationRequest.RedirectPort`.
- **Production.** Under `client.AssuranceProduction`, `client.New`
  requires the session store to declare `Durable` and `AtomicConsume`,
  the keys to declare custody (`DeclareCustody`, as above), a hardened
  `IssuerKeys`, `Random` to be `crypto/rand.Reader`, `Clock` to be
  `client.SystemClock{}` (or declare `client.ClockAssurance`), `Limits`
  within its bounds (`RecommendedLimits` is), and an https issuer and
  endpoints. A loopback redirect URI is still fine; a plain-http
  loopback authorization server, as in local testing, is not.
  `CallbackBindingDeviceLocalStore` is accepted only with a native app's
  redirect URI — a private-use scheme, or loopback http to `127.0.0.1`
  or `[::1]` — and a session store that doesn't declare
  `CrossInstanceConsistent`.

## Completing after a relaunch

With `CallbackBindingDeviceLocalStore`, the callback completes from its
query alone, so it works in whatever process the OS starts for the
deep link:

```go
result, err := c.CompleteAuthorization(ctx, client.AuthorizationCallback{
	RawQuery: deepLink.RawQuery,
})
```

Build the client from the same config, keys and session store first. The
binding is safe only because the session store is the app's own on-device
storage; a browser-based client keeps the default binding, and
`AssuranceProduction` refuses it for an https redirect URI.

## Tokens over the app's lifetime

- **Keep them** between launches with a `TokenSetSealer`: `Seal` before
  writing them to storage, `Open` to read them back, bound to their owner.
- **Refresh** with `RefreshTokens`. When the client authenticates with a
  Client Attestation, the refresh token is bound to the instance key
  (attestation-based client authentication §10.3): only this
  installation can redeem it. A FAPIgo authorization server also refuses
  an installation a refresh token issued to the same client_id under
  another method, such as your backend's `private_key_jwt`.
- **Revoke** with `RevokeToken(ctx, tokens)` when the app no longer needs
  a refresh token, before deleting the key it's bound to. It takes the
  `TokenSet`, and refuses one from another issuer. `ErrorRevocationNotSupported`
  means the server offers no revocation endpoint, and the token can only
  be forgotten.
- **Errors** may include text the server wrote. Before an error crosses
  into platform code (gomobile turns `Error()` into an `NSError`
  message), map a `*client.Error` to `Code()` and `ServerResponse()`.

## Issuing to wallets: the pre-authorized code grant

An issuer that serves its own grant, such as OpenID4VCI's
pre-authorized code, at the token endpoint uses
`AuthenticateAttestedClient` and `VerifyTokenRequestBinding` for the
client and its DPoP proof, then `IssueAccessToken` for the access
token and `IssueRefreshToken` so the wallet can refresh, bound to the
same instance key; one `GrantID` on both lets revoking the grant end
every token issued for it. See "Serving a grant this
package doesn't" in
[GETTING_STARTED §6](../../GETTING_STARTED.md#6-the-rest-of-the-http-surface).

## Further reading

- The `client` package documentation, "Native apps" section.
- [DPoP in Go](dpop.md) and [PAR in Go](par.md), which every request
  above uses.

[RFC 8252]: https://www.rfc-editor.org/rfc/rfc8252
