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
written with a single slash (`com.example.wallet:/callback`), or loopback
`http` to `127.0.0.1` or `[::1]`, matched on any port. The server also
needs `Config.AttestationBasedClientAuthentication` and an
`AttesterTrust`: `server.RegisteredAttesterKeys` with the attesters'
own keys, by issuer (a `keys.AttesterKeySource` such as
`keys.StaticAttesterKeys` — never the clients' keys), or
`server.X5CAttesterChain` to verify the attestation's `x5c` chain. With
a trust list shared by several attesters, use its
`AttesterIssuerBoundToAnchor` binding, so each anchor vouches only for
the attesters it's bound to.

## Client: keys from the platform, attestation, and the redirect

```go
// Signers backed by the Secure Enclave or Android Keystore.
km, err := keys.NewKeyManagerFromSigners(
	map[keys.SigningPurpose]crypto.Signer{
		keys.DPoPProofSigning:            dpopKey,
		keys.ClientAttestationPoPSigning: instanceKey,
	},
	map[keys.SigningPurpose]fapi.SignatureAlgorithm{
		keys.DPoPProofSigning:            fapi.ES256,
		keys.ClientAttestationPoPSigning: fapi.ES256,
	},
	nil,
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
- **Keys.** The Secure Enclave signs ES256 only. Keep each key until the
  tokens bound to it are discarded.
- **Loopback.** A desktop app on a port the OS picks per flow sets
  `RedirectURI` to the port-less `http://127.0.0.1/callback` and passes
  each flow's port as `BeginAuthorizationRequest.RedirectPort`.

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
storage; a browser-based client keeps the default binding.

## Tokens over the app's lifetime

- **Keep them** between launches with a `TokenSetSealer`: `Seal` before
  writing them to storage, `Open` to read them back, bound to their owner.
- **Refresh** with `RefreshTokens`. When the client authenticates with a
  Client Attestation, the refresh token is bound to the instance key
  (attestation-based client authentication §10.3): only this
  installation can redeem it.
- **Revoke** with `RevokeToken` when the app no longer needs a refresh
  token, before deleting the key it's bound to. `ErrorRevocationNotSupported`
  means the server offers no revocation endpoint, and the token can only
  be forgotten.
- **Errors** may include text the server wrote. Before an error crosses
  into platform code (gomobile turns `Error()` into an `NSError`
  message), map a `*client.Error` to `Code()` and `ServerResponse()`.

## Issuing to wallets: the pre-authorized code grant

An issuer that serves its own grant, such as OpenID4VCI's
pre-authorized code, at the token endpoint uses
`AuthenticateAttestedClient` and `VerifyTokenRequestBinding` for the
client and its DPoP proof, then `IssueRefreshToken` so the wallet can
refresh, bound to the same instance key. See "Serving a grant this
package doesn't" in [GETTING_STARTED](../../GETTING_STARTED.md).

## Further reading

- The `client` package documentation, "Native apps" section.
- [DPoP in Go](dpop.md) and [PAR in Go](par.md), which every request
  above uses.

[RFC 8252]: https://www.rfc-editor.org/rfc/rfc8252
