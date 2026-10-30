# Production checklist

What a deployment must do before real clients rely on it. Each item
links to the part of [GETTING_STARTED.md](../GETTING_STARTED.md) that
explains it. `New` refuses many of these mistakes at startup under
production assurance, but not all of them. The items marked *(yours)*
are things no constructor can check.

## Authorization server (`server`)

- [ ] **`Config.Assurance = server.AssuranceProduction`**, with
  `Config.Deployment` set. `AssuranceDevelopment` is not FAPI 2.0
  conformant, though its metadata looks the same.
  [Step 2](../GETTING_STARTED.md#2-build-a-config)
- [ ] **Durable stores** that declare `storage.StoreAssurance` *and* pass
  the contract tests in your own test suite, since the declaration isn't
  verified: `storage.TestClientRepositoryContract`,
  `TestTransactionStoreContract`, `TestGrantStoreContract`,
  `TestReplayStoreContract`, `TestRevocationStoreContract`, plus
  `TestAccessTokenStoreContract` (opaque access tokens),
  `TestNonceStoreContract` (DPoP nonces) and
  `TestBackchannelAuthenticationStoreContract` (CIBA). With
  `DeploymentHorizontallyScaled`, every instance must share them.
  The [`sqlstore`](../sqlstore) module provides the client repository,
  transaction, grant, replay, nonce and revocation stores on PostgreSQL
  (any deployment) or SQLite (`DeploymentSingleInstance` only), already
  passing those contracts; run its `Migrate` and, periodically, `Sweep`.
  [Step 1](../GETTING_STARTED.md#1-dependencies-use-the-reference-implementations-to-start)
- [ ] **Durable signing keys** that declare `keys.KeyCustodyAssurance`
  (`keys.NewKeyManagerFromSigners` with `keys.DeclareCustody`), and a
  plan for [rotating them](../GETTING_STARTED.md#9-rotating-a-signing-key).
- [ ] **Client keys** from `keys.NewStaticClientKeys` or
  `keys.NewClientJWKSSource`. A `keys.ClientKeySource` of your own must
  pass `keys.TestClientKeySourceContract`.
  [Step 1](../GETTING_STARTED.md#1-dependencies-use-the-reference-implementations-to-start)
- [ ] **An audit sink** (`Dependencies.Audit`), `server.SystemClock{}`
  and `crypto/rand.Reader`.
  [Step 4](../GETTING_STARTED.md#4-wire-dependencies-and-construct-the-server)
- [ ] **A revocation choice:** a revocation store the resource servers
  share, or `server.NoRevocation{}` with short access token lifetimes,
  knowing that code reuse and `RevokeGrant` then revoke nothing.
  [Step 2](../GETTING_STARTED.md#2-build-a-config)
- [ ] **A DPoP nonce choice:** a nonce store every instance shares
  (`Dependencies.Nonces`, with `Limits.DPoPNonceLifetime` of at most 15
  minutes), so a DPoP proof generated ahead of time or captured is
  refused, at the cost of one extra round trip per client on first use;
  or `server.NoDPoPNonces{}` to decline, as an mTLS-only deployment can.
  [Step 4](../GETTING_STARTED.md#4-wire-dependencies-and-construct-the-server)
- [ ] **A client certificate trust choice:** `NoPKIClientAuthentication{}`
  unless a client uses `tls_client_auth`; otherwise `TrustedClientCAs`
  with revocation checking, or `ClientCertificateChainVerifiedUpstream{}`
  only when your TLS termination verifies every chain.
  [Step 4](../GETTING_STARTED.md#4-wire-dependencies-and-construct-the-server)
- [ ] *(yours)* **Authenticate before redirecting.** Before a user has
  authenticated, end with `DenyLocally`, never `Deny` or
  `AuthenticationFailed`.
  [Step 5](../GETTING_STARTED.md#5-the-one-piece-thats-genuinely-yours-the-login-flow)
- [ ] *(yours)* **Pass the real authentication time** to
  `server.NewAuthenticationContext`: when the user actually
  authenticated, not `time.Now()` when you reuse a session, so `max_age`
  and `prompt=login` hold.
  [Step 5](../GETTING_STARTED.md#5-the-one-piece-thats-genuinely-yours-the-login-flow)
- [ ] *(yours)* **Bind the interaction to the browser** with
  `server/interactioncookie` (its keys shared by every instance) or the
  equivalent, and protect the consent form against CSRF.
  [Step 5](../GETTING_STARTED.md#5-the-one-piece-thats-genuinely-yours-the-login-flow)
- [ ] *(yours)* **Wrap `/authorize` and every login, consent and error
  page in `server.AuthorizationPageHeaders`** (anti-framing,
  `Referrer-Policy: no-referrer`, `no-store`). Load no third-party
  scripts or images there, and don't log full `/authorize` URLs.
  Redirect with 303 after a form POST, and render errors with
  `WriteText`/`WriteJSON`, never `Error()`.
  [Step 5](../GETTING_STARTED.md#5-the-one-piece-thats-genuinely-yours-the-login-flow)
- [ ] *(yours)* **The HTTP layer:** TLS 1.2 or later with BCP 195 cipher
  suites (at the proxy, if one terminates TLS), HSTS on browser-facing
  endpoints, and no CORS on the authorization endpoint.
  [Step 6](../GETTING_STARTED.md#6-the-rest-of-the-http-surface)
- [ ] *(yours)* **Client certificates behind a proxy:** read a forwarded
  certificate with `fapihttp.ForwardedClientCertificate` (RFC 9440
  `Client-Cert`), passing a `trusted` check such as
  `fapihttp.RemoteAddrIn` that accepts only your own proxy, and have the
  proxy strip any copy of the header a client sent.
  [Step 7](../GETTING_STARTED.md#verify-a-request)
- [ ] **Subjects:** decide between public and pairwise subjects before
  clients store any `sub`.
  [Pairwise subjects](../GETTING_STARTED.md#pairwise-subjects)

## Resource server (`resource`)

- [ ] **`resource.AssuranceProduction`** with `Deployment` set, and
  stores that pass the same contract tests as above.
  [Build a `Config`](../GETTING_STARTED.md#build-a-config)
- [ ] **`Config.ResourceURLs`** set to this API's own external URLs;
  behind a proxy that rewrites paths, set `VerifyRequest.URL`.
  [Verify a request](../GETTING_STARTED.md#verify-a-request)
- [ ] **The access token format matches the authorization server's.**
  JWT: `MaxTokenLifetime` at least the server's `AccessTokenLifetime`,
  and `Audience` set. Opaque: the *same* `storage.AccessTokenStore` the
  authorization server writes to, since there is no introspection
  endpoint.
  [Wire `Dependencies`](../GETTING_STARTED.md#wire-dependencies)
- [ ] **The same revocation store as the authorization server**, or
  `resource.NoRevocationUntilExpiry{MaxTokenLifetime: ...}` (at most 15
  minutes) to decline checking it; production refuses `NoRevocation{}`.
  [Wire `Dependencies`](../GETTING_STARTED.md#wire-dependencies)
- [ ] **A DPoP nonce choice:** a nonce store of the resource server's
  own (never the authorization server's), shared by its instances, with
  `Random` and `Limits.DPoPNonceLifetime`; or `resource.NoDPoPNonces{}`
  to decline. `serverresource.NewVerifier` takes it as `Options.Nonces`.
  [Wire `Dependencies`](../GETTING_STARTED.md#wire-dependencies)
- [ ] *(yours)* **Authorize anything a user owns by
  `AuthorizationContext.EndUser()`**, never by `InternalSubject` alone (a
  client credentials token's subject is a client), and use
  `ClientSubject` for anything returned to a client. [Pairwise subjects at a resource server](../GETTING_STARTED.md#pairwise-subjects-at-a-resource-server)
- [ ] *(yours)* **`PeerCertificate` behind a proxy:** the same rule as
  the authorization server's, with `fapihttp.ForwardedClientCertificate`.
  [Verify a request](../GETTING_STARTED.md#verify-a-request)

## Client (`client`)

- [ ] **`client.AssuranceProduction`**, with `Dependencies.HTTP` from
  `fapihttp.NewClient` and any client certificate or private roots given
  when it's built.
  [Step 10](../GETTING_STARTED.md#10-the-client-side-calling-a-fapi-20-authorization-server)
- [ ] **A durable session store** that passes
  `storage.TestSessionStoreContract`, and durable keys declaring
  `keys.KeyCustodyAssurance`.
- [ ] *(yours)* **Bind each authorization to the browser** that began it
  (`client/sessioncookie`), against login CSRF.
  [Step 10](../GETTING_STARTED.md#10-the-client-side-calling-a-fapi-20-authorization-server)
- [ ] *(yours)* **Serve the redirect URI with `Referrer-Policy:
  no-referrer`**, and no third-party content, so the authorization code
  doesn't leak (RFC 9700 §4.2.4).
- [ ] **`RequireAuthorizationResponseIss`**, and `MaxIDTokenLifetime`
  set to your provider's ID token lifetime if you know it.
- [ ] *(yours)* **Seal stored tokens** with `client.TokenSetSealer` if you
  keep them past the request.
  [Step 10](../GETTING_STARTED.md#10-the-client-side-calling-a-fapi-20-authorization-server)
