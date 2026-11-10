# Interoperability tests

The OIDF conformance suite checks FAPIgo against the specifications.
This directory checks something narrower and complementary: that an
independent, widely used client implementation completes real FAPI 2.0
flows against FAPIgo's authorization server, with no FAPIgo code on the
client side.

The client is [`openid-client`](https://github.com/panva/openid-client)
(Node.js). The server is [`cmd/conformance-as`](../cmd/conformance-as),
the same FAPIgo authorization server the conformance runs use, started
with a configuration written for this suite. Only positive flows are
run: negative cases are covered by FAPIgo's own tests and the
conformance suite, and a correct client can't produce them.

## Legs

Each leg is a separate `node:test` case and passes or fails on its own.

| # | Leg | Server instance |
|---|-----|-----------------|
| 1 | Authorization code + PAR + PKCE (S256) + `private_key_jwt` + DPoP-bound tokens; ID token validated by openid-client; UserInfo and the `/accounts` resource with DPoP; refresh-token grant with DPoP. Every `use_dpop_nonce` challenge is answered by openid-client's own retry. | FAPI 2.0 Security Profile |
| 2 | Authorization code + PAR + PKCE with `self_signed_tls_client_auth` and certificate-bound tokens (RFC 8705), using `mtls_endpoint_aliases` for PAR, token, UserInfo and refresh; `/accounts` over mTLS. | FAPI 2.0 Security Profile, `-mtls` |
| 3 | Message signing: a signed request object (JAR) pushed via PAR, a JARM response (`response_mode=jwt`) verified by openid-client, `private_key_jwt` + DPoP; UserInfo and `/accounts`. | FAPI 2.0 Message Signing |
| 4 | `client_credentials` + `private_key_jwt` + DPoP; `/accounts`. | FAPI 2.0 Security Profile, `-client-credentials-grant` |
| 5 | CIBA poll: signed authentication request, `private_key_jwt`, certificate-bound tokens (FAPI-CIBA's sender constraint is mTLS); polling meets `authorization_pending` before approval via `POST /backchannel-approve`; UserInfo and `/accounts` over mTLS. | FAPI 2.0 Security Profile, `-mtls -ciba` |
| 6 | CIBA ping: as leg 5, with the harness serving the `client_notification_endpoint` over HTTPS (a certificate from the run's test CA), checking the ping's bearer token and body, then redeeming the `auth_req_id`. | FAPI 2.0 Security Profile, `-mtls -ciba` |

Users interact the way the conformance suite drives them: the harness
submits `cmd/conformance-as`'s consent form (`POST /authorize/decision`)
in place of a browser, and approves CIBA requests through
`POST /backchannel-approve` in place of an authentication device.

openid-client has no CIBA-specific request signer, so the CIBA legs sign
the authentication request (CIBA Core §7.1.1) with its JAR signer,
`buildAuthorizationUrlWithJAR`, which produces the claims §7.1.1 needs
(`iss`, `aud`, `exp`, `iat`, `nbf`, `jti`) and adds `client_id` and
`response_type=code`, which the server ignores.

Client IDs follow the `fapigo-{family}-{axis1}-{axis2}` convention in
[AGENTS.md](../AGENTS.md); leg 3's `fapigo-ms-pkjwt-dpop` uses `ms` for
the Message Signing family.

## Pinned versions

`openid-client/package.json` pins every direct dependency to an exact
version and `package-lock.json` pins the whole tree; the runner installs
with `npm ci`. Dependabot proposes updates weekly; a bump of
`openid-client` also updates the table below and the version named in
the top-level README.

| Package | Version |
|---------|---------|
| `openid-client` | 6.8.9 (with `oauth4webapi` 3.8.8 and `jose` 6.2.17) |
| `undici` | 7.30.2 (TLS options for the client's `customFetch`) |

## Running it

```sh
./interop/run-openid-client.sh
```

It needs Go (the version in `go.mod`), Node.js 22.12 or later, npm, curl
and openssl. The runner builds `cmd/conformance-as`, generates a fresh
test CA, server certificate, client certificates and client signing keys
in a temporary directory (nothing is committed), writes the server
configurations, starts two server instances on ports 28443-28445 (the
harness's notification endpoint uses 28446), runs the legs, and always
stops the servers and deletes the directory. Set `INTEROP_AS_PORT`,
`INTEROP_AS_MTLS_PORT`, `INTEROP_AS_MS_PORT` or `INTEROP_HARNESS_PORT` to
move a port, and `INTEROP_KEEP_WORK_DIR=1` to keep the directory
(configurations, keys, server logs) after the run.

`.github/workflows/interop.yml` runs it weekly, on demand, and on a pull
request that changes this directory, the workflow or
`cmd/conformance-as`. It is not a required check.

## huskarl (Rust)

A second client, in a second language:
[huskarl](https://github.com/huskarl-rs/huskarl), a Rust OAuth 2.0
client library, runs the same flows against the same server
configuration from [`huskarl/`](huskarl), a small binary crate built
only on huskarl's public API. The runner reuses
`openid-client/setup.mjs` to write the server configurations and client
keys (it needs only Node.js, no npm packages), so both suites drive
identically configured servers with the same client IDs. Each leg
prints `ok` or `not ok` on its own; the binary exits non-zero if any
leg fails.

| # | Leg | huskarl |
|---|-----|---------|
| 1 | Authorization code + PAR + PKCE + `private_key_jwt` + DPoP; UserInfo, `/accounts`, refresh | Runs. `AuthorizationCodeGrant` (PAR, PKCE and ID-token validation built in), `JwtBearer` with `Audience::Issuer`, `DPoP`; `UserInfoClient`; `/accounts` through `HttpAuthorizer`, re-sent once when `dpop_resend_advised`; `RefreshGrant` from `to_refresh_grant()`. |
| 2 | `self_signed_tls_client_auth` + certificate-bound tokens | Runs. `NoAuth` over an mTLS `ReqwestClient` (`MtlsPem`), which makes huskarl use the `mtls_endpoint_aliases` for PAR, token, UserInfo and refresh. |
| 3 | Message signing: JAR via PAR + JARM | Runs. The client's signing key as the grant's `jar`, `ResponseMode::Jwt` (the mode conformance-as advertises), `private_key_jwt` + DPoP. |
| 4 | `client_credentials` + `private_key_jwt` + DPoP | Runs. `ClientCredentialsGrant`. |
| 5 | CIBA poll | Skipped: huskarl 0.11.10 has no CIBA grant. A poll-mode grant is merged upstream but not yet released; the leg can be added when a release carries it. |
| 6 | CIBA ping | Skipped: huskarl implements no CIBA ping (or push) mode. |

The consent form is submitted the same way as in the openid-client
suite. The harness trusts only the run's test CA
(`ReqwestClient::builder().root_certificates`).

`huskarl/Cargo.toml` pins every direct dependency to an exact version
(`=x.y.z`) and `huskarl/Cargo.lock` pins the whole tree; the runner
builds with `cargo build --locked`, and interop.yml pins the Rust
toolchain. Dependabot proposes crate updates weekly; a bump of `huskarl`
also updates this table and the version named in the top-level README.

| Crate | Version |
|-------|---------|
| `huskarl` | 0.11.10 (with `huskarl-core` 0.10.10) |
| `huskarl-reqwest` | 0.9.3 (`rustls-tls`) |
| `huskarl-crypto-native` | 0.11.3 |
| Rust toolchain (CI) | 1.99.1 |

```sh
./interop/run-huskarl.sh
```

It needs Go (the version in `go.mod`), Rust 1.92 or later (cargo),
Node.js 22.12 or later (for `setup.mjs` only), curl and openssl, and
otherwise behaves like `run-openid-client.sh`: the same temporary
directory, ports 28443-28445 and environment variables.

## When a leg fails

First establish, with a citation to the specification, whose
interpretation is wrong before changing anything in FAPIgo. A green
conformance suite and a red interop leg mean one of the two
implementations reads a requirement differently, and either could be
the one at fault.

- If FAPIgo is wrong, fix it in a separate pull request with its own
  test, and keep the leg as the end-to-end check.
- If the other implementation is wrong, report it upstream in generic
  terms (the request, the response, the specification text), and note it
  below with a link, so the workaround in this suite is removed when the
  fix ships.

## Known disagreements

- **FAPIgo, `client.NewFromDiscovery`** (found by the oidc-provider
  suite). With an all-zero `Config.Endpoints`, it copies every
  discovered endpoint, `backchannel_authentication_endpoint` included
  (`client/client.go:114`), and `New` then refuses a client without
  `Algorithms.BackchannelAuthenticationRequest`
  (`client/client.go:531`). So a code-flow or `client_credentials`
  client built the documented way fails to construct against any
  server that also offers CIBA, unless it configures a CIBA signing
  algorithm it never uses. This is an API gap, not a reading of a
  specification. Workaround: `fapigo-client/wiring.go` sets `Endpoints`
  from discovery itself, without the CIBA endpoint, and calls
  `MTLSEndpoints.ApplyForConfig`, as `NewFromDiscovery` would; remove it
  once `NewFromDiscovery` leaves the CIBA endpoint out for a client not
  configured for CIBA.
- **FAPIgo, resource-server DPoP nonces** (found by the oidc-provider
  suite). After a `use_dpop_nonce` challenge from a protected resource
  (UserInfo here), `ResourceClient.Do` retries with the challenge's
  nonce (`client/resource.go:187-198`) but caches only the nonce on the
  retry's response (`client/noncecache.go:150`). oidc-provider sends
  `DPoP-Nonce` on a successful response only when the nonce has
  changed, so the nonce is never cached and every later UserInfo call
  is challenged again: one extra round trip each. RFC 9449 §9 has
  resource servers provide nonces "in the same way that authorization
  servers do as described in Sections 8 and 8.2", and §8.2 says the
  client "MUST use the new nonce value supplied for the next token
  request, and for all subsequent token requests until the
  authorization server supplies a new nonce"; FAPIgo's token endpoint
  path already does (leg 1's refresh is not challenged). No workaround:
  the retry succeeds.

## oidc-provider: FAPIgo's client against an independent server

The second suite runs the other direction. The server is
[`oidc-provider`](https://github.com/panva/node-oidc-provider)
(Node.js), configured as a FAPI 2.0 authorization server in
[`oidc-provider/server.mjs`](oidc-provider/server.mjs); the client is
FAPIgo's `client` package, driven by
[`fapigo-client`](fapigo-client), a Go program in a module of its own
(building against this checkout through a `replace` directive, and
limited to FAPIgo's public API, which interop.yml checks). Only positive
flows are run, for the same reason as above.

The provider runs with oidc-provider's `fapi` profile `'2.0'`, PAR
required, PKCE (S256), DPoP with a server nonce required on every
request, mTLS (`self_signed_tls_client_auth` and certificate-bound
tokens) with `mtls_endpoint_aliases` on a second listener that requires
a client certificate, request objects and JARM, `client_credentials`,
CIBA poll and ping, resource indicators, and ES256 signing. It sends
`iss` on every authorization response (RFC 9207) and says so in its
metadata. It issues a refresh token to every client registered for the
grant, rather than only for `offline_access` with `prompt=consent`, its
default.

### Legs

The driver runs each leg on its own and prints `PASS`, `FAIL` or `SKIP`
per leg.

| # | Leg | Client |
|---|-----|--------|
| 1 | `code-pkjwt-dpop`: authorization code + PAR + PKCE + `private_key_jwt` + DPoP-bound tokens; the ID token's `sub`; UserInfo with DPoP; the refresh-token grant with DPoP, and UserInfo again with the new access token. Every `use_dpop_nonce` challenge (PAR, token, UserInfo) is answered by FAPIgo's own retry. | `fapigo-sp-pkjwt-dpop` |
| 2 | `code-mtls-mtls`: as leg 1 with `self_signed_tls_client_auth` and certificate-bound tokens; PAR, token, UserInfo and refresh go to the `mtls_endpoint_aliases`. | `fapigo-sp-mtls-mtls` |
| 3 | `message-signing`: a signed request object (JAR) pushed via PAR, to a client registered with `require_signed_request_object`; a JARM response (`response_mode=jwt`) verified by FAPIgo; `private_key_jwt` + DPoP; UserInfo and refresh. | `fapigo-ms-pkjwt-dpop` |
| 4 | `client-credentials`: `client_credentials` + `private_key_jwt` + DPoP, with a resource indicator (RFC 8707) the provider issues the `accounts` scope for. No resource is called: oidc-provider serves no protected resource besides UserInfo, which needs an end user. | `fapigo-sp-cc-pkjwt-dpop` |
| 5 | `ciba-poll`: a signed authentication request (CIBA Core §7.1.1), `private_key_jwt`, certificate-bound tokens (FAPI-CIBA's sender constraint is mTLS) at the aliases; the first poll meets `authorization_pending`, then the request is approved and redeemed; UserInfo over mTLS. | `fapigo-ciba-poll-pkjwt` |
| 6 | `ciba-ping`: as leg 5 in ping mode, with the driver serving the `client_notification_endpoint` over HTTPS (a certificate from the run's test CA), reading the ping with `client.ParseBackchannelNotification` and checking its bearer token against the session before redeeming the `auth_req_id`. | `fapigo-ciba-ping-pkjwt` |

The user is a fixture. `server.mjs` serves oidc-provider's interaction
routes: `GET /interaction/:uid` signs in the one test user
(`interop-user`) and consents to whatever was requested, then hands back
to the provider, so the driver's user agent (a cookie jar following
redirects) reaches the redirect to the client's redirect URI, which is
never served. `POST /harness/ciba-approve` (form parameter
`auth_req_id`) stands in for the authentication device: it approves the
request through `provider.backchannelResult`, which also sends a
ping-mode client its notification. oidc-provider refuses to send
anything to a loopback address (SSRF protection); `server.mjs` lifts
that for the driver's notification endpoint only.

The client is built the way an integrator would build one:
`client.Discover` through a hardened `fapihttp` fetcher, the JWKS from
the metadata, `RecommendedAlgorithms` and `RecommendedLimits` (plus a
one-minute CIBA request lifetime), `fapihttp.NewClient`'s transport, and
`NewFromDiscovery`, which picks the mTLS aliases and requires `iss` on
authorization responses. It runs at `AssuranceDevelopment` because of
the test environment, in three places `AssuranceProduction` refuses:
the provider is on localhost (`AllowLoopbackHosts` on the transport and
the fetcher), authorization sessions are in `memstore`, and the keys are
the run's throwaway keys, held in memory with no declared custody.

The driver isn't tied to oidc-provider: it reads the issuer, the CA, the
test user, the CIBA approval hook's URL, the notification listener and
each leg's client registration from a JSON file the runner writes
(`setup.mjs` here; see `runConfig` in `fapigo-client/config.go`), and a
leg can be marked skipped there with a reason.

### Pinned versions

`oidc-provider/package.json` pins `oidc-provider` exactly and
`package-lock.json` pins the whole tree; the runner installs with
`npm ci --ignore-scripts`. The driver has no dependency besides FAPIgo.
Dependabot proposes updates weekly; a bump of `oidc-provider` also
updates the table below and the version named in the top-level README.

| Package | Version |
|---------|---------|
| `oidc-provider` | 9.13.3 (with `jose` 6.2.17 and `koa` 3.3.0) |

### Running it

```sh
./interop/run-oidc-provider.sh
```

It needs Go (the version in `fapigo-client/go.mod`), Node.js 22.12 or
later, npm, curl and openssl. The runner builds the driver, generates a
fresh test CA, a localhost certificate and two self-signed client
certificates in a temporary directory, has `setup.mjs` generate the
clients' signing keys and write the provider's client registrations and
the driver's configuration there (nothing is committed), starts the
provider on ports 29443 (issuer) and 29444 (mTLS aliases), runs the
legs (the driver's notification endpoint uses 29446), and always stops
the provider and deletes the directory. Set `INTEROP_OP_PORT`,
`INTEROP_OP_MTLS_PORT` or `INTEROP_DRIVER_PORT` to move a port, and
`INTEROP_KEEP_WORK_DIR=1` to keep the directory (configuration, keys,
the provider's log) after the run. `fapigo-client -leg <name>` runs one
leg.

`.github/workflows/interop.yml`'s `oidc-provider` job runs it weekly, on
demand, and on a pull request that changes this directory, the workflow,
or the packages FAPIgo's client builds from. It is not a required check.
