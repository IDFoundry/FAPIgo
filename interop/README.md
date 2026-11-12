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
| 3 | Message signing: a signed request object (JAR) pushed via PAR, a JARM response (`response_mode=jwt`) verified by openid-client, `private_key_jwt` + DPoP; UserInfo and `/accounts`. The client signs with PS256 (an RSA key): its client assertion, request object and DPoP proofs. | FAPI 2.0 Message Signing |
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

Every client signs with ES256 (P-256 keys) except leg 3's, which
signs with PS256 (a 2048-bit RSA key), so the server is exercised with
both FAPI 2.0 signing algorithms clients commonly use.

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
| `undici` | 8.12.4 (TLS options for the client's `customFetch`) |

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

`.github/workflows/interop-openid-client.yml` runs it daily, on
demand, and on a pull request that changes this suite, the workflow,
or `cmd/conformance-as` and the packages it builds from. It is not a
required check.

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
| 3 | Message signing: JAR via PAR + JARM | Runs. The client's PS256 signing key as the grant's `jar` and for `private_key_jwt`, `ResponseMode::Jwt` (the mode conformance-as advertises), DPoP with a PS256 key setup.mjs generated (an RSA key generated in huskarl's unoptimized build would be slow). |
| 4 | `client_credentials` + `private_key_jwt` + DPoP | Runs. `ClientCredentialsGrant`. |
| 5 | CIBA poll | Skipped: huskarl 0.11.10 has no CIBA grant. A poll-mode grant is merged upstream but not yet released; the leg can be added when a release carries it. |
| 6 | CIBA ping | Skipped: huskarl implements no CIBA ping (or push) mode. |

The consent form is submitted the same way as in the openid-client
suite. The harness trusts only the run's test CA
(`ReqwestClient::builder().root_certificates`).

`huskarl/Cargo.toml` pins every direct dependency to an exact version
(`=x.y.z`) and `huskarl/Cargo.lock` pins the whole tree; the runner
builds with `cargo build --locked`, and
`.github/workflows/interop-huskarl.yml` pins the Rust toolchain; it
runs the suite daily, on demand, and on a pull request that changes
the suite or the server it drives. It is not a required check. Dependabot proposes crate updates weekly; a bump of `huskarl`
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

None open.

The oidc-provider suite found two in FAPIgo's client, both fixed in
v0.72.2: `NewFromDiscovery` kept a discovered CIBA endpoint for a
client not configured for CIBA, so `New` refused it; and
`ResourceClient.Do` didn't cache a protected resource's challenge DPoP
nonce, so every later request was challenged again (RFC 9449 §9 and
§8.2). The openid-client suite found one in the server, also fixed in
v0.72.2: a DPoP nonce challenge at PAR or the CIBA endpoint consumed
the signed request the client then resent with the nonce.

## oidc-provider: FAPIgo's client against an independent server

The second suite runs the other direction. The server is
[`oidc-provider`](https://github.com/panva/node-oidc-provider)
(Node.js), configured as a FAPI 2.0 authorization server in
[`oidc-provider/server.mjs`](oidc-provider/server.mjs); the client is
FAPIgo's `client` package, driven by
[`fapigo-client`](fapigo-client), a Go program in a module of its own
(building against this checkout through a `replace` directive, and
limited to FAPIgo's public API, which interop-oidc-provider.yml checks). Only positive
flows are run, for the same reason as above.

The provider runs with oidc-provider's `fapi` profile `'2.0'`, PAR
required, PKCE (S256), DPoP with a server nonce required on every
request, mTLS (`self_signed_tls_client_auth` and certificate-bound
tokens) with `mtls_endpoint_aliases` on a second listener that requires
a client certificate, request objects and JARM, `client_credentials`,
CIBA poll and ping, resource indicators, and ES256 and PS256 signing,
both advertised for ID tokens, so `NewFromDiscovery` doesn't pick the
ID token algorithm on its own: each client registers one
(`id_token_signed_response_alg`), PS256 for `code-mtls-mtls` and
`ciba-ping` and ES256 for the others, and the driver is told it, as an
integrator sets `Algorithms.IDToken` from their registration. It sends
`iss` on every authorization response (RFC 9207) and says so in its
metadata. It keeps oidc-provider's default for refresh tokens, its
reading of OIDC Core §11: one only for `offline_access` requested with
`prompt=consent`, so the authorization code legs send
`BeginAuthorizationRequest.Prompt` as an integrator would.

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

`.github/workflows/interop-oidc-provider.yml` runs it daily, on
demand, and on a pull request that changes this directory, the driver,
the workflow, or the packages FAPIgo's client builds from. It is not a required check.

## Keycloak: FAPIgo's client against a second independent server

The third suite runs FAPIgo's client package, through the same
[`fapigo-client`](fapigo-client) driver and its six legs, against
[Keycloak](https://github.com/keycloak/keycloak) (Java), run with
Docker. Only positive flows are run, for the same reason as above.

Keycloak runs in development mode (`start-dev`: an in-memory database,
no clustering) over HTTPS with the run's test CA, requesting (not
requiring) a client certificate on its one listener, which it also
advertises as `mtls_endpoint_aliases`; its trust store is the test CA,
for client certificates and for the driver's CIBA notification
endpoint. [`keycloak/setup.mjs`](keycloak/setup.mjs) configures a realm
through the admin REST API: a CIBA setup (poll by
default, `login_hint` as the username), the test user, the six clients,
and one client policy per kind of client applying Keycloak's own global
client profiles: `fapi-2-dpop-security-profile` (legs 1 and 4),
`fapi-2-security-profile` (leg 2), `fapi-2-dpop-message-signing`
(leg 3), and `fapi-2-security-profile` with `fapi-ciba` (legs 5 and 6).
Each client is saved once more after the policies are in place, so the
profiles' executors check it and auto-configure what they own (consent
required, full scope disabled, PKCE, the sender constraint); setup fails
if a client isn't under a profile. What each client signs (client
assertions, request objects, CIBA requests) is ES256. What Keycloak
signs is left to the profiles, whose `secure-signature-algorithm`
executor fills in PS256 for ID tokens, access tokens and UserInfo
responses (which it also turns signed), using the realm's RSA key: the
configuration a FAPI 2.0 deployment of Keycloak gets by default. JARM
responses are the exception: the profiles don't set their algorithm and
Keycloak would otherwise use the realm's default RS256, which FAPI 2.0
doesn't allow, so the Message Signing client registers PS256 for them.

### Legs

| # | Leg | Keycloak |
|---|-----|----------|
| 1 | `code-pkjwt-dpop` | Runs. PAR required, PKCE (S256), `private_key_jwt` with the client's JWKS registered, DPoP-bound access and refresh tokens, signed UserInfo. Keycloak doesn't require DPoP nonces, so FAPIgo's nonce retry isn't exercised here. |
| 2 | `code-mtls-mtls` | Runs, with `tls_client_auth` (RFC 8705 §2.1) instead of `self_signed_tls_client_auth`: Keycloak's X.509 client authenticator matches the certificate's subject DN against the registration and needs a chain to a CA in its trust store, and Keycloak has no self-signed method. The client certificate comes from the run's test CA; the driver's leg sets `tls_client_auth`. Certificate-bound tokens. |
| 3 | `message-signing` | Runs. A signed request object required, pushed via PAR, and a JARM response (`response_mode=jwt`): the request object ES256, the response PS256; `private_key_jwt` + DPoP. |
| 4 | `client-credentials` | Runs, without a resource indicator: Keycloak doesn't implement RFC 8707, so the leg asks only for the `accounts` scope (the client's one optional scope) and checks that exactly it is granted. |
| 5 | `ciba-poll` | Runs. A signed authentication request (`fapi-ciba` requires one), `private_key_jwt`, certificate-bound tokens. |
| 6 | `ciba-ping` | Runs. Keycloak sends the ping to the driver's endpoint as `host.docker.internal`. |

The user signs in through Keycloak's own login page: the driver's
configuration names the login form's fields (`login_form`), and its user
agent, when the authorization request lands on a page with a form
instead of a redirect, fills them in, keeps the form's hidden inputs and
posts it, which also accepts the consent page the profiles require.

Keycloak hands each CIBA request to an authentication channel. Its HTTP
channel provider is pointed at
[`keycloak/harness.mjs`](keycloak/harness.mjs), which stands in for the
authentication device: it holds the request Keycloak posts, and when the
driver calls its approval hook it completes that request through
Keycloak's channel callback endpoint. Keycloak doesn't pass the
`auth_req_id` to the channel; as the driver runs one leg at a time, the
hook approves the oldest request waiting.

Each leg's ID token, UserInfo and JARM signing algorithm comes from the
driver's configuration (`id_token_signed_response_alg`,
`userinfo_signed_response_alg`, `authorization_signed_response_alg`),
which setup copies from each client's registration once the profiles
have filled it in, as an integrator would set the algorithms registered
for its client: Keycloak advertises many, and `NewFromDiscovery` takes
the ID token's only when one is advertised.

### Pinned versions

[`keycloak/Dockerfile`](keycloak/Dockerfile) is never built: its `FROM`
line is the image the runner pulls and runs, pinned by tag and digest,
and Dependabot proposes updates weekly. A bump also updates the table
below and the version named in the top-level README. `setup.mjs` and
`harness.mjs` use Node.js's standard library only.

| Image | Version |
|-------|---------|
| `quay.io/keycloak/keycloak` | 26.8.2 |

### Running it

```sh
./interop/run-keycloak.sh
```

It needs Go (the version in `fapigo-client/go.mod`), Docker, Node.js
22.12 or later, curl and openssl. The runner builds the driver,
generates a fresh test CA, a server certificate (for `localhost` and
`host.docker.internal`) and two client certificates from that CA in a
temporary directory (nothing is committed), starts Keycloak on port
29543, configures the realm and writes the driver's configuration,
starts the harness on port 29547, runs the legs (the driver's
notification endpoint uses 29546), and always removes the container,
stops the harness and deletes the directory. On Linux, the harness and
the notification endpoint listen on the Docker bridge's gateway address,
which the container reaches as `host.docker.internal`; elsewhere (Docker
Desktop) on the loopback address. Set `INTEROP_KC_PORT`,
`INTEROP_DRIVER_PORT` or `INTEROP_HARNESS_PORT` to move a port, and
`INTEROP_KEEP_WORK_DIR=1` to keep the directory (configuration, keys,
Keycloak's and the harness's logs) after the run.

`.github/workflows/interop-keycloak.yml` runs it daily, on demand,
and on a pull request that changes this directory, the driver, the
workflow, or the packages FAPIgo's client builds from. It is
not a required check.
