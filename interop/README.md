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

None known.
