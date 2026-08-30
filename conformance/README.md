# Conformance

[![FAPI Conformance](https://github.com/IDFoundry/FAPIgo/actions/workflows/conformance.yml/badge.svg)](https://github.com/IDFoundry/FAPIgo/actions/workflows/conformance.yml)

Reflects the latest scheduled/manually-triggered run of
[`scripts/run-all.sh`](scripts/run-all.sh) in CI (see
[`../.github/workflows/conformance.yml`](../.github/workflows/conformance.yml))
— not a per-commit guarantee, since this doesn't run on every push/PR.

Conformance testing is tracked separately per role: passing the
authorization-server suite says nothing about client conformance, even
where both sides use the same internal JOSE code, because the protocol
behaviour and negative-test expectations differ. See
[ARCHITECTURE.md](../ARCHITECTURE.md#conformance-strategy).

- `client/` — OpenID Foundation RP/client conformance configuration and
  run scripts.
- `server/` — OpenID Foundation FAPI 2.0 AS conformance configuration and
  run scripts.
- `scripts/run-all.sh` — runs all twenty suites this repo has driver
  support for (AS baseline, AS message-signing, AS ciba-mtls, AS
  ciba-ping, AS mtls, AS message-signing-mtls, AS client-auth-mtls, AS
  client-auth-mtls-and-mtls, AS ciba-client-auth-mtls, AS
  ciba-ping-client-auth-mtls, AS baseline/mtls/client-auth-mtls/
  client-auth-mtls-and-mtls-client-credentials, RP baseline, RP
  message-signing, RP ciba-mtls, RP client-auth-mtls, RP mtls, RP
  client-auth-mtls-and-mtls) against a locally running suite and prints
  one combined summary. See the script's own header comment for
  prerequisites and env vars.
- `resource/` — resource-server verification test vectors (DPoP proof
  validation, access-token binding checks) used outside the OIDF suite.
  The suite doesn't run its own dedicated resource-server conformance
  plan against this role, but the AS test plan's happy-flow module does
  call a real protected-resource endpoint with the token it just
  issued — `cmd/conformance-as` points it at its own `/userinfo`
  endpoint (`resource.go`, backed by the `resource` package) for every
  profile except client_credentials, which points at a second, non-OIDC
  `/accounts` endpoint instead (see [Client Credentials
  Grant](#client-credentials-grant) below) — both satisfy that AS-plan
  requirement as a side effect of already needing to exist for real,
  not as resource-role certification in their own right.

## CIBA

`server`'s CIBA support (`BeginBackchannelAuthentication`/
`CompleteBackchannelAuthentication`/`ExchangeBackchannelAuthentication`,
poll and ping delivery) is verified by unit/integration tests, not the live
OIDF suite as its primary gate: `fapi-ciba-id1-test-plan` requires
MTLS-bound access tokens unconditionally. Now that this module supports
mTLS sender-constraining (RFC 8705 §3, `-mtls`), this was genuinely
re-attempted live against `ciba-mtls.config.json` — **34/34 PASS.**
Seven real library/harness gaps the attempt surfaced were all fixed
along the way: `tls_client_certificate_bound_access_tokens` metadata,
client-assertion `aud` acceptance being far too narrow, a stricter
legacy FAPI-RW §8.5 TLS check that needed both a narrower cipher list
*and* an RSA (not ECDSA) server certificate, a CIBA-specific error code
that had incorrectly borrowed PAR's `invalid_request_object`
convention, a missing `iat` requirement on CIBA's own request object, 3
modules that self-skip without an RSA/PS256-registered client
(switching the plan's own client 1 from ES256 turned all three from
SKIPPED to PASSED), and a `binding_message` acceptability check (CIBA
§13's `invalid_binding_message`) this module didn't have at all — the
last one was initially misdiagnosed as an unfixable gap in the suite's
own automated-approval design (the check the suite runs after
*accepting* an overlong/unusual binding message unconditionally fails
under automated approval, since it requires demonstrating the value was
actually displayed to a human); disassembling the actual test module's
bytecode showed the suite has a dedicated, fully-supported *rejection*
branch instead — reject a binding message the AS can't safely/faithfully
display with `invalid_binding_message`, and the display-verification
check is never reached. Full breakdown, live findings and reproduction
steps in
[`server/oidf-config/README.md`](server/oidf-config/README.md#ciba-mtlsconfigjson--the-genuine-mtls-re-attempt-automated).
Wired into `scripts/run-all.sh` as its own "AS ciba-mtls" leg now that
it's a clean 34/34.

CIBA §10.2 ping delivery mode got its own AS-side re-attempt too, once
`server.BackchannelNotifier`/`storage.BackchannelTokenDeliveryModePing`
existed — two extra clients on the same `conformance-as-ciba-mtls`
container, driven under `ciba-ping-plan.json`. Surfaced two more real
bugs: the interval throttle rejected a client's poll made immediately
after receiving a ping notification with `slow_down` (fixed by exempting
exactly that one poll per notification), and the outbound notifier
followed an HTTP redirect from the notification endpoint instead of
treating it as the final response. Confirmed live: the core
`fapi-ciba-id1` module plus all five ping-specific modules PASS. Full
breakdown in
[`server/oidf-config/README.md`](server/oidf-config/README.md#ciba-ping-planjson--ciba-102-ping-delivery-mode-automated).
Wired into `scripts/run-all.sh` as its own "AS ciba-ping" leg — no
RP-side counterpart, since `cmd/conformance-client` only ever plays a
poll-mode CIBA client.

`client`'s own CIBA support
(`BeginBackchannelAuthentication`/`PollBackchannelAuthentication`) was
genuinely attempted, live, against the RP-side
`fapi-ciba-id1-client-test-plan` (`cmd/conformance-client -profile=ciba`) —
unlike the AS side, its backchannel-authentication step doesn't share
the unconditional MTLS mandate, but its *token* endpoint does, for a
separately confirmed reason. Under DPoP: 3 of 22 modules genuinely PASS
(the ones that never reach token exchange); the rest FAIL for that one
uniform reason. Re-attempted live with `-mtls`
(`storage.SenderConstrainMTLS`) once `client` gained that support: the
token-endpoint MTLS wall is now fully resolved — every module reaches
real token exchange and correctly performs this client's own ID-token
validation against each negative-test perturbation (bad iss/aud/signature/alg,
expired, missing claims), with full suite-graded credit, not just a
correct driver-side detection. **Confirmed live: 22/22 PASS.** Wired
into `scripts/run-all.sh` as its own "RP ciba-mtls" leg. See
[`client/scripts/README.md`](client/scripts/README.md#ciba--profileciba)
for the full breakdown, including the four fixes (three driver-side,
one genuine `client`/`internal/token` gap) that took the `-mtls`
re-attempt from its first partial result to a clean 22/22.

## RAR

Rich Authorization Requests (RFC 9396, `authorization_details`) is
implemented end-to-end across both the PAR-fed authorization-code flow
and CIBA — the same `extension.RARDefinition`/`RARRegistry` types and
validation logic wired into both, including a per-type narrowing hook
so a resource owner may grant less than a client requested. Unlike
CIBA, the OIDF suite has no dedicated RAR conformance plan at all, so
this is deliberately outside the automated live-suite loop entirely,
verified instead by `extension/rar_test.go`, `server/rar_test.go`
(narrowing-grant validation, full PAR/CIBA end-to-end flows, rejection
of ungranted/over-scoped `authorization_details`), and
`cmd/conformance-as`'s own real-HTTP smoke tests
(`TestSmokeAuthorizationCodeFlowWithAuthorizationDetails`,
`TestSmokeCIBAFlowWithAuthorizationDetails`).

## Client Credentials Grant

`server.RequestClientCredentialsToken` (RFC 6749 §4.4) — opt-in via
`Config.ClientCredentialsGrant` plus a per-client
`storage.RegisteredClientConfig.AllowsClientCredentialsGrant`, matching
the same two-layer gate CIBA already established — was run live against
all four FAPI2SP OP "Client Credentials Grant" register profiles
(MTLS+MTLS, MTLS+DPoP, private key+MTLS, private key+DPoP), reusing the
same four already-running `conformance-as-{baseline,mtls,client-auth-mtls,
client-auth-mtls-and-mtls}` containers rather than standing up new ones
— this grant has no PAR/authorize/redirect_uri/browser hop at all, so
nothing about container topology needed to change, only the token
endpoint's own `grant_type` dispatch. **Confirmed live: all four
clean — 15/15, 11/11, 10/10, 6/6 modules, 0 failures/0 warnings.**

One real, previously-undocumented finding: the OIDF suite's
`fapi2-security-profile-final-test-plan` requires the `openid` variant
to be set to `plain_oauth`, not `openid_connect`, for
`fapi_profile=fapi_client_credentials_grant` — under `openid_connect`,
`happy-flow` fails outright expecting an `id_token` no grant with no end
user can ever produce; under `plain_oauth`, requesting the `openid`
*scope* is itself forbidden ("openid scope cannot be used with
PLAIN_OAUTH"). That collided with this binary's existing `/userinfo`
endpoint, which requires the `openid` scope per its own real OIDC
contract — client_credentials tokens here are registered for `accounts`
scope only, so every resource-calling module got `403
insufficient_scope`. Fixed by giving `cmd/conformance-as` a second,
genuinely non-OIDC protected-resource endpoint, `/accounts`
(`accountsHandler`, `resource.go`) — only the client_credentials plans'
`resource.resourceUrl` points there; every other profile still uses
`/userinfo` unchanged.

Also required each combo's plan to register two clients, not one:
`GetStaticClient2Configuration` interrupts every module outright
("Definition for client2 not present in supplied configuration")
regardless of `fapi_profile` — client1 alone is ever actually used to
request a token; client2 (PS256/RSA for the `private_key_jwt` combos,
matching the same RS256-negative-test-un-skip reasoning `ciba-mtls`
already established) is structural-only. Full breakdown in
[`server/oidf-config/README.md`](server/oidf-config/README.md#client-credentials-grant).
Wired into `scripts/run-all.sh` as its own four
"AS {baseline,mtls,client-auth-mtls,client-auth-mtls-and-mtls}
-client-credentials" legs. No RP-side counterpart: this grant has no
authorization request for `client` to drive at all — a client_credentials
caller is, structurally, closer to `cmd/conformance-as`'s own role in
this exchange than to `client`'s.

## Access-token format coverage

`cmd/conformance-as` supports both of `server`'s access-token formats
via a runtime `-access-token-format=jwt|opaque` flag (see
`server/docker-compose.yml`'s `ACCESS_TOKEN_FORMAT` env var for a
manual one-off run against either), but `scripts/run-all.sh` only runs
the live suite under the default, `jwt`. An earlier version of this
script looped the AS suites over both formats on every run; that was
dropped once `resource.AccessTokenResolver`'s contract was tightened
(see PR #62) so DPoP binding, ordinary expiry, and revocation are
enforced exactly once, uniformly, in `resource.Verify()` itself rather
than by each format's own implementation — the two formats can no
longer disagree on those checks by construction, so duplicating the
full live suite per format stopped pulling its weight against the
doubled runtime. `OpaqueAccessTokens`' own format-specific behavior
(issuance, storage lookup) is still covered continuously by
`server`/`resource`'s own unit and integration tests and by
`cmd/conformance-as`'s smoke test (`smoke_test.go`), which runs its
authorization-code-flow case under both formats on every `go test`.
