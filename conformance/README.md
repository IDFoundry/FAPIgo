# Conformance

[![FAPI2 Conformance](https://github.com/IDFoundry/FAPIgo/actions/workflows/conformance.yml/badge.svg)](https://github.com/IDFoundry/FAPIgo/actions/workflows/conformance.yml)

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
- `scripts/run-all.sh` — runs all six suites this repo has driver
  support for (AS baseline, AS message-signing, AS ciba-mtls, RP
  baseline, RP message-signing, RP ciba-mtls) against a locally running
  suite and prints one combined summary. See the script's own header
  comment for prerequisites and env vars.
- `resource/` — resource-server verification test vectors (DPoP proof
  validation, access-token binding checks) used outside the OIDF suite.
  The suite doesn't run its own dedicated resource-server conformance
  plan against this role, but the AS test plan's happy-flow module does
  call a real protected-resource endpoint with the token it just
  issued — `cmd/conformance-as` points it at its own `/userinfo`
  endpoint (`resource.go`, backed by the `resource` package), which
  satisfies that AS-plan requirement as a side effect of already
  needing to exist for real, not as resource-role certification in its
  own right.

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
expired, missing claims). The suite's own per-module grade for most of
these is still FAIL — full credit appears to need more of the flow than
this driver currently completes — so this is still not part of
`scripts/run-all.sh`. See
[`client/scripts/README.md`](client/scripts/README.md#ciba--profileciba)
for the full breakdown either way.

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
