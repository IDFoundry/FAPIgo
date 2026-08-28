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
- `scripts/run-all.sh` — runs all four suites this repo has driver
  support for (AS baseline, AS message-signing, RP baseline, RP
  message-signing) against a locally running suite and prints one
  combined summary. See the script's own header comment for
  prerequisites and env vars.
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
poll mode only) is verified by unit/integration tests, not the live
OIDF suite: `fapi-ciba-id1-test-plan` requires MTLS-bound access
tokens unconditionally, a requirement this module doesn't meet
anywhere (mTLS is out of scope entirely — see
[ARCHITECTURE.md](../ARCHITECTURE.md#conformance-strategy)). A manual,
non-automated setup for this plan exists in
[`server/oidf-config/README.md`](server/oidf-config/README.md#ciba-manual-only--not-part-of-automated-conformance)
for exploratory use, but it isn't expected to pass and isn't part of
`scripts/run-all.sh`.

`client`'s own CIBA support
(`BeginBackchannelAuthentication`/`PollBackchannelAuthentication`) was
genuinely attempted, live, against the RP-side
`fapi-ciba-id1-client-test-plan` (`cmd/conformance-client -profile=ciba`) —
unlike the AS side, its backchannel-authentication step doesn't share
the unconditional MTLS mandate, but its *token* endpoint does, for a
separately confirmed reason. Result: 3 of 22 modules genuinely PASS
(the ones that never reach token exchange); the rest FAIL for that one
uniform, documented reason. See
[`client/scripts/README.md`](client/scripts/README.md#ciba--profileciba)
for the full breakdown; also not part of `scripts/run-all.sh` given
the majority-FAILED result.

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
