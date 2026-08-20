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
  combined summary. The two AS suites each run twice, under
  `cmd/conformance-as -access-token-format=jwt` and `=opaque` (see
  `server/docker-compose.yml`), so both
  `server.AccessTokenIssuer`/`resource.AccessTokenVerifier`
  implementations get exercised, not just the default. See the
  script's own header comment for prerequisites and env vars.
- `resource/` — resource-server verification test vectors (DPoP proof
  validation, access-token binding checks) used outside the OIDF suite.
  The suite doesn't run its own dedicated resource-server conformance
  plan against this role, but the AS test plan's happy-flow module does
  call a real protected-resource endpoint with the token it just
  issued — `cmd/conformance-as` serves a stand-in one
  (`resource.go`, backed by the `resource` package) purely to satisfy
  that AS-plan requirement, not as resource-role certification.
