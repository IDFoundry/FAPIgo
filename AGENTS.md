# Agent guidance

This file is for AI coding agents working in this repo. It doesn't
replace [CONTRIBUTING.md](CONTRIBUTING.md) — read that first for the
conformance-first philosophy, commit message format, and pre-PR
checklist. This file adds agent-specific process notes and points at
where deeper, hard-won knowledge already lives.

## Workflow

- Never push directly to `main`, even if asked to just "push" —
  always work on a feature branch, open a PR, and wait for CI to go
  green before merging.
- Only sync a local `main` after the user has confirmed the PR is
  actually merged (e.g. via `gh pr view <n> --json state,mergedAt`) —
  don't assume, and don't merge a PR yourself unless explicitly told
  to.
- This repo uses [release-please](https://github.com/googleapis/release-please):
  every commit message must be a real [Conventional Commits](https://www.conventionalcommits.org/)
  type (`fix:`, `feat:`, `feat!:`/`fix!:` for breaking, or `docs:`/
  `chore:`/`test:`/`refactor:`/`ci:` for anything that shouldn't bump
  the version) — see CONTRIBUTING.md's "Commit messages" section for
  the full rationale. Don't invent non-standard types.
- Merging a PR here triggers an automatic release-please PR bumping
  the version and `CHANGELOG.md` — that PR needs its own merge (by a
  human or on explicit instruction) before the new version is actually
  cut/tagged.

## Where conformance-suite knowledge already lives

Don't re-derive OIDF conformance suite behavior from scratch — most of
it has already been disassembled and documented, with citations:

- [`conformance/server/oidf-config/README.md`](conformance/server/oidf-config/README.md) —
  AS-side (`cmd/conformance-as`) conformance findings: per-profile
  config shapes (baseline, mTLS, client-auth-mTLS, message-signing,
  CIBA poll/ping, client-credentials), real suite-side bugs found and
  worked around, and the exact plan-JSON shape each profile needs.
- [`conformance/client/scripts/README.md`](conformance/client/scripts/README.md) —
  RP-side (`cmd/conformance-client`) conformance findings, including
  the CIBA driver's own gotchas and the `-evidence-dir` RP-certification
  evidence format.
- Both READMEs distinguish local dev-mode suite behavior (Docker
  Compose, `docker-compose.yml`) from the hosted `certification.openid.net`
  suite — several dev-mode-only mechanisms (the plan JSON's `browser`/
  `override` blocks, `automated_ciba_approval_url`) have **no
  equivalent on the hosted UI**, which matters if you're helping set up
  or debug a real hosted certification run, not just a local one.

## CIBA on a hosted certification run

`cmd/conformance-as` has a `-ciba-approval-ui-token=<token>` flag (off
by default) that serves a token-gated manual approve/deny page at
`GET`/`POST /ciba-approve` — see `cmd/conformance-as/backchannel.go`
and `backchannel_ui.go`'s own doc comments. It exists because the
hosted certification suite has no equivalent of the local dev-mode
`automated_ciba_approval_url` mechanism: without something calling
`POST /backchannel-approve`, any CIBA module needing a real completed
flow will always expire and fail once its `auth_req_id`'s lifetime runs
out. If you're setting up a fresh hosted CIBA deployment, enable this
flag and use the resulting page instead of hand-constructing
`curl -X POST` calls against a value copied out of a live suite log.

## Client alias naming convention

When registering conformance-testing clients (locally or for a hosted
run), this session settled on `fapigo-{family}-{axis1}-{axis2}`,
mirroring the OIDF certification matrix's own column names:

- `fapigo-sp-{auth}-{sender-constrain}` — FAPI2SP authorization_code
  profiles (`sp` = Security Profile), e.g. `fapigo-sp-pkjwt-dpop`,
  `fapigo-sp-mtls-mtls`.
- `fapigo-sp-cc-{auth}-{sender-constrain}` — FAPI2SP Client Credentials
  Grant variants (`cc` = client credentials), e.g.
  `fapigo-sp-cc-pkjwt-dpop`.
- `fapigo-ciba-{poll|ping}-{auth}` — FAPI-CIBA profiles. CIBA's own
  sender-constrain axis is always MTLS (the suite's own
  `AbstractFAPICIBAID1.setupPrivateKeyJwt` hardcodes this regardless of
  `client_auth_type` — see the AS-side README's CIBA section), so
  delivery mode (poll/ping) takes the slot sender-constrain would
  otherwise occupy.
- `{auth}` is `pkjwt` (`private_key_jwt`) or `mtls`
  (`self_signed_tls_client_auth`); `{sender-constrain}` is `dpop` or
  `mtls`.

Keeping new profiles consistent with this pattern matters more than
any individual name choice — someone reading a list of registered
clients should be able to infer the exact matrix cell each one covers
without cross-referencing anything else.
