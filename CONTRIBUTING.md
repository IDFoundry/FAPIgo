# Contributing

FAPIgo implements FAPI 2.0 — a conformance-first library, not a
best-effort OAuth/OIDC implementation. Its design decisions trace back
to specific spec requirements (see `server/presets.go` for a direct
example: every value is labeled with exactly which FAPI 2.0 Security
Profile Final or RFC requirement it comes from, or that it doesn't),
and its real correctness bar is the OpenID Foundation conformance
suite, not just this repo's own unit tests.

**Open an issue before writing a PR**, for anything beyond a trivial
fix (a typo, an obviously-wrong comment). This isn't process for its
own sake: a change that looks reasonable in isolation can conflict
with a spec requirement, an existing design rule (see
[ARCHITECTURE.md](ARCHITECTURE.md)), or conformance-suite behavior
that isn't obvious from the code alone — discussing the approach first
avoids a PR, and the work behind it, being reworked or rejected after
the fact.

## What "conformance-first" means here

- Every design rule in [ARCHITECTURE.md](ARCHITECTURE.md) exists for a
  reason — read it before changing package structure, adding a shared
  abstraction across roles, or relaxing a validation. "No implicit
  defaults" and "closed sum types over optional fields" aren't
  stylistic preferences.
- A change to `server`, `client`, `resource`, `storage`, or `keys` that
  touches actual protocol behavior should be verified against the real
  OIDF conformance suite before it's proposed as done — see
  [conformance/README.md](conformance/README.md) and
  [GETTING_STARTED.md](GETTING_STARTED.md). "It passes the Go test
  suite" isn't the same claim as "it's still FAPI 2.0 conformant."

## Before you open a PR

- `gofmt -l .`, `go vet ./...`, `go build ./...`, `go test -race ./...`,
  `golangci-lint run ./...` (config in `.golangci.yml`), and
  `govulncheck ./...` all need to be clean — this is what `ci.yml`
  enforces on every PR. This module has no third-party dependencies, so
  a `govulncheck` finding is almost always a standard-library CVE fixed
  in a newer Go patch release, not something to fix in this repo's own
  code — bump the toolchain instead.
- Include tests for the behavior you're changing, not just the happy
  path — this codebase leans on tests as part of the actual
  specification (see e.g. `storage/contract.go`'s reusable contract
  test suite).

## Reporting a security issue

Don't open a public issue or PR for a vulnerability — see
[SECURITY.md](SECURITY.md) for private disclosure.
