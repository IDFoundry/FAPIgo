# FAPIgo

[![Release](https://img.shields.io/github/v/release/IDFoundry/FAPIgo)](https://github.com/IDFoundry/FAPIgo/releases/latest)
[![CI](https://github.com/IDFoundry/FAPIgo/actions/workflows/ci.yml/badge.svg)](https://github.com/IDFoundry/FAPIgo/actions/workflows/ci.yml)
[![FAPI2 Conformance](https://github.com/IDFoundry/FAPIgo/actions/workflows/conformance.yml/badge.svg)](https://github.com/IDFoundry/FAPIgo/actions/workflows/conformance.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

[![Quality Gate](https://sonarcloud.io/api/project_badges/quality_gate?project=IDFoundry_FAPIgo)](https://sonarcloud.io/summary/new_code?id=IDFoundry_FAPIgo)
[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=IDFoundry_FAPIgo&metric=coverage)](https://sonarcloud.io/summary/new_code?id=IDFoundry_FAPIgo)
[![Lines of Code](https://sonarcloud.io/api/project_badges/measure?project=IDFoundry_FAPIgo&metric=ncloc)](https://sonarcloud.io/summary/new_code?id=IDFoundry_FAPIgo)
[![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=IDFoundry_FAPIgo&metric=security_rating)](https://sonarcloud.io/summary/new_code?id=IDFoundry_FAPIgo)
[![Maintainability Rating](https://sonarcloud.io/api/project_badges/measure?project=IDFoundry_FAPIgo&metric=sqale_rating)](https://sonarcloud.io/summary/new_code?id=IDFoundry_FAPIgo)
[![Reliability Rating](https://sonarcloud.io/api/project_badges/measure?project=IDFoundry_FAPIgo&metric=reliability_rating)](https://sonarcloud.io/summary/new_code?id=IDFoundry_FAPIgo)
[![Vulnerabilities](https://sonarcloud.io/api/project_badges/measure?project=IDFoundry_FAPIgo&metric=vulnerabilities)](https://sonarcloud.io/summary/new_code?id=IDFoundry_FAPIgo)
[![Code Smells](https://sonarcloud.io/api/project_badges/measure?project=IDFoundry_FAPIgo&metric=code_smells)](https://sonarcloud.io/summary/new_code?id=IDFoundry_FAPIgo)
[![Technical Debt](https://sonarcloud.io/api/project_badges/measure?project=IDFoundry_FAPIgo&metric=sqale_index)](https://sonarcloud.io/summary/new_code?id=IDFoundry_FAPIgo)

Hardened, separately conformant FAPI 2.0 client, authorization-server and
resource-server engines for Go, built on one rigorously tested protocol
core.

> **⚠ Work in progress.** FAPIgo is under active development. APIs, package structure, and behavior may change without notice. We recommend waiting for the v1.0 release before considering it for production use.

> **Status:** all three roles (`client`, `server`, `resource`), the shared
> internal protocol core, `keys`, `storage` (including a reusable storage
> contract test suite for downstream backends), `extension`, the hardened
> `fapihttp` transport, client-side AS discovery (`client.Discover` +
> `keys.NewJWKSIssuerKeySource`) and the `fapitest` real-HTTP interop
> harness are all implemented and covered by tests, including end-to-end
> authorization flows — both hand-configured and fully
> discovery-driven — under the FAPI 2.0 baseline and message-signing
> profiles. Both the `server` (authorization server) and `client`
> (relying party) roles have been run clean against the OpenID
> Foundation conformance suite's FAPI2 baseline and message-signing test
> plans, run under `server`'s default JWT access-token format; the
> opaque alternative is covered by unit/integration tests and
> `cmd/conformance-as`'s own smoke test under both formats, not by a
> continuous live-suite run — see
> [conformance/](conformance/README.md#access-token-format-coverage).
> `resource` has not been run against a dedicated OIDF plan (only
> indirectly, as a stand-in the AS plan's own happy-flow module calls).

```go
import (
    "github.com/idfoundry/fapigo/client"
    "github.com/idfoundry/fapigo/server"
    "github.com/idfoundry/fapigo/resource"
)
```

`client` (relying party), `server` (authorization server) and `resource`
(resource server / token verification) are independent public packages
with distinct constructors, configuration and workflow APIs — there is no
generic API that tries to behave as more than one role. They share a
rigorously tested internal protocol core (JOSE, DPoP, PAR, PKCE, JARM,
request objects, client assertions, canonicalization) without sharing
role-level types or behaviour.

`storage/memstore` and `keys/ephemeral` provide in-memory, non-durable
implementations of every interface `server` needs (client repository,
transaction/grant/replay/access-token stores, key manager, client key
source) — for local development and testing only, never production —
so integrating `server` doesn't require writing real persistence and
key management from scratch just to see it run. `server.RecommendedLimits()`
and `server.RecommendedAlgorithms()` do the same for `Config`'s algorithm
and duration fields, each grounded in a specific FAPI 2.0 Security
Profile Final or RFC 9449 requirement where one exists — see
[GETTING_STARTED.md](GETTING_STARTED.md) for a walkthrough of standing
up an authorization server and resource server end to end.

Access tokens can be issued as self-contained JWTs (RFC 9068 — the
default, `server.JWTAccessTokens`/`resource.JWTAccessTokens`) or as
opaque, storage-backed values (`server.OpaqueAccessTokens`/
`resource.OpaqueAccessTokens`) — FAPI 2.0 doesn't mandate a format, so
this is a deployment's own choice, not something the library imposes.

See [ARCHITECTURE.md](ARCHITECTURE.md) for the full design rationale and
package layout, and [conformance/](conformance/README.md) for how each
role is tested against the OpenID Foundation conformance suite.

## Relevant specifications

- [FAPI 2.0 Security Profile][fapi2]
- [FAPI 2.0 Message Signing][fapi2-sign]
- [RFC 9126 — Pushed Authorization Requests][par]
- [RFC 9449 — Demonstrating Proof of Possession (DPoP)][dpop]
- [RFC 9396 — Rich Authorization Requests][rar]

[fapi2]: https://openid.net/specs/fapi-security-profile-2_0-final.html
[fapi2-sign]: https://openid.net/specs/fapi-2_0-message-signing.html
[par]: https://www.rfc-editor.org/info/rfc9126
[dpop]: https://www.rfc-editor.org/info/rfc9449
[rar]: https://www.rfc-editor.org/info/rfc9396

## License

MIT — see [LICENSE](LICENSE).
