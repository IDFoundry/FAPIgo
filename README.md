# FAPIgo

[![CI](https://github.com/IDFoundry/FAPIgo/actions/workflows/ci.yml/badge.svg)](https://github.com/IDFoundry/FAPIgo/actions/workflows/ci.yml)
[![FAPI2 Conformance](https://github.com/IDFoundry/FAPIgo/actions/workflows/conformance.yml/badge.svg)](https://github.com/IDFoundry/FAPIgo/actions/workflows/conformance.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

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
> plans; `resource` has not been run against a dedicated OIDF plan (only
> indirectly, as a stand-in the AS plan's own happy-flow module calls)
> — see [conformance/](conformance/README.md).

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
transaction/grant/replay stores, key manager, client key source) — for
local development and testing only, never production — so integrating
`server` doesn't require writing real persistence and key management
from scratch just to see it run. `server.RecommendedLimits()` and
`server.RecommendedAlgorithms()` do the same for `Config`'s algorithm
and duration fields, each grounded in a specific FAPI 2.0 Security
Profile Final or RFC 9449 requirement where one exists — see
[GETTING_STARTED.md](GETTING_STARTED.md) for a walkthrough of standing
up an authorization server end to end.

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
