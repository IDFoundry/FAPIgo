# FAPIgo

Hardened, separately conformant FAPI 2.0 client, authorization-server and
resource-server engines for Go, built on one rigorously tested protocol
core.

> **⚠ Work in progress.** APIs, package layout and behavior may still
> change without notice. Not yet recommended for production use.

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
