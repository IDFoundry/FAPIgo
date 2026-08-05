# go-fapi

Hardened, separately conformant FAPI 2.0 client, authorization-server and
resource-server engines for Go, built on one rigorously tested protocol
core.

> **Status:** early scaffolding. The package layout and public API shape
> described below are fixed; implementation is not yet underway.

```go
import (
    "github.com/osanderson/go-fapi/client"
    "github.com/osanderson/go-fapi/server"
    "github.com/osanderson/go-fapi/resource"
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
