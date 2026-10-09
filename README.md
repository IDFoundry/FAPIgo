# FAPIgo

[![Release](https://img.shields.io/github/v/release/IDFoundry/FAPIgo)](https://github.com/IDFoundry/FAPIgo/releases/latest)
[![CI](https://github.com/IDFoundry/FAPIgo/actions/workflows/ci.yml/badge.svg)](https://github.com/IDFoundry/FAPIgo/actions/workflows/ci.yml)
[![FAPI Conformance](https://github.com/IDFoundry/FAPIgo/actions/workflows/conformance.yml/badge.svg)](https://github.com/IDFoundry/FAPIgo/actions/workflows/conformance.yml)
[![codecov](https://codecov.io/gh/IDFoundry/FAPIgo/graph/badge.svg)](https://codecov.io/gh/IDFoundry/FAPIgo)
[![Go Reference](https://pkg.go.dev/badge/github.com/idfoundry/fapigo.svg)](https://pkg.go.dev/github.com/idfoundry/fapigo)
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

**Standards-first FAPI 2.0 for Go.** OpenID Certified™, hardened, separately
conformant client, authorization-server and resource-server engines, built on
one rigorously tested protocol core — so you build against the security
profile instead of reverse-engineering it yourself.

FAPI 2.0 (Financial-grade API) is the OpenID Foundation's security profile
for OAuth 2.0 and OpenID Connect, used by open banking, open finance and
other high-assurance API ecosystems to mandate protections — sender-
constrained tokens, request integrity, strong client authentication — that
plain OAuth leaves optional. Getting PAR, DPoP, JAR/JARM, mTLS or
private_key_jwt, and RAR/CIBA all correct by hand is a significant amount of
security-critical work; FAPIgo does that work once, as tested and
OIDF-certified Go packages.

This isn't a stricter default you can opt out of: legacy patterns FAPI 2.0
and RFC 9700 identify as insecure — the implicit/hybrid response types,
`client_secret_basic`/`client_secret_post` authentication — aren't
configuration options that happen to be off, they simply aren't
implemented. `server` only ever accepts `response_type=code`, and
`ClientAuthMethod` is a closed enum of `private_key_jwt`, the mTLS
variants and OAuth 2.0 attestation-based client authentication.

- FAPI 2.0 Security Profile Final + Message Signing Final
- PAR (RFC 9126) · DPoP (RFC 9449) · mTLS client auth & cert-bound tokens (RFC 8705), with CRL revocation checking
- private_key_jwt client authentication
- OAuth 2.0 Attestation-Based Client Authentication, including HAIP 1.0 x5c attester certificate chains, optionally binding each trust anchor to the attesters it may vouch for
- JAR / JARM · RAR (RFC 9396) · CIBA (poll & ping delivery)
- Refresh tokens (not rotated, per FAPI 2.0), whole-grant revocation, and refresh-token revocation (RFC 7009)
- OpenID Connect: the `claims` parameter with per-claim consent, `acr_values`, enforced `max_age` and `prompt` (`none` answered without UI, `login` enforced), signed and encrypted ID tokens and UserInfo
- Native apps (RFC 8252): private-use URI scheme and any-port loopback redirect URIs, for clients registered as native
- Grants you serve yourself at the token endpoint (OpenID4VCI's `pre-authorized_code`, say), with the server's own attestation-based client authentication and DPoP/mTLS checks
- OpenID Federation 1.0 (trust chains, automatic client registration, trust marks)
- OpenID Certified™ for OP, RP and FAPI-CIBA OP conformance profiles — see below

[![OpenID Certified](assets/openid-certified-badge.png)](https://openid.net/certification/)

> **OpenID Certified™** by Oscar Sanderson to the FAPI 2.0 OP, FAPI 2.0
> RP (both Security Profile Final + Message Signing Final), FAPI 2.0 OP
> Client Credentials Grant Type, and FAPI-CIBA OP conformance profiles
> of the OpenID Connect™ protocol, as tested for FAPIgo 0.25.0 — not
> merely a self-run pass against the live suite, but a result submitted
> to and published by the OpenID Foundation. This is a statement of
> tested conformance, not an OIDF endorsement of FAPIgo generally. See
> [conformance/README.md#oidf-certification](conformance/README.md#oidf-certification)
> for the full list of certified profiles and links to each official
> listing.

> **⚠ Work in progress.** FAPIgo is under active development. APIs, package structure, and behavior may change without notice. We recommend waiting for the v1.0 release before considering it for production use.

Requires Go 1.26.9+ (per `go.mod`'s `go` directive).

```
go get github.com/idfoundry/fapigo
```

```go
import (
    "github.com/idfoundry/fapigo/client"
    "github.com/idfoundry/fapigo/server"
    "github.com/idfoundry/fapigo/resource"
)
```

*(Go module paths are lowercased; the GitHub repository itself is
[IDFoundry/FAPIgo](https://github.com/IDFoundry/FAPIgo).)*

`client` (relying party), `server` (authorization server) and `resource`
(resource server / token verification) are independent public packages
with distinct constructors, configuration and workflow APIs — there is no
generic API that tries to behave as more than one role. They share a
rigorously tested internal protocol core (JOSE, DPoP, PAR, PKCE, JARM,
request objects, client assertions, canonicalization) without sharing
role-level types or behaviour. `serverresource` builds a `resource`
verifier matching a `server` in the same process, for an authorization
server that hosts its own protected endpoints.

A few helpers cover what every deployment otherwise writes by hand, and
gets wrong in the same ways:

- `server/interactioncookie` carries a pending authorization from
  `/authorize` to the consent form's submission in one encrypted cookie,
  tied to the form that was shown.
- `client/sessioncookie` binds a client's authorization to the browser
  that began it (login CSRF, [RFC 9700 §4.7](https://www.rfc-editor.org/rfc/rfc9700#section-4.7)), with your own value
  for it alongside.
- `client.TokenSetSealer` keeps tokens at rest, encrypted and bound to
  their owner, for a client that refreshes after a restart or on
  another instance.
- The `*FromHTTP` constructors (`server.PushAuthorizationRequestFromHTTP`,
  `resource.VerifyRequestFromHTTP` and others) read every header and
  certificate a request type needs from an `*http.Request` at once.

See [GETTING_STARTED.md](GETTING_STARTED.md) for a full walkthrough of
standing up an authorization server, resource server and client end to
end, including a runnable configuration you can start from.

For one mechanism at a time, [docs/guides](docs/guides/README.md) has
short guides to [DPoP](docs/guides/dpop.md), [mutual
TLS](docs/guides/mtls.md), [PAR](docs/guides/par.md), [Message
Signing](docs/guides/message-signing.md), [CIBA](docs/guides/ciba.md),
[Rich Authorization Requests](docs/guides/rar.md), [OpenID
Federation](docs/guides/openid-federation.md), and [building a wallet or
other native app client](docs/guides/native-wallet.md).

Six runnable demos show these end to end, each with a guided tour and an
attack lab; [examples/README.md](examples/README.md) maps every capability
to the demo that shows it.

[examples/federated-union](examples/federated-union/README.md) is a
runnable demo: three fictional countries' identity federations joined
into one OpenID Federation, with cross-border sign-in, automatic
registration, accredited Trust Marks and a console of attack scenes.

[examples/payment-consent](examples/payment-consent/README.md) shows the
FAPI 2.0 Message Signing redirect flow end to end: a web shop takes
payment by bank with PAR, a signed request object, a RAR consent screen,
JARM and a DPoP-bound token, and an attack lab tries to break each of
them, with a protocol trace of every step.

[examples/decoupled-checkout](examples/decoupled-checkout/README.md) is
another: a customer approves, on their phone, a payment or account access
started on another device, with CIBA and Rich Authorization Requests —
the phone shows exactly what's being approved, and the bank's APIs allow
exactly that.

[examples/payroll-run](examples/payroll-run/README.md) is machine to
machine: a payroll provider pays a company's staff through its bank's
API with mutual TLS client authentication, certificate-bound tokens from
the client credentials grant, certificate revocation and a Rich
Authorization Request checked against a standing mandate, with an attack
lab and a certificate rotation panel.

[examples/identity-check](examples/identity-check/README.md) shows the
bank as an OpenID Provider: a fintech verifies a new customer's identity
with the `claims` parameter, per-claim consent, `acr_values` and
`max_age`, and an ID token and UserInfo response signed by the bank and
encrypted to the relying party, with an attack lab.

[examples/linked-accounts](examples/linked-accounts/README.md) shows
long-lived access: a budgeting app links a customer's accounts for 90
days and syncs with a refresh token, while the customer can revoke the
whole grant from the bank's Connected apps page, with a demo clock and
an attack lab.

`storage/memstore` and `keys/ephemeral` provide in-memory, non-durable
implementations of every interface `server` needs (client repository;
transaction, grant, replay, revocation, access-token, CIBA and DPoP-nonce
stores; key manager; client key source), and `client`'s session store —
for local development and testing only, never production —
so integrating `server` doesn't require writing real persistence and
key management from scratch just to see it run. `server.RecommendedLimits()`
and `server.RecommendedAlgorithms()` do the same for `Config`'s algorithm
and duration fields, each grounded in a specific FAPI 2.0 Security
Profile Final or RFC 9449 requirement where one exists.

Access tokens can be issued as self-contained JWTs (RFC 9068 — the
default, `server.JWTAccessTokens`/`resource.JWTAccessTokens`) or as
opaque, storage-backed values (`server.OpaqueAccessTokens`/
`resource.OpaqueAccessTokens`) — FAPI 2.0 doesn't mandate a format, so
this is a deployment's own choice, not something the library imposes.

OpenID Connect identity (an ID token) is likewise optional, not
assumed: `server` issues one alongside the access token exactly when
the granted scope includes `"openid"`, and `client` populates
`TokenSet.IDToken`/`Subject`/`IDTokenClaims` exactly when the token
response actually carried one — leaving `TokenSet.HasIDToken` false is
a normal outcome, not an error. A deployment that only needs access
tokens can drop `"openid"` from a client's `AllowedScopes` entirely and
run this library as plain OAuth 2.0 + FAPI 2.0 — and `Config.OAuthOnly`
(on `server` and `client` alike) makes that a checked configuration
rather than a convention.

See [ARCHITECTURE.md](ARCHITECTURE.md) for the full design rationale and
package layout, and [conformance/](conformance/README.md) for how each
role is tested against the OpenID Foundation conformance suite.

<details>
<summary><strong>Full conformance and capability status</strong> (the detail behind the certification and checklist above)</summary>

> All three roles (`client`, `server`, `resource`), the shared
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
> plans, run under `server`'s default JWT access-token format and again
> under mTLS-bound access tokens (RFC 8705 §3); both roles have also been
> run clean against `tls_client_auth`/`self_signed_tls_client_auth`
> client authentication (RFC 8705 §2) and against CIBA (OpenID Connect
> CIBA Core 1.0, poll and ping delivery, mTLS-bound tokens, the OIDF
> `fapi-ciba-id1` plan) — see [conformance/](conformance/README.md) for
> the full breakdown and pass counts per plan. Rich Authorization
> Requests (RFC 9396) are implemented end-to-end across the PAR-fed
> authorization-code flow, CIBA, and the client_credentials grant (RFC
> 9396 §6), including a per-type narrowing hook so a resource owner can
> grant less than what a client requested on the first two — the OIDF
> suite has no dedicated RAR conformance plan, so this is validated by
> this repo's own unit, integration and end-to-end tests instead — see
> [conformance/](conformance/README.md#rar). The opaque access-token
> alternative is covered by unit/integration tests and
> `cmd/conformance-as`'s own smoke test under both formats, not by a
> continuous live-suite run — see
> [conformance/](conformance/README.md#access-token-format-coverage).
> `resource` has not been run against a dedicated OIDF plan (only
> indirectly, as a stand-in the AS plan's own happy-flow module calls).
> `server` also implements the RFC 6749 §4.4 client_credentials grant
> (opt-in via `Config.ClientCredentialsGrant` and a per-client
> `AllowsClientCredentialsGrant`), run clean against all four FAPI2SP OP
> "Client Credentials Grant" register profiles (MTLS+MTLS, MTLS+DPoP,
> private key+MTLS, private key+DPoP) — see
> [conformance/](conformance/README.md#client-credentials-grant). `client`
> implements the matching relying-party side (`RequestClientCredentialsToken`),
> including a `client_credentials`-only `Config` (no browser flow, no
> CIBA); this has no OIDF RP-side plan to run against (the grant has no
> browser hop at all), so it's covered by unit tests and a real-HTTP
> `fapitest` round trip instead. `server.Config.OAuthOnly` turns the
> server into a pure OAuth 2.0 + FAPI 2.0 AS — "openid" is refused as a
> requested scope everywhere (PAR, CIBA, client_credentials alike), no
> ID token is ever issued, and `Metadata` omits every OIDC-only field
> (`subject_types_supported`, `id_token_signing_alg_values_supported`)
> — covered by unit tests and a real-HTTP `fapitest` round trip, not an
> OIDF plan (the suite has no bare-OAuth2 FAPI2 plan to run against).
>
> The `federation` package adds OpenID Federation 1.0 (Final) support:
> Trust Chain resolution (`Resolver`, §10, enforcing every `constraints`
> claim and a resolver-wide path-length ceiling), self-issuance of an
> entity's own Entity Configuration (`SelfIssuer`), Automatic Client
> Registration for an OP (§12.1, `AutomaticClientRepository` —
> including every RFC 8705 mTLS client authentication method, reading a
> resolved RP's own certificate straight from its `jwks`/`jwks_uri`'s
> own `x5c` member for `self_signed_tls_client_auth`), the
> symmetric capability on the RP side (`client.DiscoverViaFederation` —
> the same `DiscoveredMetadata` `client.Discover` produces, sourced from
> a Trust-Chain-verified `openid_provider` object instead of a live
> `.well-known/openid-configuration` fetch), acting as
> a Trust Anchor or Intermediate (`SubordinateIssuer`, signing the
> Subordinate Statements §8.1's fetch endpoint serves), and Trust Marks
> end to end — verification (§7), issuance (`TrustMarkIssuer`), and live
> status queries (§8.4, `Resolver.CheckTrustMarkStatus`) — plus Trust
> Marked Entities Listing request validation (§8.5), the Resolve
> endpoint (§8.3, `Resolver.ResolveViaEndpoint`/`ResolveIssuer`) — both
> sides: querying a trusted resolver's resolve-as-a-service endpoint instead of
> walking its Trust Chain hop by hop, and signing a response for an
> embedder's own already-resolved result — and the Federation Historical
> Keys endpoint (§8.7, `Resolver.FetchHistoricalKeys`), querying side:
> a peer's retired keys (with their own expiry and, if applicable,
> revocation status), to keep an older Trust Chain verifiable after key
> rotation. **Explicit
> Registration (§12.2) is not implemented**: an
> OP can accept RPs via Automatic Registration, but provisioning a
> distinct `client_id`/`client_secret` through a dedicated federation
> registration request is not supported. See `federation/doc.go` for the
> exact scope of every capability above.

</details>

## Relevant specifications

- [FAPI 2.0 Security Profile][fapi2]
- [FAPI 2.0 Message Signing][fapi2-sign]
- [RFC 9126 — Pushed Authorization Requests][par]
- [RFC 9449 — Demonstrating Proof of Possession (DPoP)][dpop]
- [RFC 8705 — Mutual TLS Client Authentication and Certificate-Bound Access Tokens][mtls]
- [OpenID Connect Client-Initiated Backchannel Authentication (CIBA) Core 1.0][ciba]
- [RFC 9396 — Rich Authorization Requests][rar]
- [RFC 8252 — OAuth 2.0 for Native Apps][native]

[fapi2]: https://openid.net/specs/fapi-security-profile-2_0-final.html
[fapi2-sign]: https://openid.net/specs/fapi-message-signing-2_0-final.html
[par]: https://www.rfc-editor.org/info/rfc9126
[native]: https://www.rfc-editor.org/info/rfc8252
[dpop]: https://www.rfc-editor.org/info/rfc9449
[mtls]: https://www.rfc-editor.org/info/rfc8705
[ciba]: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html
[rar]: https://www.rfc-editor.org/info/rfc9396

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the conformance-first development
philosophy and pre-PR checklist, [SECURITY.md](SECURITY.md) to report a
vulnerability, [CHANGELOG.md](CHANGELOG.md) for release history, and
[UPGRADING.md](UPGRADING.md) for what to change when a release is breaking.

## License

MIT — see [LICENSE](LICENSE).

OpenID®, OpenID Connect™, and OpenID Certified™ are trademarks or
registered trademarks of the OpenID Foundation in the United States and
other countries. Use of these marks here is limited to the certified
conformance statement above, per [Section 3(d) of the OpenID
Certification Terms and
Conditions](https://openid.net/wordpress-content/uploads/2015/03/OpenID-Certification-Terms-and-Conditions.pdf).
