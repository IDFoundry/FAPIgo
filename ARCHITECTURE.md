# Architecture

FAPIgo provides hardened, separately conformant FAPI client,
authorization-server and resource-server engines built on one rigorously
tested protocol core.

FAPI 2.0 defines requirements across clients, authorization servers and
resource servers, and PAR and DPoP each impose role-specific behaviour on
top of that ([FAPI 2.0 Security Profile][fapi2], [RFC 9126][par],
[RFC 9449][dpop]). The client and server roles in particular have
different trust boundaries, state machines and failure modes, so this
module does not expose one generic API that tries to behave as both.

FAPI is defined for high-value scenarios alongside an explicit attacker
model ([FAPI 2.0 Attacker Model][attacker]), and RFC 9700 captures
broader OAuth 2.0 security best current practice ([RFC 9700][bcp]). The
guiding rule for every public API in this module, not just the protocol
message formats, is:

> **Expose business decisions, not protocol mechanisms.**

A caller decides who authenticated, what access was approved and which
durable infrastructure to use. It must never be able to weaken request
validation, bypass replay prevention, modify a signed output, or
construct a security-sensitive protocol artefact by hand. See
"Hardening rules for every role's public API" below.

## The one rule everything else follows

> **Share protocol implementation, not role-level APIs.**

Concretely:

- `client`, `server` and `resource` are separate public packages with
  separate constructors (`client.New`, `server.New`,
  `resource.NewVerifier`), not one `fapi.New(role, ...)` behind a role
  enum. A role enum tends to produce one large config type with fields
  that only make sense in some modes, and makes it easy to accidentally
  wire up the wrong role.
- They may all depend on the same `internal/` protocol core (JOSE parsing,
  JWK validation, DPoP thumbprints, canonicalization, ...), but `client`
  must never import `server` or vice versa. Both public packages must
  stay independently usable.
- Where client and server both touch the same wire format, the operation
  is asymmetric: signing lives on one side, verification on the other,
  as two distinct types even when they share JOSE encoding helpers (e.g.
  `internal/jarm`: server signs, client verifies; `internal/requestobject`:
  client signs, server verifies).

## Package layout

```text
fapigo/                    // package fapi: shared value types only
├── client/                // RP public API
├── server/                // AS public API
├── resource/              // RS verification API
├── extension/             // shared custom-parameter & RAR definitions
├── storage/                // role-specific storage contracts, shared replay primitive,
│                           // StoreAssurance capability checks + reusable contract test suite
│   └── memstore/           // in-memory reference implementation (dev/test only, never production)
├── keys/                  // operation-based signing/verification contracts (Sign, never Signer)
│   └── ephemeral/          // in-memory reference KeyManager/ClientKeySource (dev/test only, never production)
├── fapihttp/               // hardened HTTP transport used by all three roles
├── fapitest/               // in-process interop harness (test-only)
├── internal/
│   ├── oauth/              // OAuth 2.0 protocol core
│   ├── oidc/                // OIDC protocol core
│   ├── jose/                 // JWT/JWS/JWK parsing & algorithm policy
│   ├── dpop/                 // DPoP proof create (client) / verify (server, resource)
│   ├── pkce/                 // PKCE generate (client) / verify (server)
│   ├── par/                  // PAR wire format
│   ├── jarm/                  // JARM sign (server) / verify (client)
│   ├── requestobject/         // request object sign (client) / verify (server)
│   ├── clientassertion/       // client assertion create (client) / verify (server)
│   ├── token/                 // token issue (server) / validate (client, resource)
│   ├── metadata/               // AS/client metadata parsing
│   ├── canonical/               // URL/JSON canonicalization
│   └── validation/               // generic strict-parsing helpers
└── conformance/
    ├── client/                  // OIDF RP/client test plan config + scripts
    ├── server/                  // OIDF AS test plan config + scripts
    └── resource/                 // RS verification test vectors (not covered by OIDF)
```

## Design rules

### 1. Separate public constructors per role

```go
rp, err := client.New(clientConfig, clientDeps)
as, err := server.New(serverConfig, serverDeps)
rs, err := resource.NewVerifier(resourceConfig, resourceDeps)
```

Not `fapi.New(RoleClient, ...)`.

### 2. Shared value types only where semantics match

Identifiers and enums with one wire-level meaning regardless of role
(`ClientID`, `Scope`, `Issuer`, `SignatureAlgorithm`, `SenderConstraint`)
live in the root `fapi` package. Anything whose meaning depends on
trust state does not — `client.AuthorizationRequest` (an instruction to
construct a request) and `server.ValidatedAuthorizationRequest`
(something already checked) are deliberately different types, so code
can never accidentally treat untrusted input as validated protocol
state.

Two more value types belong here because every role needs them
identically:

- **`Secret`** — wraps any token, code or credential value that could
  end up in a log line by accident. `String()`, `GoString()` and
  `MarshalText()` all redact; `Reveal()` is the only way to get the raw
  value out. `client.TokenSet`, `server.TokenResult` and any resource
  claim that carries a raw token value all use it.
- **`URL`** (constructed via `ParseIssuerURL` / `ParseEndpointURL`, not a
  bare `string`) — enforces absolute, HTTPS (except an explicitly
  enabled loopback development mode), no fragment, no embedded
  credentials, normalized host. Registered redirect URIs are compared
  under OAuth registration semantics, never generic URL equivalence or
  automatic normalization — see `RegisteredRedirectURI` in `client` and
  `server`.

`SignatureAlgorithm` is a closed enum (`ES256`, `PS256`, ...), never a
bare string accepted from a caller or read directly out of a JWT header
before the engine has decided which algorithms are even permitted for
that operation.

### 3. Client: workflow methods, not primitives

`BeginAuthorization` → `AuthorizationSession` (opaque, carries the
authorization URL and a session handle) → `HandleAuthorizationResponse`
→ `ExchangeCode`, or the combined `CompleteAuthorization` so a caller
cannot skip callback validation before exchanging a code. The
intermediate `ValidatedAuthorizationResponse` is opaque and can only be
constructed by `HandleAuthorizationResponse`.

`BeginAuthorization` internally: generates `state`/`nonce`/PKCE, builds
and signs the request object when required, authenticates to and calls
the PAR endpoint ([RFC 9126][par]), receives `request_uri`, builds the
browser URL, and persists correlation state.

`HandleAuthorizationResponse` internally validates: correlation state,
issuer, JARM signature and claims, audience, expiry, response mode,
authorization-code presence, error-response integrity, and replay.

The response is a closed sum type, not one struct with optional fields —
a caller cannot assume every callback carries a code, and cannot forget
to branch on an error case that was silently left zero-valued.

### 4. Client session storage is atomic-consume, not CRUD

`SessionStore.Create` / `SessionStore.Consume` — no `GetSession` /
`DeleteSession`. `Consume` atomically validates and retires `state`,
nonce, PKCE verifier, expected issuer, expected redirect URI, expected
response mode, DPoP key reference and request-object identifier in one
step, to prevent callback replay and race conditions.

### 5. Keys are handles and operations, never raw private keys

`KeyManager.Sign` / `KeyManager.PublicKey`, keyed by purpose
(`ClientAuthentication`, `RequestObjectSigning`, `DPoPProofSigning`). A
session refers to a DPoP key by an opaque `DPoPKeyHandle`, never a
`crypto.PrivateKey` — DPoP's value depends on the private key never
leaving its holder ([RFC 9449][dpop]).

`keys.KeyManager` never hands back a `crypto.Signer`, only a `Sign`
operation and a public JWK — the same model `server` uses to select and
use its own signing keys (`SelectSigningKey` / `Sign` / `PublicJWKS`),
so both a client's and a server's key material can be backed by an HSM
or a remote signing service without the module ever holding private key
material in process. `client.PublicJWKS` is this same publication
surface on the RP side — its `ClientAuthentication` key always, its
`RequestObjectSigning` key under message-signing, and its
`IDTokenDecryption`/`UserInfoDecryption` encryption key when configured,
never its `DPoPProofSigning` key (RFC 9449 embeds that one directly in
each proof, not via a discoverable JWKS). Resolving a *client's*
verification keys (for request-object and client-assertion signatures)
is a separate concern from `KeyManager` — it belongs in `server`'s
client-lookup path, prefers administratively pre-resolved/registered
keys over live JWKS fetches in the request-handling path, and where it
does fetch JWKS applies the same SSRF, size-limit, content-type,
bounded-redirect and stale-key rules as any other outbound fetch (see
rule 6).

`keys.Decrypter` (`UnwrapContentEncryptionKey` / `EncryptionPublicKey`)
is the same rule applied to recovering an encrypted ID token's or
UserInfo response's content-encryption key: never a raw private key,
only an operation and a public JWK. `keys.ECDHAgreer` / `KeyDecrypter`
go one step further, splitting that operation into the one private-key
primitive a real HSM/KMS actually exposes (raw ECDH agreement, or an
RSA-OAEP-256 decrypt) so an embedder implements only that primitive,
never the JOSE Concat-KDF/AES-unwrap machinery this module already
owns. `keys.NewKeyManagerFromSigners` and `keys.NewDecrypter` /
`NewSingleKeyDecrypter` are this package's own on-ramps for either rule
— the first adapts any `crypto.Signer` (what most HSM/KMS Go wrappers
already implement) into a `KeyManager`; the others assemble a
`Decrypter` from an `ECDHAgreer`/`KeyDecrypter` backend — so a
production HSM/KMS integration often needs zero custom glue code,
not just an interface it's free to satisfy. See `keys/doc.go`.

Rotation is the seam these interfaces leave open on purpose — this
module never prescribes a key's lifecycle — but two places needed
explicit support, not just permission: `keys.RotatingKeyManager` is
`KeyManager`'s optional extension for publishing more than one
currently-valid key per purpose (an outgoing key alongside an incoming
one) during a rotation's overlap window, which `server.PublicJWKS` uses
automatically when a configured `KeyManager` implements it; and
`Decrypter`'s `UnwrapRequest` carries the JWE's own "kid" through to
`ECDHAgreer`/`KeyDecrypter` so a backend holding more than one
registered decryption key can tell which one a given ciphertext was
actually wrapped to, instead of only ever being able to guess "the
current one."

Publishing a JWK Set is where this module makes one deliberate,
narrow exception to "no shared role-level types" (rule 1, and the
package-layout note above): `client.PublicJWKS`/`server.PublicJWKS`
are both thin callers over `keys.PublicJWKS`, and `client.PublicKeySet`/
`server.PublicKeySet` (and their `PublicJWK`) are type aliases of
`keys.PublicKeySet`/`keys.PublicJWK`, not each role's own redefinition.
A JWK Set's wire shape (RFC 7517) genuinely doesn't differ by who's
publishing it, unlike a session handle or a verification request — so
sharing the type here removes real duplication (`keys.PublicJWKS`
resolves every `keys.SigningKeyUse`/`keys.EncryptionKeyUse` it's given,
honoring `RotatingKeyManager`, deduplicated by kid — logic `client` and
`server` had each independently written once already) without
reintroducing a generic cross-role API: the caller still decides which
purposes belong in the set, so all the role-specific business logic
(DPoP's key excluded, `RequestObjectSigning` only under
message-signing, and so on) stays exactly where it was. The same
function is what lets an integrator publish a real JWKS from key
material and a declared algorithm alone, with no `client.Client` or
`server.Server` constructed at all — the seam a from-scratch onboarding
flow needs and neither role's own `PublicJWKS` method can offer by
itself, since both require a fully validated `Config`/`Dependencies`
first.

### 6. HTTP is a narrow interface, hardened internally

Callers supply a `Do(*http.Request) (*http.Response, error)`;
`fapihttp` wraps it with strict TLS verification, response-size limits,
bounded/no redirects, endpoint origin validation, timeouts, body-read
deadlines, SSRF restrictions on discovery/JWKS fetches, and
content-type checks. The public API never asks a caller to hand-build
a PAR body or similar wire-level payload.

### 7. Server: a state machine over client-generated artefacts

`PushAuthorizationRequest` → `BeginAuthorization` → `CompleteAuthorization`
→ `ExchangeAuthorizationCode` → `RefreshAccessToken`, plus `Metadata` and
`PublicJWKS`. The server only ever verifies; it must not expose
`client`'s request-building functionality, and it must not expose a
generic `HandleRequest(map[string]any)` or bare `ValidateJWT(token
string)` — which claims, algorithms, audiences, replay checks and key
sources apply is determined by the protocol context, not left for the
caller to assemble correctly.

**Raw request boundary.** `PushAuthorizationRequest` and
`AuthorizationCodeExchangeRequest` carry an `HTTP FormRequest` — an
ordered list of `FormParameter{Name, Value}` plus method, URL, content
type, body size, client certificate and DPoP proof — not a pre-parsed
`url.Values` or `map[string]string`. A map can silently collapse
duplicate parameters before the engine ever sees them; `server` needs
the lossless form to detect duplicate/conflicting values, malformed
names, parameter-count abuse and oversized values itself. `fapihttp`
(or an equivalent adapter) is responsible for building a `FormRequest`
faithfully from `*http.Request`.

**Opaque identifiers.** `PushAuthorizationResult.RequestURI` and the
`InteractionHandle` handed to the embedding application's login UI have
no public constructor — only `server` can produce one. The interaction
handle is high-entropy, short-lived, bound to one authorization
transaction, single-use, and deliberately unsuitable as an authorization
code; the PAR identifier or any storage primary key must never reach the
UI.

**Closed sum types for results**, so a caller can't assume a shape that
isn't there — e.g. an unvalidated `redirect_uri` must produce a
`LocalErrorResponse`/`AuthorizationLocalError`, never something that
looks like a normal redirect:

- `AuthorizationAction` — `InteractionRequired` | `RedirectResponse` |
  `LocalErrorResponse`, returned from `BeginAuthorization`.
- `AuthorizationResult` — `AuthorizationRedirect` | `AuthorizationLocalError`,
  returned from `CompleteAuthorization`. Only the engine assembles the
  final redirect destination — the embedding app cannot replace `state`,
  edit a JARM response, change the redirect URI, or leak a code into logs.
- `InteractionResult` — built only via constructor functions
  (`Authorize(subject, authContext, grant)`, `Deny(reason)`,
  `AuthenticationFailed(reason)`) passed to `CompleteAuthorization`, so
  invalid combinations of subject/grant/denial can't be constructed.

Untrusted hints stay untrusted: `AuthenticationHints.LoginHint` is a
plain string-wrapping type, never a `SubjectID` — only a
`SubjectProvider` or the application's own authentication result can
produce a verified `SubjectID`.

**Assurance levels.** `Config.Assurance` is `AssuranceDevelopment` or
`AssuranceProduction`. `New` fails construction unless every
security-critical dependency is present and valid — no implicit
in-memory fallback for clocks, randomness, replay storage, signing keys,
client lookup or authorization-code storage. Under
`AssuranceProduction`, `New` additionally rejects non-durable stores,
stores without atomic consumption, software keys where policy requires
HSM-backed keys, insecure issuer URLs, wildcard redirect configuration,
excessive clock skew, a missing audit sink, missing replay protection,
and unsupported/weak algorithms. A separate, explicitly named
`NewDevelopmentServer` constructor exists for local/dev convenience so a
caller can never end up on a weakened profile by omission.

**Policy is a bounded deployment decision, not a bypass.**
`AuthorizationPolicy.Evaluate` receives only already-validated protocol
values (`RegisteredClient`, `AuthenticatedSubject`,
`RequestedAuthorization`, `AuthenticationContext`, validated extensions)
and may decide allowed scopes, claims, authorization details, consent
requirements and token lifetime within configured bounds — it cannot
disable PAR, PKCE, sender constraint, redirect URI validation, client
authentication, replay protection, required signed request objects, or
profile algorithm restrictions.

**Audit is a typed dependency**, not a side channel a caller can leave
disconnected: `Dependencies.Audit` records structured `AuditEvent`s
(id, time, type, outcome, client/subject/transaction references, typed
attributes — never a bare `map[string]any`, so a sensitive value can't
end up in an audit record by accident). Whether audit failure is
fail-closed for issuance events, buffered through a durable outbox, or
tolerated for low-value diagnostics is a `server` configuration
decision, not something left to `AuditSink` implementers to each decide
differently.

**Dynamic client registration ([RFC 7591][dcr] / [RFC 7592][dcrm]), if
added, extends this state machine — it doesn't bypass it.** Not
committed to: FAPI 2.0 Security Profile Final §5.4.2 recommends but
does not require it, as one of two options for client key distribution
— the other, a static `jwks_uri` per client, is already fully
supported, and the OIDF conformance suite's plain FAPI2 Security
Profile Final test plan (unlike its separate, Brazil-Open-Banking-
specific DCR plan) has no DCR module at all. If it is added:

- A registration request is validated against `Config.Algorithms` and
  a fixed FAPI2 grant/response-type set (`authorization_code`
  [+`refresh_token` for `offline_access`], `response_type=code`,
  `private_key_jwt` only — RFC 7591 §2's `token_endpoint_auth_method`/
  `grant_types`/`response_types` are not client-negotiable here) in
  `server`, before `storage` is ever touched.
  `storage.NewRegisteredClient` only checks structural validity today
  (is this a recognized algorithm at all) — it has no visibility into
  server-wide policy, and shouldn't gain any: `storage` sits below
  `server` in rule 14's dependency layering, so a policy check that
  needs `Config.Algorithms` belongs in `server`, the same layer that
  already runs the equivalent check lazily, per request, in
  `PushAuthorizationRequest`.
- `RegisterClient`/`ReadClient`/`UpdateClient`/`DeleteClient` follow
  the same typed-request → typed-result/typed-error shape every other
  method here does — no generic `HandleRequest` for this either.
- Registration access tokens (RFC 7592 §1.1) are a new storage
  primitive, not a repurposed `GrantStore` refresh token: they
  authenticate the management endpoint itself, not a resource, and
  their rotate-on-read/update semantics (RFC 7592 §5, a MAY, never a
  MUST) don't match this codebase's existing single-use (authorization
  code) or reuse-until-expiry (refresh token) lifecycles.
- `keys.ClientKeySource` needs its own write path, independent of
  `storage.ClientRepository`'s. A client's key material (`jwks`/
  `jwks_uri`, RFC 7591 §2) is already modeled as a concern separate
  from its registration metadata (see `keys.ClientKeySource` vs.
  `storage.ClientRepository`); registration must keep writing to both
  without merging them into one interface.

### 8. Resource server verifies in HTTP context, not in isolation

`Verifier.Verify(ctx, VerifyRequest{Method, URL, Authorization, DPoPProof})`
→ `AuthorizationContext{Subject, ClientID, Scopes, Claims}`. Token
verification is inseparable from method/URL/DPoP context, so there is no
bare `VerifyJWT` entry point — and, symmetrically, no bare `VerifyDPoP`
entry point either, since a DPoP proof can't be judged valid without the
HTTP method, target URI, access-token hash, expected nonce and JTI
replay state alongside it. `AuthorizationContext.Claims` uses `Secret`
for any raw token value it carries, and a verification failure is a
typed `Error` (see rule 16), not a bare `error` the caller has to
string-match.

**Access-token format is pluggable, verification is not.**
`server.AccessTokenIssuer` and `resource.AccessTokenResolver` let an
integrator choose a self-contained JWT (RFC 9068 — `JWTAccessTokens`,
the default) or an opaque, storage-backed token (`OpaqueAccessTokens`)
— FAPI 2.0 doesn't mandate a format, so this isn't the library's own
opinion to impose. But `AccessTokenResolver` only resolves a token's
claims and its own claimed DPoP-binding thumbprint — it cannot check
sender-constraint binding, ordinary expiry, or revocation, and
`ResolveAccessTokenRequest` carries no expected thumbprint for it to
compare against even if it tried. `Verify()` enforces all three
itself, once, uniformly, regardless of which format is wired in, so
the two formats can't disagree on FAPI2/RFC 9449-mandated behavior by
construction — an earlier design let each implementation check binding
and expiry itself, which meant CI had to run the full live conformance
suite once per format to catch divergence; the current shape makes
that unnecessary (see `conformance/README.md`'s "Access-token format
coverage"). A returned error is a typed `*Error` per rule 16 either
way, so `Verify()` propagates the right exposure without the resolver
needing to anticipate how it'll be used.

### 9. Internal protocol core is organized around asymmetric operations

See the `internal/` table above — `sign.go`/`verify.go` or
`create.go`/`verify.go` pairs per concern, each side used by exactly the
role(s) that need it, sharing JOSE encoding but not signing/verification
policy.

### 10–11. Extension and RAR parameters are defined once, used by both sides

A `extension.Definition[T]` (or, for Rich Authorization Requests
[RFC 9396][rar], the RAR-specific variant living alongside it in the
same package) captures wire name, cardinality, encoding, allowed source,
max size, sensitivity, validator, whether it's integrity-protected,
whether it may appear in request objects, and whether it may be returned
in token claims — once. RAR definitions additionally bound the number of
detail objects, bytes per object, total bytes, JSON depth, and how
duplicate/unknown JSON members are handled.

Client sets a value against the definition with `req.Extensions.Set(...)`;
server registers the same definition (`server.WithAuthorizationExtension`)
and reads the validated value back out through a typed accessor —
`extension.Get(validated.Extensions, Definition)` — never a generic
`map[string]any`, which would allow name collisions and invalid type
assertions. Any parameter without a registered definition is rejected by
default; there is no production option to silently preserve unknown
fields; a caller who genuinely needs that (a compatibility gateway, a
test server) must opt in explicitly and separately rather than being one
missed check away from it.

### 12. Configuration is per-role, not one shared struct

`client.Config`, `server.Config` and `resource.Config` are separate
types. They may reference the same validated value types (`Issuer`,
algorithm policy types) but are not merged into one struct with
role-conditional fields.

### 13. Storage contracts are per-role, with one shared replay primitive

`client.SessionStore`, `server.TransactionStore`, `server.GrantStore` are
distinct, and none of them expose generic CRUD (`GetSession`,
`GetCode`, `UpdateCode`, `DeleteCode`, ...) — every method is a named
security operation. `GrantStore.RedeemAuthorizationCode` in particular
must atomically verify and consume a code hash, client ID, redirect URI,
PKCE verifier and sender-binding together, in one step. `replay.Store`
stores only a digest and expiry per use (`ReplayUse{Namespace, Digest,
ExpiresAt}`) — never a complete client assertion, DPoP proof or other
sensitive payload — and callers must assign it a namespaced identifier
per role/subsystem (`client:jarm`, `server:request-object`,
`server:dpop`, `resource:dpop`, ...) so different subsystems can never
collide on the same use-once token.

Because a storage backend's atomicity/durability guarantees are
self-asserted, `storage` also defines a `StoreAssurance.Capabilities`
interface (durable, atomic-consume, serializable-redemption,
cross-instance-consistent, encrypted-at-rest) that `server`'s
`AssuranceProduction` mode checks at construction time, and a reusable
contract test suite (e.g. a `storage.TestGrantStoreContract(t,
factory)` helper) that any storage implementation — first-party or
downstream — runs against concurrent redemption, expiry boundaries,
cancellation, transaction rollback and cross-connection consistency,
rather than relying on the capability declaration alone.

### 14. No cross-role dependency cycles

```text
client ─────┐
server ─────┼──▶ internal protocol packages
resource ───┘

extension ──▶ shared value definitions
storage   ──▶ shared storage primitives
keys      ──▶ signing contracts
```

`client` and `server` never import each other.

### 15. fapitest is a real-HTTP interop harness, not a shortcut

`fapitest` wires a `client.Client`, `server.Server` and
`resource.Verifier` together through `httptest.Server` so tests exercise
real wire encoding and HTTP semantics — catching parameter
serialization bugs, duplicate handling, header issues, URI
canonicalization mismatches, content-type handling and redirect
behaviour that in-process shortcuts would hide. It is test-only and must
never be reachable from production code paths.

### 16. Errors carry their own exposure — the caller doesn't decide

`client`, `server` and `resource` all return a typed `Error` (`Code()`,
`PublicDescription()`, `HTTPStatus()`, `Unwrap()`) tagged with an
`Exposure` — `ExposureLocal`, `ExposureRedirect`, `ExposureTokenEndpoint`
for `server`; the equivalent split for `client` and `resource`. The
engine, not the embedding application, decides whether a failure is safe
to put in a redirect query string versus a response body versus neither;
internal diagnostic detail is never copied into a public
`error_description`-style field. This is what makes rule 7's "an
unvalidated `redirect_uri` must produce a local error, never a redirect"
enforceable in the type system rather than by convention.

### Conformance strategy

Certification is tracked separately per role under `conformance/`. The
server runs the OIDF AS test plan; the client runs the applicable
RP/client tests; the resource server is verified against test vectors
maintained in this repo, since OIDF does not cover that role. One role
passing its suite is not evidence the other role conforms, even where
both share internal JOSE code — protocol behaviour and negative-test
expectations differ per role.

CIBA (`server.BeginBackchannelAuthentication`/`CompleteBackchannelAuthentication`/
`ExchangeBackchannelAuthentication`) is deliberately not part of this
automated certification loop. It implements base OIDC CIBA and
FAPI-CIBA's other requirements (a mandatory signed authentication
request with `jti`/`nbf`, poll-mode-only delivery, DPoP- or
mTLS-bound tokens), verified by unit/integration tests instead — but
the OIDF suite's own `fapi-ciba-id1-test-plan` requires MTLS-bound
access tokens unconditionally, even under
`client_auth_type=private_key_jwt` (confirmed directly from the
suite's own `AbstractFAPICIBAID1.setupPrivateKeyJwt`, not inferred):
"FAPI requires the use of MTLS sender constrained access tokens, so we
must use the MTLS version of the token endpoint even when using
private_key_jwt client authentication."

This module now supports mTLS sender-constrained access tokens (RFC
8705 §3, `storage.SenderConstrainMTLS`, `-mtls`) as an alternative to
DPoP — client *authentication* is still private_key_jwt only;
`tls_client_auth`/dynamic client registration remain out of scope (see
`cmd/conformance-as`'s own doc comment). This made the CIBA wall above
worth a genuine live re-attempt rather than a permanent limitation:
against `conformance/server/oidf-config/ciba-mtls.config.json`: **33
PASS, 1 FAIL.** The one remaining FAIL is unfixable by construction —
confirmed by disassembling `ExpectBindingMessageCorrectDisplay.evaluate()`
itself: it unconditionally throws whenever `automated_ciba_approval_url`
is set, no branch or placeholder exists for that case, and its only
passing route needs a human physically watching a real device and
uploading a screenshot as evidence — exactly the scenario
`automated_ciba_approval_url` exists to replace everywhere else, so
this one check and an automated run are mutually exclusive by the
suite's own design. (The 3 modules
requiring an RS256-signed probe — `...-signature-algorithm-is-RS256-fails`
and its two client-assertion counterparts — self-skip unless the
plan's own client is registered with an RSA/PS256 key, since the
suite reuses that same registered key, just forcing its JWS header to
RS256, rather than provisioning a separate one; switching client 1
from ES256 to PS256/RSA — already an allowed algorithm here — turned
all three from SKIPPED to PASSED with zero regressions elsewhere.)
Getting here fixed five real library/harness gaps: `server.Metadata`
was missing
`tls_client_certificate_bound_access_tokens` (RFC 8705 §3.3);
`authenticateClient`'s client-assertion `aud` acceptance was far
narrower than RFC 7523 §3 actually requires (see `server/par.go`'s
`acceptableClientAssertionAudiences`, not mTLS-specific despite being
found here); this plan's own TLS check needed both a narrower cipher
list *and* an RSA (not ECDSA) server certificate — `cmd/conformance-as`'s
conformance cert is now RSA
(`conformance/server/scripts/generate-server-cert.sh`), shared across
every profile in `docker-compose.yml` (the change is TLS-layer only,
no application code touched, treated as low-risk to already-passing
baseline/message-signing but not independently re-confirmed live
end-to-end — that needs the official `run-test-plan.py`/`unblock-implicit-callback.py`
tooling, a real suite checkout, that an ad-hoc REST-API driver can't
substitute for on a browser-driven flow); CIBA's own error vocabulary
had incorrectly borrowed PAR's `invalid_request_object` convention
(CIBA Core 1.0 §13 defines no such code — every request-object
negative test uniformly expects plain `invalid_request`, confirmed by
disassembling the suite's own check); and a CIBA backchannel
authentication request's `iat` claim was never required at all — new
`requestobject.VerifyPolicy.RequireIssuedAt`, mirroring
`RequireNotBefore`/`RequireJTI`'s own pattern, set `true` only for
CIBA (PAR's stays `false`). Full breakdown in
`conformance/server/oidf-config/README.md`'s own CIBA section, which
also covers the DPoP-only config's manual (non-automated) setup.

`client`'s own CIBA support
(`BeginBackchannelAuthentication`/`PollBackchannelAuthentication`) was
genuinely attempted against the OIDF suite's RP-side plan
(`fapi-ciba-id1-client-test-plan`, `cmd/conformance-client -profile=ciba`),
unlike the AS side's plan being ruled out ahead of time — the suite's
own `FAPICIBARPProfileBehavior.requiresMtlsForBackchannelEndpoint()`
returns `false` for `plain_fapi`, so the backchannel authentication
step itself doesn't share the AS-side plan's unconditional MTLS
mandate. A live run confirmed this: 3 of 22 modules genuinely PASS
(`fapi-ciba-id1-client-invalid-missing-authreqid-test`,
`-invalid-missing-expiresin-test`, `-invalid-unknown-user-id-test` —
each one a negative test for the backchannel response itself, which
never reaches token exchange). Every other module FAILs for one
uniform, confirmed reason: `AbstractFAPICIBAClientTest.handleHttp`'s
own routing hardcodes `case "token":` to throw "Token endpoint must be
called over an mTLS secured connection" unconditionally — regardless
of `client_auth_type` variant, unlike `setupPrivateKeyJwt` on the
methods that actually vary per-variant. So the *token* endpoint carries
the AS-side plan's same MTLS wall even though the *backchannel*
endpoint doesn't; once `PollBackchannelAuthentication` reaches token
exchange (every happy-path and most negative-test modules do), it hits
this the same way. This live attempt also surfaced and fixed a real,
separate bug along the way: `client.Discover`/`client.Config` assumed
every client also drives the browser PAR+authorize flow
(`authorization_endpoint`/`pushed_authorization_request_endpoint` were
unconditionally required both in `internal/metadata.ParseAndValidate`
and in `client.validateConfig`), which made a CIBA-only client
(exactly this suite's own CIBA-only mock AS, and a legitimate real
deployment shape) impossible to construct at all. Fixed by making the
pair conditionally required — mirroring
`Endpoints.BackchannelAuthentication`'s own optionality — with
`client.New` now requiring at least one of the two flows to be
configured.

Once `client.Config` gained `storage.SenderConstrainMTLS` support, the
token-endpoint MTLS wall above was worth a genuine re-attempt too
(`cmd/conformance-client -profile=ciba -mtls`, a throwaway self-signed
client certificate in place of a DPoP proof). **Confirmed live: fully
resolved — never hit again.** Every module now reaches real token
exchange and this client's own `ValidateIDToken` correctly rejects
every negative-test perturbation the suite sends (bad `iss`/`aud`/
signature/`alg`, expired, missing claims) — genuine, correct client
behavior, the same as against any other AS. The suite's own per-module
grade for most of these is still FAIL; full credit for a negative
ID-token test in this plan appears to need more of the flow than this
driver currently completes, not chased further here.
`conformance/client/scripts/README.md`'s own CIBA section covers
running this driver (with or without `-mtls`) for exploratory use; it
isn't wired into any automated pass/fail gate given the still-majority-FAILED
result.

## What is and isn't shared

**Shared** (via `internal/`, `extension`, `storage`'s replay primitive
and contract test suite, `keys`, `fapihttp`, and the root `fapi`
package's value types): strict parsers, canonicalization rules, JOSE
implementation, algorithm policy primitives, `Secret`, typed `URL`, key
representations, extension/RAR definitions, replay machinery, storage
contract tests, conformance test vectors.

**Not shared**: role-level configuration, workflow APIs, transaction
types, untrusted vs. validated request types, storage interfaces where
semantics differ, generic JWT/DPoP verification methods, audit sink
wiring (each role's `Dependencies` wires its own).

## No public JOSE utility package

None of `client`, `server` or `resource` exposes a general-purpose
JWT/JWS/JWK helper. If one did, callers would eventually reach for it
outside the exact protocol context it was validated for and end up with
a verification path missing an issuer, audience, lifetime or replay
check. Everything JOSE-shaped stays under `internal/jose` and its
asymmetric callers (`internal/dpop`, `internal/jarm`,
`internal/requestobject`, `internal/clientassertion`, `internal/token`);
the public surface is limited to `keys.KeyManager`, registered public
key types, the closed `SignatureAlgorithm` enum, and each role's own
signed protocol outputs.

[fapi2]: https://openid.net/specs/fapi-security-profile-2_0-final.html
[attacker]: https://openid.net/specs/fapi-attacker-model-2_0-final.html
[bcp]: https://www.rfc-editor.org/info/rfc9700
[par]: https://www.rfc-editor.org/info/rfc9126
[dpop]: https://www.rfc-editor.org/info/rfc9449
[rar]: https://www.rfc-editor.org/info/rfc9396
[dcr]: https://www.rfc-editor.org/info/rfc7591
[dcrm]: https://www.rfc-editor.org/info/rfc7592
