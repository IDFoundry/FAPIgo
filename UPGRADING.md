# Upgrading

This page covers every breaking change from v0.30.0 onward: who each one
affects and what to change. Releases with no breaking changes aren't
listed. [CHANGELOG.md](CHANGELOG.md) has the full history.

`New` fails at startup when a new requirement isn't met, and the error
names the missing field, so a skipped step can't slip through to
runtime. If you're several versions behind, work through the sections
from oldest to newest.

Most production-assurance changes only affect `Config.Assurance =
AssuranceProduction`. A development-assurance setup built on `memstore`
and `keys/ephemeral` needs only the steps not marked *production only*.

## v0.42.0

### `TrustedClientCAs` needs `Revocation` (server)

**Affects:** a server whose `Dependencies.ClientCertificateTrust` is
`server.TrustedClientCAs`. `NoClientCertificateChainTrust{}` is
unaffected.

**Why:** a client certificate's validity period alone can't stop a
compromised key before it expires; revocation can, and many mTLS
ecosystems require it. `TrustedClientCAs` had no way to check it, so a
revoked certificate was accepted until it expired. Its new
`Revocation` field is required, so a server built without a revocation
check says so in its own code.

`New` now also rejects a `TrustedClientCAs` with nil `Roots`: crypto/x509
falls back to the system roots for a nil pool, which trusted every
public CA to issue client certificates.

**What to change:** set `Revocation` to one of:

- `server.ClientCertificateCRLs{Lists: ...}`, which checks Certificate
  Revocation Lists your `Lists` function returns. Keep them in memory
  and refresh them before their nextUpdate; a missing or stale list
  rejects the certificate.
- your own `server.ClientCertificateRevocation`, for OCSP or another
  revocation source.
- `server.NoClientCertificateRevocationCheck{}` to keep the old
  behaviour.

If your client certificates are issued by an intermediate CA that you
put in `Roots`, move it to the new `Intermediates` pool and put its root
in `Roots` instead. A CA in `Roots` is a trust anchor, so its own
revocation is never checked. In `Intermediates`, it's part of the
verified chain and is checked against its root's CRL like the leaf.

```go
// Before
ClientCertificateTrust: server.TrustedClientCAs{Roots: pool},

// After
ClientCertificateTrust: server.TrustedClientCAs{
	Roots:      pool,
	Revocation: server.ClientCertificateCRLs{Lists: crlCache.Current},
},
```

### Client certificates are checked at `Dependencies.Clock`'s time (server)

**Affects:** a server using `server.TrustedClientCAs` with a
`Dependencies.Clock` that isn't the wall clock, such as a fixed clock
in tests.

**Why:** a client certificate's validity period was checked against
the wall clock, while everything else (tokens, assertions, attester
certificates) uses `Dependencies.Clock`. A test with a fixed clock now
needs client certificates valid at that clock's time.

### An mTLS-bound token without a certificate is invalid_token (resource)

**Affects:** anything that checks the status or error code
`resource.Verifier` returns for a `Bearer` request arriving without a TLS
client certificate.

**Why:** RFC 8705 §3 has a protected resource reject an access token
whose certificate doesn't match the one presented "using an HTTP 401
status code and the "invalid_token" error code", and no certificate
matches none. Such a request was answered 400 `invalid_request`, before
the token was even looked at. Nothing is missing from the HTTP request
itself: the certificate belongs to the connection. The usual cause is a
client calling the resource's plain host rather than its mTLS host, or
a TLS stack that didn't send its certificate.

**What to change:** expect 401 with `WWW-Authenticate: Bearer
error="invalid_token"` instead. The token is now resolved first, so an
invalid or expired token without a certificate gets the same answer. A
`DPoP` request without a `DPoP` header is unchanged: still 400
`invalid_request`.

### `max_age` is enforced (server)

**Affects:** a server whose clients send `max_age`, and whose
application completes an authorization with an earlier authentication,
from a single sign-on session for example, rather than authenticating
the user again.

**Why:** OIDC Core §3.1.2.1 says that when more than `max_age` seconds
have passed since the user last actively authenticated, "the OP MUST
attempt to actively re-authenticate the End-User". The server used to
ignore `max_age`. It now validates it at the pushed authorization
request (a malformed value is `invalid_request`), surfaces it as
`InteractionRequest.MaxAge`/`HasMaxAge`, and has `CompleteAuthorization`
answer the client with `login_required` when the authentication time
passed to `NewAuthenticationContext` is older than that.

**What to change:** when `InteractionRequest.HasMaxAge` is set and your
user's last authentication is older than `MaxAge`, authenticate them
again before calling `Authorize`. A `max_age` of 0 asks for a fresh
authentication every time. `InteractionRequest.ACRValues` now carries
the client's `acr_values` too, for deciding how strongly to
authenticate. It's a request, not a requirement.

## v0.41.0

### An invalid DPoP proof is invalid_dpop_proof

**Affects:** anything that checks the error codes of `server` (the PAR,
token and backchannel authentication endpoints) or `resource.Verifier`.

**Why:** RFC 9449 gives an invalid DPoP proof its own error code,
`invalid_dpop_proof`: at the authorization server "If the DPoP proof is
invalid, the authorization server issues an error response ... with
invalid_dpop_proof" (§5), and at a protected resource for a proof
"deemed invalid based on the criteria of Section 4.3" (§7.1). A proof
that fails verification, is replayed, or isn't the only DPoP header was
reported as `invalid_request` by `server` and `invalid_token` (or, for
more than one DPoP header, 400 `invalid_request`) by `resource`. They're
now `server.ErrorInvalidDPoPProof` (HTTP 400) and
`resource.ErrorInvalidDPoPProof` (HTTP 401, in a `DPoP` challenge). A
request with no proof at all is still `invalid_request`.

### A resource request without credentials gets 401, not 400

**Affects:** anyone using `resource.Verifier`, and anything that checks
its errors' status codes or error codes.

**Why:** RFC 6750 §3.1 answers a request that "lacks any authentication
information (e.g., the client was unaware that authentication is
necessary or attempted using an unsupported authentication method)"
with 401 and a challenge carrying no error code; RFC 9449 §7.2 says the
same for a resource server accepting both DPoP and Bearer. `Verify`
answered it with 400 `invalid_request`. It now returns a
`*resource.Error` with an empty `Code()` and status 401, for a missing
Authorization header and for a scheme other than DPoP or Bearer.
`WriteJSON`/`WriteError` send it as `WWW-Authenticate: Bearer, DPoP
algs="ES256 PS256 EdDSA"` with no body. A header with a supported
scheme but no token is still 400 `invalid_request`.

Errors for a request that used the DPoP scheme are now sent in a `DPoP`
challenge, with `algs`, rather than a `Bearer` one (RFC 9449 §7.2).

If you pass `Verify`'s errors to `WriteJSON` or `WriteError`, there's
nothing to change. If you build the response yourself, send no error
code when `Code()` is empty, and use the challenge `WriteJSON` would.

### Entity Identifiers with a query or userinfo are rejected

**Affects:** anyone resolving Trust Chains, registering federation
clients automatically, or passing an Entity Identifier to
`federation.ValidEntityID` or `NewSelfIssuer`.

**Why:** OpenID Federation 1.0 §1.2 defines an Entity Identifier as an
https URL with a host and optionally a port and path, which "MUST NOT
contain query parameter or fragment components". Only a non-empty
fragment was rejected: a query, an empty `?` or `#`, and userinfo
(`https://user@host`) were accepted, and the query and userinfo were
carried into the Entity Configuration fetch. All are now rejected.

Entity Identifiers of the form the specification allows are
unaffected.

### Federation metadata member names are case-sensitive

**Affects:** anyone using `federation.AutomaticClientRepository`,
resolving Trust Chains, or calling `client.DiscoverViaFederation`.

**Why:** OpenID Federation metadata policy applies to parameters by
their exact names, but relying-party and `federation_entity` metadata
were decoded with Go's case-insensitive field matching. An RP could
publish `Token_Endpoint_Auth_Method` instead of
`token_endpoint_auth_method`, escape a superior's policy on that
parameter, and still have its value registered. Metadata with a member
name matching a known parameter only in a different case is now
rejected, as are Entity Statement `jwks` keys whose `kid` is spelled
that way.

Metadata using the specifications' exact parameter names is unaffected.
A federation member publishing case-variant names no longer registers
or resolves; it must correct its metadata.

### Entity Statements need a `kid`, unique key IDs, and no `crit`

**Affects:** anyone resolving Trust Chains, and anyone signing Entity
Statements with `internal/federation`-backed issuers (`SelfIssuer`,
`SubordinateIssuer`, `server.Server.EntityConfiguration`).

**Why:** OpenID Federation 1.0 §3.2 requires an Entity Statement's
header `kid` to be a non-empty string naming a key of its issuer, and
§3.1.1 requires every key in its `jwks` to have a unique `kid`. A
statement without a `kid` was verified against every key of the right
algorithm instead. And a statement whose `crit` claim marked an
extension claim critical was accepted, although §3.2 requires rejecting
one the implementation doesn't understand. All three are now rejected.

Issuers already set `kid` from their `KeyID`; `jwks` passed to them must
give every key a unique `kid` (`keys.PublicJWKS` does). A federation
member publishing statements without `kid`, with duplicate or missing
key IDs, or with `crit`, no longer resolves.

### Trust Chain resolution tries every authority hint

**Affects:** anyone resolving Trust Chains for entities that list more
than one authority hint.

**Why:** `Resolver` followed only the first authority hint whose Entity
Configuration verified, so an entity whose first superior led nowhere
trusted failed to resolve even when another hint reached a configured
Trust Anchor (OpenID Federation 1.0 §10.1 builds chains through every
hint). It now tries each hint, backtracking from dead ends, with a
configured Trust Anchor tried first — which also means an entity listing
both an Intermediate and a configured Trust Anchor now resolves through
the Trust Anchor directly (§10.3's shorter chain), so the Intermediate's
metadata policy no longer applies to it. The search is bounded by
`MaxPathLength × MaxAuthorityHints` superiors in total, and each Entity
Statement is fetched at most once per resolution.

Nothing changes for an entity with one authority hint per level.

### A superior's `metadata` for its subordinate now applies

**Affects:** anyone resolving Trust Chains in a federation where an
Intermediate or Trust Anchor puts a `metadata` claim in a Subordinate
Statement.

**Why:** OpenID Federation 1.0 §3.1.1 lets an Immediate Superior set
metadata values for its subordinate, overriding the subordinate's own,
and §6.1.4.2 applies them before any metadata policy. `Resolver`
ignored them, so `ResolvedEntity.Metadata` carried the subordinate's
self-declared values instead of its superior's. Resolved metadata now
reflects them — only for Entity Types the subordinate itself declares,
and only for the statement's own subject. `SubordinateStatementParams`
gains `Metadata`, so a FAPIgo Intermediate or Trust Anchor can set them.

Nothing changes where no superior uses the claim.

### Metadata policies that combine operators the spec disallows now fail

**Affects:** relying parties and OPs resolving Trust Chains
(`federation.Resolver`, automatic registration), when some statement in
the chain uses a metadata policy with a disallowed operator combination.

**Why:** OpenID Federation 1.0 §6.1.3 fixes which policy operators may
appear together for one metadata parameter, and how their values must
relate (e.g. `add`'s values must be among `value`'s). Only one rule was
enforced, so a statement lower in a chain could loosen what a superior
fixed: an Intermediate's `add` extended a Trust Anchor's `value`, and its
`default` restored a parameter the Trust Anchor had removed with
`value: null`. Every rule is now enforced, for each statement's own
policy and for every merge, and a violation is a policy error that fails
the resolution, as §6.1.4 requires.

Nothing changes for a federation whose policies are valid. If a Trust
Chain that used to resolve now fails with a `policy error`, the error
names the entity type, parameter and rule; the federation's policy needs
correcting — don't work around it.


### `fapihttp`'s loopback settings: literal hosts only, split from http

**Affects:** `fapihttp.Config` and `fapihttp.TransportConfig` users that
set `AllowLoopbackHTTP` (development setups fetching from a local
issuer, wallet or test suite).

**Why:** `AllowLoopbackHTTP` lifted the loopback SSRF block for https
as well as http, and for any hostname that *resolved* to a loopback
address, not just literal loopback hosts. A development server with it
set could be made to fetch this machine's own services through any DNS
name an attacker points at 127.0.0.1. And a setup that only needed https
to a local server had to enable a flag named for plain http.

Loopback is now reachable only from:

- **`AllowLoopbackHosts`** (new): https to literal loopback hosts —
  `localhost`, names under `.localhost` (RFC 6761), 127.0.0.0/8 and
  `::1`.
- **`AllowLoopbackHTTP`**: the same hosts, plus plain http.
- **`AllowedLoopbackHosts`** (new): exact hostnames allowed to resolve to
  loopback, e.g. a local test suite with public DNS pointing at
  127.0.0.1.

```go
fapihttp.Config{
	// ...
	AllowLoopbackHosts: true, // https://localhost, https://*.localhost, https://127.0.0.1
	// AllowLoopbackHTTP: true, // only if something is served over plain http
	AllowedLoopbackHosts: []string{"suite.example.test"}, // a name that resolves to 127.0.0.1
}
```

If you only fetch from `localhost`, `*.localhost` or a loopback IP over
https, switch `AllowLoopbackHTTP` to `AllowLoopbackHosts`. If you fetch
from a *name* that resolves to loopback (it now fails with
`ErrSSRFBlocked`), list it in `AllowedLoopbackHosts`. Set the same
fields on `TransportConfig` if you use `NewClient`.

### Custom `SessionStore`s must return `ExpectedIssuer`

**Affects:** relying parties using `client` with their own
`storage.SessionStore` (not `memstore`).

**Why:** completing a callback now checks the consumed session's
`ExpectedIssuer` against the completing client's issuer, so a callback
routed to the wrong client (one client per issuer over a shared store)
can't finish another issuer's flow. Nothing read that field before, so
a store that never persisted it now fails every sign-in with "session
was begun by a client for a different issuer".

Stores that pass `storage.TestSessionStoreContract` already round-trip it.
Otherwise, persist `NewSession.ExpectedIssuer` and return it as
`ConsumedSession.ExpectedIssuer`.

## v0.39.0

### `federation.Limits.MaxAuthorityHints` is required

**Affects:** every `federation.NewResolver` caller, and servers setting
`server.Config.AutomaticRegistration` (its new `MaxAuthorityHints`
field).

**Why:** automatic registration resolves an unknown `client_id`'s Trust
Chain before the request can be authenticated, and the resolver fetched
every superior an Entity Configuration listed in `authority_hints`. One
Entity Configuration listing thousands of hints could turn a single
unauthenticated request into thousands of outbound fetches.

```go
federation.Limits{
	MaxPathLength:        5,
	MaxAuthorityHints:    5, // an entity listing more is rejected
	MaxStatementLifetime: 24 * time.Hour,
	MaxClockSkew:         30 * time.Second,
}
```

An Entity Configuration listing more hints than the limit now fails
resolution. Real ones list one, or a handful for an entity in several
federations. Concurrent automatic-registration requests for the same
`client_id` now also share one resolution. Rate-limit PAR per client
address in front of the server too: each distinct unknown `client_id`
still costs one resolution.

### `backchannelhttp.New` builds its own guarded client

**Affects:** CIBA ping deployments using `backchannelhttp`.

**Why:** a client's notification endpoint can come from an OpenID
Federation relying party's own metadata under automatic registration,
and `New` accepted any HTTP client. Passing a plain `http.Client` made
every notification a server-side request forgery that could reach
internal hosts and follow redirects.

```go
notifier, err := backchannelhttp.New(backchannelhttp.Config{
	Timeout: 5 * time.Second,
	Transport: fapihttp.TransportConfig{
		DialTimeout:         5 * time.Second,
		TLSHandshakeTimeout: 5 * time.Second,
	},
})
```

`New` no longer takes a client: it builds one with
`fapihttp.NewClient(cfg.Transport)`, which blocks loopback, private and
link-local addresses at connect time and never follows a redirect. Use
`Transport.AllowedPrivateHosts` for a notification endpoint that really
is on a private network.

### Identity claims need the user's approval (server)

**Affects:** servers with `Dependencies.IdentityClaims` configured, whose
clients request identity claims with the OIDC `claims` parameter.

**Why:** requested claim names went straight to the claims source, with
no scope check, no consent step and no client context, so any
registered client could obtain any identity attribute the source holds.

Show `InteractionRequest.RequestedClaims` (or
`BackchannelInteractionRequest.RequestedClaims`) on the consent screen,
and pass the names the user approves:

```go
server.GrantedAuthorization{
	Scope:                  approvedScope,
	ApprovedIdentityClaims: approvedClaims, // a subset of RequestedClaims.Names()
}
```

Only claims both requested and approved are resolved, for the ID token
or UserInfo wherever each was requested. Leaving the field nil releases
none, and approving a claim that wasn't requested fails
`CompleteAuthorization`/`CompleteBackchannelAuthentication`.

### Extensions can't return values under standard claim names (server)

**Affects:** servers whose `Config.Extensions` registers a definition
with `ReturnInTokenClaims` under a name the server or the resource owner
supplies: a claim the server sets itself (`sub`, `acr`, `cnf`,
`authorization_details`, ...) or an OIDC Core §5.1 identity claim
(`email`, `name`, `phone_number`, ...). `server.New` now rejects it.

**Why:** the value is the client's own, copied into the token. Under a
name like `email`, a relying party would read a client-supplied value
as the user's identity claim — for example when the user didn't approve
releasing their real email.

Rename the extension, or drop `ReturnInTokenClaims` if the value only
needs to reach the interaction step (`InteractionRequest.Extensions`).

### `Resolver.VerifyTrustMark` takes an accreditation policy (federation)

**Affects:** callers of `federation.Resolver.VerifyTrustMark`.

**Why:** a verified Trust Mark only proved its issuer was some member of
the federation. Any member, including the entity the mark is about,
could issue itself a mark of any type and have it verify.

```go
claims, err := resolver.VerifyTrustMark(ctx, subjectID, mark,
	federation.RequireFederationAccreditation) // or AcceptAnyFederationIssuer
```

`RequireFederationAccreditation` accepts a mark only when the Trust
Anchor's `trust_mark_issuers` lists its type and names its issuer (or
leaves that type's list empty, meaning anyone may issue it).
`AcceptAnyFederationIssuer` keeps the previous behaviour for marks
accredited out of band; check `claims.Issuer` yourself then. A Trust
Anchor built with `SelfIssuer` publishes the claim through
`SelfIssueConfig.TrustMarkIssuers`. Trust Marks without a `kid` header
are now rejected.

## v0.38.0

### `Dependencies.Random` must be `crypto/rand.Reader` (production only)

**Affects:** `server.New` and `client.New` under `AssuranceProduction`
with any other `Random`, including a wrapper around `crypto/rand.Reader`.

**Why:** codes, tokens, `state`, `nonce`, PKCE verifiers and every `jti`
are only as unguessable as this reader, and an `io.Reader` can't declare
that it is a CSPRNG.

```go
deps.Random = rand.Reader // crypto/rand
```

`resource.Dependencies.Random` is unchanged.

### JOSE and metadata member names are case-sensitive

**Affects:** nobody talking to a conforming peer. A JWS or JWE header,
JWK, JWK Set, DPoP proof, client assertion, client attestation, access
token `cnf` claim or AS metadata document whose member names only
case-fold to a known name (`"ALG"` for `"alg"`) is now rejected instead
of being read as that member. No code change is needed.

### Scope errors are `invalid_scope` (server)

**Affects:** anything matching on the error code. A pushed
authorization request or CIBA backchannel authentication request naming
a scope the client isn't allowed (or `openid` under `Config.OAuthOnly`)
now gets `invalid_scope` instead of `invalid_request`, as RFC 6749 and
CIBA Core §13 define. A missing or non-string scope is still
`invalid_request`.

### Server error text is character-checked (client)

**Affects:** callers reading server-supplied error text. `error`,
`error_description` and `error_uri` values outside RFC 6749 §5.2's
character set are now dropped from `Error.PublicDescription`,
`CallbackDenied.Description` and `BackchannelAuthenticationDenied.Description`,
and an authorization error redirect whose `error` code is malformed is
rejected as `invalid_response` rather than returned as `CallbackDenied`.
Well-formed responses are unaffected. `Error.ServerResponse()` is new in
this release and exposes the code, description, URI and HTTP status.

## v0.37.0

### `AuthorizationCallback.Session` is required (client)

**Affects:** every client using the browser flow
(`HandleAuthorizationResponse` or `CompleteAuthorization`).

**Why:** a callback's `state` only identifies a session, and anyone can
deliver a callback URL to someone else's browser. Binding the callback to
the browser that started the flow stops login CSRF (RFC 9700 §4.7).

Store the handle with the user agent when you redirect, and pass it back
at the callback:

```go
// Starting the flow.
session, err := rp.BeginAuthorization(ctx, req)
if err != nil { /* ... */ }
http.SetCookie(w, &http.Cookie{
	Name:     "fapi_session",
	Value:    session.Handle().String(),
	HttpOnly: true,
	Secure:   true,
	SameSite: http.SameSiteLaxMode, // Lax, so the cookie survives the AS's top-level redirect back
})
http.Redirect(w, r, session.URL().String(), http.StatusFound)

// At the redirect URI.
cookie, err := r.Cookie("fapi_session")
if err != nil { /* reject: no session for this browser */ }
handle, err := client.ParseSessionHandle(cookie.Value)
if err != nil { /* reject */ }
result, err := rp.CompleteAuthorization(ctx, client.AuthorizationCallback{
	RawQuery: r.URL.RawQuery,
	Session:  handle,
})
```

A callback whose `Session` doesn't match its `state` is rejected before
the session is consumed. Tests using `fapitest.RunAuthorizationCodeFlowWithCallback`
now pass the session handle as its second argument.

### Signing and decryption keys must declare custody (production only)

**Affects:** `server.Dependencies.Keys`, `JWTAccessTokens.Keys`,
`client.Dependencies.Keys` and `client.Dependencies.Decryption` under
`AssuranceProduction`.

Declare how the keys are held when you build the key manager or
decrypter:

```go
km, err := keys.NewKeyManagerFromSigners(signers, algorithms, kids,
	keys.DeclareCustody(keys.KeyCustody{
		Durable:                 true, // keys survive a restart (KMS, HSM, or your own durable storage)
		CrossInstanceConsistent: true, // every instance uses the same keys (needed with HorizontallyScaled)
	}))
```

`keys.NewDecrypter` and `keys.NewSingleKeyDecrypter` take the same
option. A custom `KeyManager` or `Decrypter` implements
`keys.KeyCustodyAssurance` instead. `keys/ephemeral` never declares
custody and is rejected in production.

## v0.36.0

### `X5CAttesterChain.IssuerBinding` is required (server)

**Affects:** servers using `X5CAttesterChain` for attestation-based
client authentication.

**Why:** a client attestation's `iss` is chosen by the attester. Without a
binding, any attester certified under a shared trust anchor could
authenticate as another attester's clients.

```go
deps.AttesterTrust = server.X5CAttesterChain{
	TrustAnchors:  server.StaticAttesterTrustAnchors{Roots: pool},
	IssuerBinding: server.AttesterIssuerInCertificate,
}
```

- `AttesterIssuerInCertificate`: the signing certificate carries a URI
  SAN exactly equal to the client's `ExpectedAttesterIssuer`. Use this
  whenever anchors are shared between attesters.
- `AttesterIssuerByTrustAnchors`: your `AttesterTrustAnchors` returns
  anchors belonging to each client's attester alone, so the chain itself
  identifies the attester.

## v0.34.0

### `Dependencies.AttesterTrust` is required with attestation auth (server)

**Affects:** servers with `Config.AttestationBasedClientAuthentication`
set.

- To keep the previous behavior (attester key looked up by `kid` in
  `ClientKeys`), pass `server.RegisteredAttesterKeys{}`.
- To verify the attestation's `x5c` certificate chain (HAIP 1.0 §4.4.1),
  pass `server.X5CAttesterChain` with trust anchors and, from v0.36.0,
  an `IssuerBinding` (see above).

## v0.33.0

### `Limits.MaxIDTokenClaimsBytes` is required (server)

**Affects:** servers building `Limits` by hand, unless `Config.OAuthOnly`
is set. `server.RecommendedLimits()` already sets it to 4096.

### Stores persist an opaque `Request` or `Grant` value (storage)

**Affects:** custom `TransactionStore`, `GrantStore` and
`BackchannelAuthenticationStore` implementations. `memstore` is already
updated.

- Replace the removed per-field columns with the single `Request` or
  `Grant` value, and persist and return it unmodified. The server owns
  its format, so future fields never touch your schema.
- Run `storage.TestTransactionStoreContract`, `TestGrantStoreContract`
  and `TestBackchannelAuthenticationStoreContract` against your store.
- Records written by an earlier version can't be read after upgrading.
  Pushed requests, authorization codes and CIBA requests are
  short-lived. Refresh tokens are not, so clients will need to
  re-authorize once.

## v0.31.0

### `AuthorizationResponseIssPolicy` is required (client)

**Affects:** every client. `Config.RequireAuthorizationResponseIss`
(bool) is replaced by `Config.AuthorizationResponseIssPolicy`, with no
default:

- `client.RequireAuthorizationResponseIss` matches the former `true`.
- `client.TolerateAbsentAuthorizationResponseIss` matches the former
  `false` or unset.

### Key sources must declare `KeySourceAssurance` (production only)

This one wasn't flagged as breaking in the v0.31.0 changelog.

**Affects:** `server.Dependencies.ClientKeys`, `ClientEncryptionKeys`
and `client.Dependencies.IssuerKeys` under `AssuranceProduction`. A
custom key source implements `keys.KeySourceAssurance` and declares
`LiveFetchHardened`: every live fetch goes through `fapihttp`, or there
is no live fetch at all. `keys.JWKSIssuerKeySource` and
`keys.NewLocalIssuerKeys` already declare it.

## v0.30.0

### `ClientCertificateTrust` replaces `MTLSClientCAs` (server)

**Affects:** every server. `Dependencies.MTLSClientCAs` is renamed to
`Dependencies.ClientCertificateTrust` and is now required:

- `server.TrustedClientCAs{Roots: pool}` if you previously set
  `MTLSClientCAs` (this package verifies the chain).
- `server.NoClientCertificateChainTrust{}` if you left it unset and
  verify client certificate chains yourself (for example, at a
  TLS-terminating proxy).
